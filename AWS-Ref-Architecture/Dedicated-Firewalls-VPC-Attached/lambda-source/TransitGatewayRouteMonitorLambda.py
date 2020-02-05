# Copyright (c) 2018, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Justin Harris <jharris@paloaltonetworks.com>

"""
Palo Alto Networks TransitGatewayRouteMonitorLambda.py

Script triggered by a Cloudwatch event that will monitor the health of firewalls
via the "show chassis status" op command on the Trust interface.
The purpose is to assess the health of the firewall and modify an AWS route table to redirect
traffic if the firewall is down.  When I firewall goes down routes within the route table bound to the
TGW attachment will show next hop as blackhole.  The routes need to be updated to a functional eni.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
"""

import logging
import os
import ssl
import urllib
import xml.etree.ElementTree as et

import boto3
from botocore.exceptions import ClientError

event = {}
context = {}
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

ec2 = boto3.resource('ec2')

ec2_client = boto3.client('ec2')
client = boto3.client('ec2')
events_client = boto3.client('events')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def check_route_table(route_table_id, target_route, target_eni):
    """
    Checks the route table if the route points to the target eni then return true else false
    :param route_table_id:  The route table that we will modify.
    :param vpc_summary_route:  A summary route used to forward all east west traffic to the alternative firewall if
    required
    :param def_route: The default route in this case 0.0.0.0/0
    :param route_table_id: route table the we need to check
    :return: True/False

    """
    route_table = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
    routes = route_table['RouteTables'][0]['Routes']
    current_eni = ''

    logger.info('looking for route {} in route table {}'.format(target_route, route_table_id))
    for route in routes:
        key = 'NetworkInterfaceId'
        if key in route:
            if route['DestinationCidrBlock'] == target_route:
                logger.info('Route table entry is {} and route to find is {}'.format(route['DestinationCidrBlock'],
                                                                                     target_route))
                current_eni = route['NetworkInterfaceId']
                break

    if target_eni == current_eni:
        logger.info('Route {} already using eni {}'.format(route['DestinationCidrBlock'], target_eni))
        return True
    else:
        logger.info('Route {} NOT using eni {}'.format(route['DestinationCidrBlock'], target_eni))
        return False


def check_for_split_routes(route_table_id, vpc_summary_route, def_route):
    """
    Checks the route table if split_routes == yes and if both the vpc_summary and Default point to the same eni
    Return False else Return True.  When split routes is yes we want to use both firewalls.  Firewall 1 for internet
    traffic and firewall 2 for east/west traffic.

    :param route_table_id:  The route table that we will modify.
    :param vpc_summary_route:  A summary route used to forward all east west traffic to the alternative firewall if
    required
    :param def_route: The default route in this case 0.0.0.0/0
    :param route_table_id: route table the we need to check
    :return: True/False

    """
    vpc_summary_route_eni = ''
    def_route_eni = ''
    route_table = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
    Interfaceids = []
    routes = route_table['RouteTables'][0]['Routes']
    for route in routes:
        key = 'NetworkInterfaceId'
        if key in route:
            eni1 = route['NetworkInterfaceId']
            if route['DestinationCidrBlock'] == vpc_summary_route:
                vpc_summary_route_eni = eni1
            elif route['DestinationCidrBlock'] == def_route:
                def_route_eni = eni1
    if vpc_summary_route_eni == def_route_eni:
        logger.info("Both routes use eni {0}".format(def_route_eni))
        return False
    else:
        return True


def replace_vpc_route_to_fw(route_table_id, destination_cidr_block, NetworkInterfaceId, DryRun=False):
    """
    Scan the route table for blackhole routes where the next hop is the eni of the failed firewall.
    In order to replace the routes we first delete the route and then add a new route pointing to the
    backup eni.

    :param route_table_id: The route table that requires modification
    :param destination_cidr_block: The cidr block that we need to change.  Normally the default route and VPC summary route
    :param NetworkInterfaceId: The eni of the Firewall that we need to failover to
    :param DryRun: Perform a DryRun - Doesn't update the route table
    :return: Respone to route_create or 'None'

    """

    try:
        ec2_client.delete_route(
            DestinationCidrBlock=destination_cidr_block,
            RouteTableId=route_table_id
        )
        logger.info("Success deleting {0} route".format(destination_cidr_block))
    except ClientError as e:
        logger.info("Got error {0} deleting route Moving on.".format(e))
        return None

    try:
        resp = ec2_client.create_route(
            DryRun=False,
            DestinationCidrBlock=destination_cidr_block,
            RouteTableId=route_table_id,
            NetworkInterfaceId=NetworkInterfaceId
        )
        logger.info("Success adding {} route next hop {}".format(destination_cidr_block, NetworkInterfaceId))
    except ClientError as e:
        logger.info("Got error {0} adding route Moving on.".format(e))
        return
    return True


def failover(route_table_id, route_target, failed_eni, backup_eni):
    """
    Looks for routes that are blackholed by the failure of the firewall
    When it finds a route it will call replace_vpc_route_to_fw to update the next hop to a functional eni

    :param route_table_id: The route table that requires modification
    :param failed_eni: NetworkInterfaceId: The eni of the Firewall that has failed
    :param backup_eni: NetworkInterfaceId: The eni of the Firewall that we need to failover to
    :return:
    """

    route_table = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
    Interfaceids = []
    routes = route_table['RouteTables'][0]['Routes']
    for route in routes:
        if route['DestinationCidrBlock'] == route_target:
            key = 'NetworkInterfaceId'
            if key in route:
                eni1 = route['NetworkInterfaceId']
                if route['NetworkInterfaceId'] == failed_eni:
                    logger.info(
                        "Found blackhole route {} with  next hop {}".format(route['DestinationCidrBlock'], failed_eni))
                    destination_cidr_block = route['DestinationCidrBlock']
                    if replace_vpc_route_to_fw(route_table_id, destination_cidr_block, backup_eni, DryRun=False):
                        return True
                    else:
                        return False
                else:
                    logger.info('*******Route {} already modified - Nothing to do********'.format(
                        route['DestinationCidrBlock']))


def get_firewall_status(gwMgmtIp, api_key):
    """
     Reruns the status of the firewall.  Calls the op command show chassis status
     Requires an apikey and the IP address of the interface we send the api request
     :param gwMgmtIp:
     :param api_key:
     :return:
     """

    global gcontext
    # cmd = urllib.request.Request('https://google.com')
    cmd = urllib.request.Request(
        "https://" + gwMgmtIp + "/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=" + api_key)
    # Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command: {}'.format(cmd))
    try:
        response = urllib.request.urlopen(cmd, data=None, context=gcontext, timeout=5).read()
        logger.info(
            "[INFO]:Got http 200 response from FW with address {}. So need to check the response".format(gwMgmtIp))
        # Now we do stuff to the gw
    except urllib.error.URLError:
        logger.info("[INFO]: No response from FW with address {}. So maybe not up!".format(gwMgmtIp))
        return 'down'
        # sleep and check again?
    else:
        logger.info("[INFO]: FW is responding!!")

    logger.info("[RESPONSE]: {}".format(response))
    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        return 'down'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got response header error for the command")
        return 'down'

    if resp_header.attrib['status'] == 'success':
        # The fw responded with a successful command execution
        for element in resp_header:
            if element.text.rstrip() == 'yes':
                # Call config gw command?
                logger.info("[INFO]: FW with ip {} is ready ".format(gwMgmtIp))
                return 'running'
    else:
        return 'down'


def check_fw(prifwstatus, secfwstatus, route_table_id, target_routes, primary_nic, secondary_nic, preempt):
    '''

    :param prifwstatus: String 'running'
    :param secfwstatus: String 'running'
    :param route_table_id: String VPC route table id
    :param target_routes:  List list of routes to process
    :param primary_nic: String ENI id of firewall trust nic
    :param secondary_nic: String ENI id of firewall trust nic
    :param preempt: String 'yes' or 'no' Fail back to primary when it recovers
    :return: True
    '''
    if ((prifwstatus == 'running') and (secfwstatus == 'running')):
        for route in target_routes:
            if check_route_table(route_table_id, route, primary_nic):
                '''
                Iterate of the target_routes list and check if the routes are set to the primary firewall
                '''
                logger.info("Both firewalls running and using primary firewall")
            else:
                '''
                The default route does not currently use the primary firewall
                Check if we can fail back to primary
                '''
                if preempt == 'no':
                    logger.info('********* Both firewalls running and preempt set to no - exiting *********')
                    exit()

                else:
                    '''
                    Able to fail back to primary firewall
                    '''
                    logger.info("Both firewalls running and we can failback")
                    for route_ in target_routes:
                        logger.info('Processing route {}'.format(route_))
                        replace_vpc_route_to_fw(route_table_id, route_, primary_nic, DryRun=False)

    elif ((prifwstatus != 'running') and (secfwstatus == 'running')):
        logger.info("********* Failing over all routes to secondary firewall *********")
        try:
            for route in target_routes:
                failover(route_table_id, route, primary_nic, secondary_nic)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))

    elif ((prifwstatus == 'running') and (secfwstatus != 'running')):
        logger.info("********* Failing over all routes to firewall primary firewall *********")
        try:
            for route in target_routes:
                failover(route_table_id, route, secondary_nic, primary_nic)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))
            return False

    elif ((prifwstatus != 'running') and (secfwstatus != 'running')):
        logger.info("********* Both Firewalls are Down - Nothing to do *********")


def lambda_handler(event, context):
    '''
    Controls the failover of routing of traffic between VPC's and to the internet.   In the event of a failure the
    backup firewall will provide routing and security


    preempt = os.environ['preempt'] Set this value to TRUE if you wish the firewalls to return to an Active/Active state
    as soon as the failed firewall becomees healthy again or set it to true in the environment variables during a change
    window.
    vpc_summary_route = os.environ['VpcSummaryRoute'] Set thus value as a route that summarises wth VPC spokes. The
    security VPC should not be contained in this summary route.
    fw1_trust_eni = os.environ['fw1Trusteni']  Fw 1 trust eni id
    fw2_trust_eni = os.environ['fw2Trusteni']  Fw 1 trust eni id
    route_table_id = os.environ['fromTGWRouteTableId']  Route table id of the route table associated with the TGW attachment
    fw1_trust_ip = os.environ['fw1Trustip'] FW Trust Inteface IP used for health probies.
    fw2_trust_ip = os.environ['fw2Trustip'] FW Trust Inteface IP used for health probies.
    api_key = os.environ['apikey']
    split_routes = os.environ['splitroutes'] Select True if you intend to use both firewalls One for east/West and
    one for internet.
    :param event:
    :param context:
    :return:

    Assumptions

    fw1 = Primary Firewall for Internet traffic
    fw2 = Secondary Firewall for Internet traffic
    fw3 = Primary Firewall for E/W Traffic
    fw4 = Secondary Firewall for E/W Traffic
    '''

    NSpreempt = os.environ['NSpreempt']
    EWpreempt = os.environ['NSpreempt']
    vpc_summary_routes = os.environ['VpcSummaryRoute'].split(',')
    fw1_trust_eni = os.environ['fw1Trusteni']
    fw2_trust_eni = os.environ['fw2Trusteni']
    fw3_trust_eni = os.environ['fw3Trusteni']
    fw4_trust_eni = os.environ['fw4Trusteni']
    route_table_id = os.environ['fromTGWRouteTableId']
    fw1_trust_ip = os.environ['fw1Trustip']
    fw2_trust_ip = os.environ['fw2Trustip']
    fw3_trust_ip = os.environ['fw3Trustip']
    fw4_trust_ip = os.environ['fw4Trustip']
    api_key = os.environ['apikey']

    internet_routes = ['0.0.0.0/0']

    global gcontext

    NSprifwstatus = get_firewall_status(gwMgmtIp=fw1_trust_ip, api_key=api_key)
    NSsecfwstatus = get_firewall_status(gwMgmtIp=fw2_trust_ip, api_key=api_key)
    EWprifwstatus = get_firewall_status(gwMgmtIp=fw3_trust_ip, api_key=api_key)
    EWsecfwstatus = get_firewall_status(gwMgmtIp=fw4_trust_ip, api_key=api_key)
    [logger.info('VPC route {}'.format(route)) for route in vpc_summary_routes]

    internet_primary_nic = fw1_trust_eni
    internet_secondary_nic = fw2_trust_eni

    vpc_summary_primary_nic = fw3_trust_eni
    vpc_summary_secondary_nic = fw4_trust_eni

    logger.info('*******')
    logger.info('*******Checking internet firewall routes************')
    logger.info('*******')
    check_fw(NSprifwstatus, NSsecfwstatus, route_table_id, internet_routes, internet_primary_nic,
             internet_secondary_nic, NSpreempt)

    logger.info('*******')
    logger.info('*******Checking East/West firewall routes************')
    logger.info('*******')
    check_fw(EWprifwstatus, EWsecfwstatus, route_table_id, vpc_summary_routes, vpc_summary_primary_nic,
             vpc_summary_secondary_nic, EWpreempt)


if __name__ == '__main__':
    event = {}
    context = {}
    lambda_handler(event, context)
