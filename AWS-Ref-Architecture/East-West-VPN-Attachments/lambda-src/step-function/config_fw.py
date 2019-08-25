"""
/*****************************************************************************
 * Copyright (c) 2019, Palo Alto Networks. All rights reserved.              *
 *                                                                           *
 * This Software is the property of Palo Alto Networks. The Software and all *
 * accompanying documentation are copyrighted.                               *
 *****************************************************************************/

Copyright 2019 Palo Alto Networks

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


jharris@paloaltonetworks.com

"""

import logging
import ssl
import urllib
import xml
import os
import netaddr
import xml.etree.ElementTree as et
import boto3
import sys
import time

sys.path.append('asglib/')
import tgwaslib as lib

from botocore.exceptions import ClientError

pa_asn = os.environ['N1Asn']
fw1_trust_ip = os.environ['fw1TrustIp']
fw2_trust_ip = os.environ['fw2TrustIp']
fw1_mgmt_ip = os.environ['fw1MgmtIp']
fw2_mgmt_ip = os.environ['fw2MgmtIp']
fw1_untrust_ip = os.environ['fw1UntrustIp']
fw2_untrust_ip = os.environ['fw2UntrustIp']
fw1_untrust_sec_ip = os.environ['fw1UntrustSecIp']
fw2_untrust_sec_ip = os.environ['fw2UntrustSecIp']
fw1_untrust_pub_ip = os.environ['fw1UntrustPubIp']
fw2_untrust_pub_ip = os.environ['fw2UntrustPubIp']
fw1_untrust_sec_pub_ip = os.environ['fw1UntrustSecPubIp']
fw2_untrust_sec_pub_ip = os.environ['fw2UntrustSecPubIp']
trustAZ1_subnet = os.environ['trustAZ1Subnet']
trustAZ2_subnet = os.environ['trustAZ2Subnet']
untrustAZ1_subnet = os.environ['untrustAZ1Subnet']
untrustAZ2_subnet = os.environ['untrustAZ2Subnet']
vpc_summary_route = os.environ['VpcSummaryRoute']
vpc_cidr_block = os.environ['VpcCidrBlock']
fw1instanceId = os.environ['fw1instanceId']
fw2instanceId = os.environ['fw2instanceId']
api_key = os.environ['apikey']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

subnets = []


class FWNotUpException(Exception):
    # Constructor or Initializer
    def __init__(self, value):
        self.value = value

        # __str__ is to print() the value

    def __str__(self):
        return (repr(self.value))


def find_subnet_by_id(subnet_id):
    """
    find a subnet by subnet ID. Sets a Filter based on the subnet_id and calls find_classic_subnet()
    :param subnet_id:

    """
    kwargs = {
        'SubnetIds': [subnet_id]
    }
    return find_classic_subnet(kwargs)


def find_subnet_by_block(cidr):
    """find a subnet by CIDR block. Sets a Filter based on the subnet CIDR and calls find_classic_subnet()"""
    kwargs = {
        'Filters': [
            {
                'Name': 'cidrBlock',
                'Values': [cidr]
            }
        ]
    }
    return find_classic_subnet(kwargs)


def find_classic_subnet(kwargs):
    """call describe_subnets passing kwargs.  Returns the first subnet in the list of subnets.
    """
    logger.info("Querying for subnet")
    logger.debug("calling ec2.describe_subnets with args: %s", kwargs)
    try:
        subnets = ec2_client.describe_subnets(**kwargs)['Subnets']
    except ClientError:
        logger.debug("No Classic subnet found matching query.")
        return None
    logger.debug("Result: %s", subnets)
    if len(subnets) < 1:
        raise SystemExit("Error: 0 subnets found matching: %s" % kwargs)
    if len(subnets) > 1:
        raise SystemExit("Error: %s subnets found matching: %s" % (
            len(subnets), kwargs
        ))
    return subnets[0]


def updateRouteNexthop(route, fwMgmtIp, entry_name, api_key, interface, subnetGateway, virtualRouter="default"):
    """
    Updates the firewall route table with the next hop of the default gateway in the AWS subnet

    :param hostname: IP address of the firewall
    :param api_key:
    :param subnetGateway: AWS subnet gateway (First IP in the subnet range)
    :param virtualRouter: VR where we wish to apply this route
    :return: Result of API request
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/" \
            "virtual-router/entry[@name='default']/routing-table/ip/static-route/entry[@name='{0}']".format(entry_name)
    element = "<destination>{0}</destination><interface>{1}" \
              "</interface><nexthop><ip-address>{2}</ip-address></nexthop>".format(route, interface, subnetGateway)

    return panSetConfig(fwMgmtIp, api_key, xpath, element)


def updateRouteNexthopDiscard(route, fwMgmtIp, entry_name, api_key, virtualRouter="default"):
    """
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/" \
            "virtual-router/entry[@name='{0}']/routing-table/ip/static-route/entry[@name='{1}']".format(virtualRouter,
                                                                                                        entry_name)
    element = "<destination>{0}</destination><nexthop><discard/></nexthop>".format(route)

    return panSetConfig(fwMgmtIp, api_key, xpath, element)


def panEditConfig(fwMgmtIp, api_key, xpath, element):
    """
    Builds a request object and then Calls makeApiCall with request object.
    :param hostname: IP address of the firewall
    :param api_key:
    :param xpath: xpath of the configuration we wish to modify
    :param element: element that we wish to modify
    :return:  Returns the firewall response
    """
    logger.info("Updating edit config with xpath \n{} and element \n{} ".format(xpath, element))

    data = {
        'type': 'config',
        'action': 'edit',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    response = makeApiCall(fwMgmtIp, data)

    return response


def makeApiCall(hostname, data):
    """
    Makes the API call to the firewall interface.  We turn off certificate checking before making the API call.
    Returns the API response from the firewall.
    :param hostname:
    :param data:
    :return: Expected response
    <response status="success">
        <result>
            <![CDATA[yes\n]]>
        </result>
    </response>
    """

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # No certificate check
    ctx.verify_mode = ssl.CERT_NONE
    url = "https://" + hostname + "/api"
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')
    return urllib.request.urlopen(url, data=encoded_data, context=ctx).read()


def panSetConfig(hostname, api_key, xpath, element):
    """Function to make API call to "set" a specific configuration
    """
    data = {
        'type': 'config',
        'action': 'set',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    logger.info("Updating set config with xpath \n{} and element \n{} ".format(xpath, element))
    response = makeApiCall(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response


def editFqdnObject(hostname, api_key, objectname, fqdn):
    """Function to edit/update an existing FQDN Address object on a PA Node
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{0}']/fqdn".format(
        objectname)

    element = "<fqdn>{0}</fqdn>".format(fqdn)

    return panEditConfig(hostname, api_key, xpath, element)


def editIpObject(hostname, api_key, objectname, address):
    """Function to edit/update an existing IP Address object on a PA Node
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{0}']/ip-netmask".format(
        objectname)
    element = "<ip-netmask>{0}</ip-netmask>".format(address)
    return panEditConfig(hostname, api_key, xpath, element)


def getApiKey(hostname, username, password):
    """Generate API keys using username/password
    API Call: http(s)://hostname/api/?type=keygen&user=username&password=password
    """
    data = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    response = makeApiCall(hostname, data)
    if response == 'error':
        logger.info("Got error making api call to get api key!")
        return response
    else:
        return xml.etree.ElementTree.XML(response)[0][0].text


def panCommit(hostname, api_key, message=""):
    """Function to commit configuration changes
    """
    data = {
        "type": "commit",
        "key": api_key,
        "cmd": "<commit>{0}</commit>".format(message)
    }
    return makeApiCall(hostname, data)


def get_gw_ip(cidr):
    ip = netaddr.IPNetwork(cidr)
    iplist = list(ip)
    return iplist[1]


def getFirewallStatus(gwMgmtIp, api_key):
    """
    Gets the firewall status by sending the API request show chassis status.
    :param gwMgmtIp:  IP Address of firewall interface to be probed
    :param api_key:  Panos API key
    """
    global gcontext
    fwurl = "https://" + gwMgmtIp + "/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=" + api_key
    cmd = urllib.request.Request(
        "https://" + gwMgmtIp + "/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=" + api_key)
    # Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command: %s', fwurl)
    try:
        response = urllib.request.urlopen(cmd, data=None, context=gcontext, timeout=5).read()
        # Now we do stuff to the gw
    except urllib.error.URLError:
        logger.info("[INFO]: No response from FW. So maybe not up!")
        time.sleep(30)
        return 'no'

    else:
        logger.info("[INFO]: FW is up!!")

    logger.info("[RESPONSE]: {}".format(response))
    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        return 'cmd_error'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got an error for the command")
        return 'cmd_error'

    if resp_header.attrib['status'] == 'success':
        # The fw responded with a successful command execution. So is it ready?
        for element in resp_header:
            if element.text.rstrip() == 'yes':
                # Call config gw command?
                logger.info("[INFO]: FW is ready for configure")
                return 'yes'
            else:
                return 'almost'
            # The fw is still not ready to accept commands
            # so invoke lambda again and do this all over? Or just retry command?


def initial_setup_panw_firewall(vpc_summary_route, vpc_cidr_block, fw_mgmt_ip, fw_trust_ip, fw_untrust_ip,
                                fw_untrust_pub_ip, fw_untrust_sec_ip, api_key, trustAZ_subnet_cidr,
                                untrustAZ_subnet_cidr, pa_asn):
    err = 'no'
    while (True):
        err = getFirewallStatus(fw_mgmt_ip, api_key)
        if err == 'cmd_error':
            logger.info("[ERROR]: Command error from fw ")
            time.sleep(30)
            # raise FWNotUpException('FW is not up!  Request Timeout')
        elif err == 'almost':
            ("Fw not up ")
            # raise FWNotUpException('FW is not up. Nic responds but DP not ready!')
            time.sleep(30)
        elif err == 'yes':
            logger.info("[INFO]: FW is up")
            break

    # Get the gateway IP for the trust subnet
    trustAZ_subnet_gw = get_gw_ip(trustAZ_subnet_cidr)
    untrustAZ_subnet_gw = get_gw_ip(untrustAZ_subnet_cidr)

    # Update the route table with a static route
    entry_name = 'vnet-local'
    interface = 'ethernet1/2'
    route = vpc_summary_route
    response2 = updateRouteNexthop(vpc_cidr_block, fw_mgmt_ip, entry_name, api_key, interface, trustAZ_subnet_gw,
                                   virtualRouter="default")
    logger.info('Response to update vpc_summary_route {}'.format(response2))

    # Update next hop of static route to match subnet gw
    entry_name = 'default'
    interface = 'ethernet1/1'
    route = '0.0.0.0/0'
    response3 = updateRouteNexthop(route, fw_mgmt_ip, entry_name, api_key, interface, untrustAZ_subnet_gw,
                                   virtualRouter="default")
    logger.info('Response to update default route {}'.format(response3))

    # Update the vnet-local route with assigned vpc Cidr Block
    entry_name = 'vnets-summary'
    updateRouteNexthopDiscard(vpc_summary_route, fw_mgmt_ip, entry_name, api_key, virtualRouter="default")

    # Update an Untrust interface address objects of the firewall.

    editIpObject(fw_mgmt_ip, api_key, 'fw_untrust_int', fw_untrust_ip + '/24')
    editIpObject(fw_mgmt_ip, api_key, 'fw_untrust_sec_int', fw_untrust_sec_ip + '/32')

    # Update an Trust interface address objects of the firewall.
    editIpObject(fw_mgmt_ip, api_key, 'fw_trust_int', fw_trust_ip)

    # Update BGP router ID with public IP of eth1 and BGP ASN
    response2 = lib.update_routerId_asn(fw_mgmt_ip, api_key, fw_untrust_pub_ip, pa_asn)
    logger.info('Response to updateRouterIdAndAsn {}'.format(response2))

    # Add ApiKey to deactivate License
    # response4 = lib.config_deactivate_license_apikey(fw_trust_ip, api_key, license_api_key)
    return True


def lambda_handler(event, context):
    logger.info("Got Event {}".format(event))

    fw1_vpnId = event.get('fw1_vpnId')
    fw2_vpnId = event.get('fw2_vpnId')
    fw1_cgwId = event.get('fw1_cgwId')
    fw2_cgwId = event.get('fw2_cgwId')
    fw1_sec_vpnId = event.get('fw1_sec_vpnId')
    fw2_sec_vpnId = event.get('fw2_sec_vpnId')
    fw1_sec_cgwId = event.get('fw1_sec_cgwId')
    fw2_sec_cgwId = event.get('fw2_sec_cgwId')

    trustAZ1_subnet_cidr = find_subnet_by_id(trustAZ1_subnet)['CidrBlock']
    logger.info('Trust AZ1 subnet is {}'.format(trustAZ1_subnet_cidr))
    trustAZ2_subnet_cidr = find_subnet_by_id(trustAZ2_subnet)['CidrBlock']
    logger.info('Trust AZ2 subnet is {}'.format(trustAZ2_subnet_cidr))
    untrustAZ1_subnet_cidr = lib.find_subnet_by_id(untrustAZ1_subnet)['CidrBlock']
    logger.info('Untrust AZ1 subnet is {}'.format(untrustAZ1_subnet_cidr))
    untrustAZ2_subnet_cidr = lib.find_subnet_by_id(untrustAZ2_subnet)['CidrBlock']
    logger.info('Untrust AZ2 subnet is {}'.format(untrustAZ2_subnet_cidr))

    cgw1Tag = fw1instanceId
    cgw2Tag = fw2instanceId
    tag1 = fw1instanceId
    tag2 = fw2instanceId

    res1 = initial_setup_panw_firewall(vpc_summary_route, vpc_cidr_block, fw1_mgmt_ip, fw1_trust_ip, fw1_untrust_ip,
                                       fw1_untrust_pub_ip, fw1_untrust_sec_ip, api_key,
                                       trustAZ1_subnet_cidr, untrustAZ1_subnet_cidr, pa_asn)

    panCommit(fw1_mgmt_ip, api_key, message="Updated route table and address object")

    res2 = initial_setup_panw_firewall(vpc_summary_route, vpc_cidr_block, fw2_mgmt_ip, fw2_trust_ip, fw2_untrust_ip,
                                       fw2_untrust_pub_ip, fw2_untrust_sec_ip, api_key,
                                       trustAZ2_subnet_cidr, untrustAZ2_subnet_cidr, pa_asn)

    panCommit(fw2_mgmt_ip, api_key, message="Updated route table and address object")

    if res1 and res2:
        data = {
            'Action': 'config_fw_success',
            'fw1_vpnId': fw1_vpnId,
            'fw1_cgwId': fw1_cgwId,
            'fw2_vpnId': fw2_vpnId,
            'fw2_cgwId': fw2_cgwId,
            'fw1_sec_vpnId': fw1_sec_vpnId,
            'fw1_sec_cgwId': fw1_sec_cgwId,
            'fw2_sec_vpnId': fw2_sec_vpnId,
            'fw2_sec_cgwId': fw2_sec_cgwId
        }
    else:
        data = {
            'Action': 'config_fw_failed',
            'fw1_vpnId': fw1_vpnId,
            'fw1_cgwId': fw1_cgwId,
            'fw2_vpnId': fw2_vpnId,
            'fw2_cgwId': fw2_cgwId,
            'fw1_sec_vpnId': fw1_sec_vpnId,
            'fw1_sec_cgwId': fw1_sec_cgwId,
            'fw2_sec_vpnId': fw2_sec_vpnId,
            'fw2_sec_cgwId': fw2_sec_cgwId
        }
    return data







