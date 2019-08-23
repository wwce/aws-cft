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

Region = os.environ['Region']
fw1_mgmt_ip = os.environ['fw1MgmtIp']
fw2_mgmt_ip = os.environ['fw2MgmtIp']
fw1_untrust_ip = os.environ['fw1UntrustIp']
fw2_untrust_ip = os.environ['fw2UntrustIp']
fw1_untrust_sec_ip = os.environ['fw2UntrustSecIp']
fw2_untrust_sec_ip = os.environ['fw2UntrustSecIp']
fw1_trust_ip = os.environ['fw1TrustIp']
fw2_trust_ip = os.environ['fw2TrustIp']
trustAZ1_subnet = os.environ['trustAZ1Subnet']
trustAZ2_subnet = os.environ['trustAZ2Subnet']
untrustAZ1_subnet = os.environ['untrustAZ1Subnet']
untrustAZ2_subnet = os.environ['untrustAZ2Subnet']
api_key = os.environ['apikey']
lambda_bucket_name = os.environ['lambda_bucket_name']


sys.path.append('asglib/')
import tgwaslib as lib

from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

subnets = []


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


def updateRouteNexthop(route, hostname, api_key, subnetGateway, virtualRouter="default"):
    """
    Updates the firewall route table with the next hop of the default gateway in the AWS subnet

    :param hostname: IP address of the firewall
    :param api_key:
    :param subnetGateway: AWS subnet gateway (First IP in the subnet range)
    :param virtualRouter: VR where we wish to apply this route
    :return: Result of API request
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/" \
            "virtual-router/entry[@name='default']/routing-table/ip/static-route/entry[@name='vnet-local']"
    element = "<destination>{0}</destination><interface>ethernet1/2" \
              "</interface><nexthop><ip-address>{1}</ip-address></nexthop>".format(route, subnetGateway)

    return panSetConfig(hostname, api_key, xpath, element)


def panEditConfig(hostname, api_key, xpath, element):
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
    response = makeApiCall(hostname, data)

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
        return 'no'
        # sleep and check again?
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


def create_panw_vpn(gwMgmtPubIp, api_key, bucketName, vpnId, src_ip):

    vpnConfDict = lib.loadVpnConfigFromS3(bucketName, vpnId)
    # Returns Dict
    # vpnconfdict
    # <
    #
    # class 'dict'>:
    #     {'id': 'vpn-0f25ec6eac09640de',
    #      'pa_dmz_ip': '99.81.149.22',
    #      'pa_asn': '65000',
    #      'vgw_asn': '64512',
    #      't1_ike_peer': '52.211.25.77',
    #      't1_int_ip': '169.254.0.150',
    #      't1_int_peer_ip': '169.254.0.149',
    #      't1_ike_psk': 'nMXJ.ALJnsKvNTy_9YYUQHQ45N1qu03C',
    #      't2_ike_peer': '63.33.243.114',
    #      't2_int_ip': '169.254.0.146',
    #      't2_int_peer_ip': '169.254.0.145',
    #      't2_ike_psk': 'EiJbta47HJbh.JNE8bbZ88xta2I5i4.f'}

    resource_id = vpnConfDict['id']
    logger.info('resource_id is {} from vpnConfDict {}'.format(resource_id, vpnConfDict))

    peerGroup = 'tgw-out'
    confVpnStatus = lib.pa_configure_vpn(gwMgmtPubIp, api_key, vpnConfDict, peerGroup, src_ip,
                                         ikeProfile="default", ipsecProfile="default",
                                         pa_dmz_inf="ethernet1/1", virtualRouter="default", zone="Untrust")
    if not confVpnStatus:
        lib.pan_rollback(gwMgmtPubIp, api_key)
        return False
    else:
        lib.pan_commit(gwMgmtPubIp, api_key, message="VpnConfigured")
        return True



def lambda_handler(event, context):
    fw1_vpnId = event.get('fw1_vpnId')
    fw2_vpnId = event.get('fw2_vpnId')
    fw1_sec_vpnId = event.get('fw1_sec_vpnId')
    fw2_sec_vpnId = event.get('fw2_sec_vpnId')
    logger.info("Got Event {}".format(event))



    trustAZ1_subnet_cidr = find_subnet_by_id(trustAZ1_subnet)['CidrBlock']
    logger.info('Trust AZ1 subnet is {}'.format(trustAZ1_subnet_cidr))
    trustAZ2_subnet_cidr = find_subnet_by_id(trustAZ2_subnet)['CidrBlock']
    logger.info('Trust AZ2 subnet is {}'.format(trustAZ2_subnet_cidr))
    untrustAZ1_subnet_cidr = lib.find_subnet_by_id(untrustAZ1_subnet)['CidrBlock']
    logger.info('Untrust AZ1 subnet is {}'.format(untrustAZ1_subnet_cidr))
    untrustAZ2_subnet_cidr = lib.find_subnet_by_id(untrustAZ2_subnet)['CidrBlock']
    logger.info('Untrust AZ2 subnet is {}'.format(untrustAZ2_subnet_cidr))

    logger.info(
        'called create_panw_vpn {}\n{}\n{}'.format(fw1_trust_ip, lambda_bucket_name, fw1_vpnId, 'fw_untrust_int'))
    fw1_vpn_status = create_panw_vpn(fw1_mgmt_ip, api_key, lambda_bucket_name, fw1_vpnId, 'fw_untrust_int')
    logger.info(
        'called create_panw_vpn {}\n{}\n{}'.format(fw2_trust_ip, lambda_bucket_name, fw2_vpnId, 'fw_untrust_int'))
    fw2_vpn_status = create_panw_vpn(fw2_mgmt_ip, api_key, lambda_bucket_name, fw2_vpnId, 'fw_untrust_int')

    logger.info('called create_panw_vpn {}\n{}\n{}'.format(fw1_mgmt_ip, lambda_bucket_name, fw1_sec_vpnId,
                                                           'fw_untrust_sec_int'))
    fw1_sec_vpn_status = create_panw_vpn(fw1_mgmt_ip, api_key, lambda_bucket_name, fw1_sec_vpnId, 'fw_untrust_sec_int')
    logger.info('called create_panw_vpn {}\n{}\n{}'.format(fw2_mgmt_ip, lambda_bucket_name, fw2_sec_vpnId,
                                                           'fw_untrust_sec_int'))
    fw2_sec_vpn_status = create_panw_vpn(fw2_mgmt_ip, api_key, lambda_bucket_name, fw2_sec_vpnId, 'fw_untrust_sec_int')
    # time.sleep(300)

    if fw1_vpn_status and fw2_vpn_status:
        event.update({'Action':'config_fw_vpn_success'})
        logger.info('VPN creation succeeded returning {}'.format(event))
    else:
        event.update({'Action':'config_fw_vpn_failed'})
        logger.info('VPN creation failed returning {}'.format(event))
    return event


































