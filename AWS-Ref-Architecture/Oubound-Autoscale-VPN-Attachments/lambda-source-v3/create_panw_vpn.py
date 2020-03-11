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

from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

subnets = []


def deactivate_license(hostname, api_key):
    """Function to Deactivate / remove license associated with a PA node
    This function is used during decommision of a server and requires internet connectivity
    """
    cmd = "<request><license><deactivate><VM-Capacity><mode>auto</mode></VM-Capacity></deactivate></license></request>"
    return pan_op_cmd(hostname, api_key, cmd)


def pan_set_config(hostname, api_key, xpath, element):
    """Function to make API call to "set" a specific configuration
    """
    logger.info('Calling pan_set_config {} {} {} {}'.format(hostname, api_key, xpath, element))
    data = {
        'type': 'config',
        'action': 'set',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    response = make_api_call(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response


def pan_get_config(hostname, api_key, xpath):
    """Function to make API call to "get" (or read or list) a specific configuration
    """
    data = {
        'type': 'config',
        'action': 'get',
        'key': api_key,
        'xpath': xpath
    }
    response = make_api_call(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response


def pan_edit_config(hostname, api_key, xpath, element):
    """Function to make API call to "edit" (or modify) a specific configuration
    Note: Some properties need "set" method instead of "edit" to work
    """
    data = {
        'type': 'config',
        'action': 'edit',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    response = make_api_call(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response


def get_tunnel_units(hostname, api_key):
    """Function to fet all tunnel interfaces and return it as a list. This is used to find unused tunnel interface id while creating a new one.
    """
    # Get all tunnel interface ids
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units"
    response = pan_get_config(hostname, api_key, xpath)
    data = XmlDictConfig(xml.etree.ElementTree.XML(response)[0])
    tunnelNames = []
    loop = True
    while loop:
        try:
            tunnelNames.append(data['units']['entry'].pop()['name'])
        except:
            # nothing to left to pop
            loop = False
    return tunnelNames


def get_free_tunnel_inf_ids(tunnelNames, no_of_ids=2):
    """Function to return two unused tunnel ids within range 1-9999 and not already used by names in the list 'tunnelNames'
    """
    # Function to return valid tunnel ids that can be used to create new tunnel interfaces
    range_start = 1
    range_end = 9999
    if len(tunnelNames) == 0:
        return [x for x in range(1, no_of_ids + 1)]
    else:
        currentTunnelIds = [int(name.split('.')[1]) for name in tunnelNames]
        newIds = []
        while len(newIds) < no_of_ids:
            for id in range(range_start, range_end + 1):
                if id not in currentTunnelIds:
                    currentTunnelIds.append(id)
                    newIds.append(id)
                    break
        return newIds


def create_ike_gateway(hostname, api_key, name, psk, ikeProfile, pa_dmz_inf, peerIp, src_ip):
    """Function to create IKE Gateway
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='{0}']".format(name)
    element = "<authentication><pre-shared-key><key>{0}</key></pre-shared-key></authentication>\
              <protocol><ikev1><dpd><enable>yes</enable><interval>10</interval><retry>3</retry></dpd>\
              <ike-crypto-profile>{1}</ike-crypto-profile><exchange-mode>main</exchange-mode></ikev1>\
              <ikev2><dpd><enable>yes</enable></dpd></ikev2></protocol><protocol-common><nat-traversal>\
              <enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation>\
              </protocol-common><local-address><interface>{2}</interface></local-address><peer-address>\
              <ip>{3}</ip></peer-address>".format(psk, ikeProfile, pa_dmz_inf, peerIp)
    # response from SecConfig is return so that incase needed, it can be used to do some processesing
    # In case of failure, Exception should be thrown by makeApiCall itself

    pan_set_config(hostname, api_key, xpath, element)

    xpath2 = "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='{0}']/local-address".format(
        name)
    element2 = "<ip>{0}</ip>".format(src_ip)

    res = pan_set_config(hostname, api_key, xpath2, element2)
    logger.info('Response setting source ip on ike gw {}'.format(res))
    return


def create_ipsec_tunnel_Inf(hostname, api_key, tunnelInfId, tunnelInfIp="ip/30", mtu=1427):
    """Function to create tunnel interface to use with IPsec
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units/entry[@name='tunnel.{0}']".format(
        tunnelInfId)
    element = "<ip><entry name='{0}/30'/></ip><mtu>{1}</mtu>".format(tunnelInfIp, mtu)
    # print("Add: IpsecTunnelInf")
    # print(xpath)
    # print(element)

    return pan_set_config(hostname, api_key, xpath, element)


def create_ipsec_tunnel(hostname, api_key, tunnelName, ikeName, ipsecProfile, tunnelInfId):
    """Function to create IPSec tunnel
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='{0}']".format(
        tunnelName)
    element = "<auto-key><ike-gateway><entry name='{0}'/></ike-gateway><ipsec-crypto-profile>{1}</ipsec-crypto-profile></auto-key><tunnel-monitor><enable>no</enable>\
              </tunnel-monitor><tunnel-interface>tunnel.{2}</tunnel-interface>".format(ikeName, ipsecProfile,
                                                                                       tunnelInfId)
    print("Add: Ipsec Tunnel")
    print(xpath)
    print(element)
    return pan_set_config(hostname, api_key, xpath, element)


def add_inf_to_router(hostname, api_key, tunnelInfId, virtualRouter="default"):
    """Function to add an interface to a Virtual-Router
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='{0}']/interface".format(
        virtualRouter)
    element = "<member>tunnel.{0}</member>".format(tunnelInfId)
    return pan_set_config(hostname, api_key, xpath, element)


def add_inf_to_zone(hostname, api_key, zone, tunnelInfId):
    """Function to add an interface to a Zone
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name='{0}']/network/layer3".format(
        zone)
    element = "<member>tunnel.{0}</member>".format(tunnelInfId)
    # return panSetConfig(hostname, api_key, xpath, element)
    x = pan_set_config(hostname, api_key, xpath, element)
    print("Adding interface to Zone")
    print(x)


def add_to_peer_group(hostname, api_key, virtualRouter, peerGroup, peerName, tunnel_int_ip, tunnelInfId,
                      tunnel_int_peer_ip, peerAsn):
    """Add IPSec tunnel interface to a BGP Peer group
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='{0}']/protocol/bgp/peer-group/entry[@name='{1}']/peer/entry[@name='{2}']".format(
        virtualRouter, peerGroup, peerName)
    element = "<connection-options><incoming-bgp-connection><remote-port>0</remote-port><allow>yes</allow></incoming-bgp-connection><outgoing-bgp-connection><local-port>0</local-port><allow>yes</allow></outgoing-bgp-connection><multihop>0</multihop><keep-alive-interval>10</keep-alive-interval><open-delay-time>0</open-delay-time><hold-time>30</hold-time><idle-hold-time>15</idle-hold-time></connection-options><local-address><ip>{0}</ip><interface>tunnel.{1}</interface></local-address><peer-address><ip>{2}</ip></peer-address><bfd><profile>Inherit-vr-global-setting</profile></bfd><max-prefixes>5000</max-prefixes><peer-as>{3}</peer-as><enable>yes</enable><reflector-client>non-client</reflector-client><peering-type>unspecified</peering-type>".format(
        tunnel_int_ip, tunnelInfId, tunnel_int_peer_ip, peerAsn)
    return pan_set_config(hostname, api_key, xpath, element)


def make_api_call(hostname, data):
    """Function to make API call
    """
    # Todo:
    # Context to separate function?
    # check response for status codes and return reponse.read() if success
    #   Else throw exception and catch it in calling function
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = "https://" + hostname + "/api"
    logger.info('API call is {} {}'.format(url, data))
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')
    response = urllib.request.urlopen(url, data=encoded_data, context=ctx).read()
    return response


def pa_configure_vpn(hostname, api_key, vpnConfDict, peerGroup, src_ip, ikeProfile="default", ipsecProfile="default",
                     pa_dmz_inf="ethernet1/1", virtualRouter="default", zone="UNTRUST", ):
    """Function to configure IPSec vpn on a PA Node
    """
    # try:
    # Configure T1 IKE
    create_ike_gateway(hostname, api_key,
                       "-".join(["ike", vpnConfDict['id'], "0"]),
                       vpnConfDict['t1_ike_psk'], ikeProfile,
                       pa_dmz_inf, vpnConfDict['t1_ike_peer'], src_ip)
    # Configure T2 IKE
    create_ike_gateway(hostname, api_key,
                       "-".join(["ike", vpnConfDict['id'], "1"]),
                       vpnConfDict['t2_ike_psk'], ikeProfile,
                       pa_dmz_inf, vpnConfDict['t2_ike_peer'], src_ip)
    # Get ids to create tunnel Interface
    tunnelInfIds = get_free_tunnel_inf_ids(get_tunnel_units(hostname, api_key))
    # Configure T1 tunnelInf
    create_ipsec_tunnel_Inf(hostname, api_key, tunnelInfIds[0],
                            tunnelInfIp=vpnConfDict['t1_int_ip'],
                            mtu=1427)
    add_inf_to_router(hostname, api_key, tunnelInfIds[0], virtualRouter)
    add_inf_to_zone(hostname, api_key, zone, tunnelInfIds[0])
    # Configure T2 tunnelInf
    create_ipsec_tunnel_Inf(hostname, api_key, tunnelInfIds[1],
                            tunnelInfIp=vpnConfDict['t2_int_ip'],
                            mtu=1427)
    add_inf_to_router(hostname, api_key, tunnelInfIds[1], virtualRouter)
    add_inf_to_zone(hostname, api_key, zone, tunnelInfIds[1])
    # Configure T1 tunne1
    response1 = create_ipsec_tunnel(hostname, api_key,
                                    "-".join(["ipsec", vpnConfDict['id'], "0"]),
                                    "-".join(["ike", vpnConfDict['id'], "0"]),
                                    ipsecProfile, tunnelInfIds[0])
    # Configure T2 tuneel
    response2 = create_ipsec_tunnel(hostname, api_key,
                                    "-".join(["ipsec", vpnConfDict['id'], "1"]),
                                    "-".join(["ike", vpnConfDict['id'], "1"]),
                                    ipsecProfile, tunnelInfIds[1])
    # Add T1 to peer group
    response3 = add_to_peer_group(hostname, api_key, "default", peerGroup,
                                  "-".join(["peer", vpnConfDict['id'], "0"]),
                                  "".join([vpnConfDict['t1_int_ip'], "/30"]),
                                  tunnelInfIds[0], vpnConfDict['t1_int_peer_ip'],
                                  vpnConfDict['vgw_asn'])
    # Add T2 to peer group
    response4 = add_to_peer_group(hostname, api_key, "default", peerGroup,
                                  "-".join(["peer", vpnConfDict['id'], "1"]),
                                  "".join([vpnConfDict['t2_int_ip'], "/30"]),
                                  tunnelInfIds[1], vpnConfDict['t2_int_peer_ip'],
                                  vpnConfDict['vgw_asn'])
    # return response
    # except:
    #     print("PA VPN configuration failed", sys.exc_info()[0])
    #     return False

    logger.info('Got responses to api request Ipsec tunnel {} {} \nPeer Group {} {} '
                .format(response1, response2, response3, response4))
    return True


class XmlDictConfig(dict):
    """
    Example usage:

    >>> tree = ElementTree.parse('your_file.xml')
    >>> root = tree.getroot()
    >>> xmldict = XmlDictConfig(root)

    Or, if you want to use an XML string:

    >>> root = ElementTree.XML(xml_string)
    >>> xmldict = XmlDictConfig(root)

    And then use xmldict for what it is... a dict.
    """

    def __init__(self, parent_element):
        if parent_element.items():
            self.update(dict(parent_element.items()))
        for element in parent_element:
            if element:
                # treat like dict - we assume that if the first two tags
                # in a series are different, then they are all different.
                if len(element) == 1 or element[0].tag != element[1].tag:
                    aDict = XmlDictConfig(element)
                # treat like list - we assume that if the first two tags
                # in a series are the same, then the rest are the same.
                else:
                    # here, we put the list in dictionary; the key is the
                    # tag name the list elements all share in common, and
                    # the value is the list itself
                    aDict = {element[0].tag: XmlListConfig(element)}
                # if the tag has attributes, add those to the dict
                if element.items():
                    aDict.update(dict(element.items()))
                self.update({element.tag: aDict})
            # this assumes that if you've got an attribute in a tag,
            # you won't be having any text. This may or may not be a
            # good idea -- time will tell. It works for the way we are
            # currently doing XML configuration files...
            elif element.items():
                self.update({element.tag: dict(element.items())})
            # finally, if there are no child tags and no attributes, extract
            # the text
            else:
                self.update({element.tag: element.text})


def loadVpnConfigFromS3(bucketName, vpnId):
    """Function to read AWS-IPSec configuration (xml format) from an S3 bucket, parse it return important data as a dictionary
    Returns Dict
    <class 'dict'>:
    {'id': 'vpn-05574d274b6385444',
    'pa_dmz_ip': '99.80.124.137',
    'pa_asn': '65000',
    'vgw_asn': '64512',
    't1_ike_peer': '63.35.84.61',
    't1_int_ip': '169.254.0.118',
    't1_int_peer_ip': '169.254.0.117',
    't1_ike_psk': 'Da7SFsg6mNSH5uKCoA_ShWjRUBzjDqLh',
    't2_ike_peer': '63.35.142.140',
    't2_int_ip': '169.254.0.114',
    't2_int_peer_ip': '169.254.0.113',
    't2_ike_psk': 'EpdPi5Qrqdt8ENE.8oB3q4AdaFshjOMT'}

    """
    filename = ".".join([vpnId, "xml"])
    s3 = boto3.resource('s3')
    try:
        vpnConf = s3.Object(bucketName, filename).get()['Body'].read().decode('utf-8')
    except:
        print("Error While downloading vpn config xml from s3")
        return False
    ConfigTree = xml.etree.ElementTree.XML(vpnConf)
    Tun1Dict = XmlDictConfig(ConfigTree[-2])
    Tun2Dict = XmlDictConfig(ConfigTree[-1])
    vpnConfDict = {}
    vpnConfDict['id'] = vpnId
    vpnConfDict['pa_dmz_ip'] = Tun1Dict['customer_gateway']['tunnel_outside_address']['ip_address']
    vpnConfDict['pa_asn'] = Tun1Dict['customer_gateway']['bgp']['asn']
    vpnConfDict['vgw_asn'] = Tun1Dict['vpn_gateway']['bgp']['asn']
    vpnConfDict['t1_ike_peer'] = Tun1Dict['vpn_gateway']['tunnel_outside_address']['ip_address']
    vpnConfDict['t1_int_ip'] = Tun1Dict['customer_gateway']['tunnel_inside_address']['ip_address']
    vpnConfDict['t1_int_peer_ip'] = Tun1Dict['vpn_gateway']['tunnel_inside_address']['ip_address']
    vpnConfDict['t1_ike_psk'] = Tun1Dict['ike']['pre_shared_key']
    vpnConfDict['t2_ike_peer'] = Tun2Dict['vpn_gateway']['tunnel_outside_address']['ip_address']
    vpnConfDict['t2_int_ip'] = Tun2Dict['customer_gateway']['tunnel_inside_address']['ip_address']
    vpnConfDict['t2_int_peer_ip'] = Tun2Dict['vpn_gateway']['tunnel_inside_address']['ip_address']
    vpnConfDict['t2_ike_psk'] = Tun2Dict['ike']['pre_shared_key']
    return vpnConfDict


def pan_commit(hostname, api_key, message=""):
    """Function to commit configuration changes
    """
    data = {
        "type": "commit",
        "key": api_key,
        "cmd": "<commit>{0}</commit>".format(message)
    }
    return make_api_call(hostname, data)


def pan_rollback(hostname, api_key, username="admin"):
    """Function to rollback uncommited changes
    """
    # https://firewall/api/?key=apikey&type=op&cmd=<revert><config><partial><admin><member>admin-name</member></admin></partial></config></revert>
    # panOpCmd(hostname, api_key, cmd)
    cmd = "<revert><config><partial><admin><member>" + username + "</member></admin></partial></config></revert>"
    pan_op_cmd(hostname, api_key, cmd)


def pan_op_cmd(hostname, api_key, cmd):
    """Function to make an 'op' call to execute a command
    """
    data = {
        "type": "op",
        "key": api_key,
        "cmd": cmd
    }
    return make_api_call(hostname, data)


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
    vpnConfDict = loadVpnConfigFromS3(bucketName, vpnId)
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
    confVpnStatus = pa_configure_vpn(gwMgmtPubIp, api_key, vpnConfDict, peerGroup, src_ip,
                                     ikeProfile="default", ipsecProfile="default",
                                     pa_dmz_inf="ethernet1/1", virtualRouter="default", zone="Untrust")
    if not confVpnStatus:
        pan_rollback(gwMgmtPubIp, api_key)
        return False
    else:
        pan_commit(gwMgmtPubIp, api_key, message="VpnConfigured")
        return True


def lambda_handler(event, context):
    fw1_vpnId = event.get('fw1_vpnId')
    logger.info("Got Event {}".format(event))
    '''
    {
    "LifecycleHookName": "ireland-ouASG-life-cycle-launch",
    "AccountId": "106808901653",
    "RequestId": "b625bf57-b47e-18ed-3304-3d77f26d88ba",
    "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
    "AutoScalingGroupName": "ireland-ouASG",
    "Service": "AWS Auto Scaling",
    "Time": "2020-01-24T05:02:27.963Z",
    "EC2InstanceId": "i-0eb95335a18f7a6ac",
    "NotificationMetadata": "{\"MGMT\": \"subnet-011d5429b04fdfee1,subnet-03a6f2e9711510e51\", \"UNTRUST\": \"subnet-0bd4e9305a390a949,subnet-0805cc8f73eae576b\", \"TRUST\": \"subnet-081e022dea36f09c4,subnet-0b974e8aff9eecdbe\", \"SGM\": \"sg-0c0acf90d8d7e2681\", \"SGU\": \"sg-01cc400735fc3f214\", \"SGT\": \"sg-01b86eda4f224bc8f\", \"apikey\": \"LUFRPT1qS2xCRmZ6WVMrREtrK00yUGt4dVRna2lkY1U9cmgyaE93L3VoZ2U3WUgxeFpGVE1wOUNtdlM2S0Z5Z25ObG8wbmZoNXpuWT0=\"}",
    "LifecycleActionToken": "0ff52df8-82f7-4cfb-b22e-5cb39721d398",
    "Action": "config_fw_success",
    "fwMgmtIP": "172.16.10.152",
    "lambda_bucket_name": "ireland-outbound-vpn",
    "event-name": "gw-launch",
    "fwUntrustPubIP": "3.248.53.194",
    "fwUntrustPrivIP": "172.16.11.40",
    "instance-id": "i-0eb95335a18f7a6ac",
    "asg_name": "ireland-ouASG",
    "asg_hookname": "ireland-ouASG-life-cycle-launch",
    "fwUntrustSubnet": "subnet-0805cc8f73eae576b",
    "fwMgmtSubnet": "subnet-03a6f2e9711510e51",
    "fw1_vpnId": "vpn-0815b9d88c270afdf",
    "fw1_cgwId": "cgw-0372bf65f2cc175ea"
    }
    '''
    fw1_untrust_ip = event['fwUntrustPubIP']
    fw1_vpnId = event['fw1_vpnId']
    lambda_bucket_name = event['lambda_bucket_name']
    api_key = os.environ['apikey']
    logger.info(
        'called create_panw_vpn {}\n{}\n{}'.format(fw1_untrust_ip, lambda_bucket_name, fw1_vpnId, 'fw_untrust_int'))
    fw1_vpn_status = create_panw_vpn(fw1_untrust_ip, api_key, lambda_bucket_name, fw1_vpnId, 'fw_untrust_int')

    if fw1_vpn_status:
        event.update({'Action': 'config_fw_vpn_success'})
        logger.info('VPN creation succeeded returning {}'.format(event))
    else:
        event.update({'Action': 'config_fw_vpn_failed'})
        logger.info('VPN creation failed returning {}'.format(event))
    return event

