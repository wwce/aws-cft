"""
/*****************************************************************************
 * Copyright (c) 2019, Palo Alto Networks. All rights reserved.              *
 *                                                                           *
 * This Software is the property of Palo Alto Networks. The Software and all *
 * accompanying documentation are copyrighted.                               *
 *****************************************************************************/

Copyright 2016 Palo Alto Networks

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
import os
import ssl
import sys
import urllib
import xml
import xml.etree.ElementTree as ET

import boto3
from botocore.exceptions import ClientError
import requests
import time
import urllib3
from boto3.dynamodb.conditions import Attr

import netaddr

Region = os.environ['Region']

urllib3.disable_warnings()

logger = logging.getLogger()
logger.setLevel(logging.INFO)
dynamodb = boto3.resource('dynamodb', region_name=Region)
asg = boto3.client('autoscaling', region_name=Region)
ec2 = boto3.resource('ec2', region_name=Region)
ec2_client = boto3.client('ec2', region_name=Region)
lambda_client = boto3.client('lambda', region_name=Region)
iam_client = boto3.client('iam')
events_client = boto3.client('events', region_name=Region)

# Some global variables....yikes!
asg_name = ""
asg_hookname = ""
instanceId = ""
gwMgmtPubIp = ""
fwUntrustPubIP = ""
PortalMgmtIp = ""
api_key = ""
gcontext = ""
job_id = ""
this_func_name = ""
lambda_function_arn = ""
gwDpInterfaceId = ""

hostname = ""
fqdn = ""

##
## Firewall license product codes
##
valid_panfw_productcode_byol = {
    "6njl1pau431dv1qxipg63mvah": "VMLIC_BYOL",
    # AWS IC product codes
    "3bgub3avj7bew2l8odml3cxdx": "VMLIC_IC_BYOL",
}


def get_device_serial_no(instanceId, gwMgmtIp, fwApiKey):
    """
    Retrieve the serial number from the FW.

    :param gcontext: ssl context
    :param instanceId: instance Id
    :param gwMgmtIP: The IP address of the FW
    :param fwApiKey: Api key of the FW

    :return: The serial number of the FW
    :rtype: str
    """

    serial_no = None
    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return None

    logger.info('Retrieve the serial number from FW {} with IP: {}'.format(instanceId, gwMgmtIp))
    fw_cmd = '<show><system><info/></system></show>'
    try:
        response = pan_op_cmd(gwMgmtIp, fwApiKey, fw_cmd)
        # response = runCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response is None:
            print('CFG_FW_GET_SERIAL_NO: Failed to run command: ' + fw_cmd)
            return None
    except Exception as e:
        print("[CFG_FW_GET_SERIAL_NO]: {}".format(e))
        return None

    resp = ET.fromstring(response)
    serial_info = resp.findall(".//serial")
    for info in serial_info:
        serial_no = info.text

    if not serial_no:
        logger.error("Unable to retrieve the serial number from device: {} with IP: {}".format(instanceId, gwMgmtIp))

    return serial_no


def deactivate_fw_license(instanceId, gwMgmtIp, fwApiKey):
    """
    Call the FW to deactivate the license from the licensing
    server

    :param gcontext: ssl context
    :param instanceId: instance Id
    :param gwMgmtIP: The IP address of the FW
    :param fwApiKey: Api key of the FW

    :return: Api call status
    :rtype: bool
    """

    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return False

    logger.info('Deactivate and the license for FW: {} with IP: {}'.format(instanceId, gwMgmtIp))

    fw_cmd = "<request><license><deactivate><VM-Capacity><mode>auto</mode></VM-Capacity></deactivate></license></request>".format(
        gwMgmtIp, fwApiKey)
    try:
        response = pan_op_cmd(gwMgmtIp, fwApiKey, fw_cmd)
        # response = runCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response is None:
            print('CFG_FW_DELICENSE: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
        print("[CFG_FW_DELICENSE]: {}".format(e))
        return False

    return True


def handle_license(instanceId, fwMgmtIp, fwApiKey):
    serial_no = get_device_serial_no(instanceId, fwMgmtIp, fwApiKey)
    if not serial_no:
        logger.error('Unable to retrieve the serial no for device with IP: {}'.format(fwMgmtIp))
        return False

    logger.info('The serial number retrieved from device with IP: {} is {}'.format(fwMgmtIp, serial_no))

    try:
        instance_info = ec2_client.describe_instance_attribute(
            Attribute='productCodes',
            InstanceId=instanceId,
        )
    except Exception as e:
        logger.info("Exception occured while retrieving instance ID information: {}".format(e))

    logger.info('describe_instance_attribute:response: {}'.format(instance_info))
    valid_byol = False
    for code in instance_info['ProductCodes']:
        product_code_id = code.get("ProductCodeId", None)
        if product_code_id in valid_panfw_productcode_byol.keys():
            valid_byol = True
            break

    if valid_byol:
        for retry in range(1, 10):
            logger.info('Identified the fw license as BYOL. The fw will be de-licensed now.')
            try:
                ## TODO
                ret = deactivate_fw_license(instanceId, fwMgmtIp, fwApiKey)
                # ret = deactivate_fw_license_panorama(PIP, KeyPANWPanorama, serial_no)
            except Exception as e:
                logger.exception(
                    "Exception occurred during deactivate license for device: {} with IP: {}. Error:  {}".format(
                        instanceId, fwMgmtIp, e))
                break
            else:
                if not ret:
                    logger.error(
                        'Failed to deactivate the license for device: {} with IP: {}'.format(instanceId, fwMgmtIp))
                else:
                    logger.info(
                        'Successfully deactivated license for device: {} with IP: {}'.format(instanceId, fwMgmtIp))
                    break
                time.sleep(30)
    else:
        logger.info("This firewall device does not have a BYOL license.")

    logger.info('Termination sequence completed.')
    return True


def pa_initialize(hostname, api_key, pa_dmz_priv_ip, pa_dmz_pub_ip, pa_asn, pa_dmz_subnet_gw, SubnetCidr,
                  license_api_key=""):
    """

    :param hostname:
    :param api_key:
    :param pa_dmz_priv_ip:
    :param pa_dmz_pub_ip:
    :param pa_asn:
    :param pa_dmz_subnet_gw:
    :param SubnetCidr:
    :param license_api_key:
    :return:
    Function to initialize PA node
    """

    # Update 'eth1' object with private IP of eth1 interface
    mask = SubnetCidr.split("/")[1]

    response1 = editIpObject(hostname, api_key, "eth1", "/".join([pa_dmz_priv_ip, mask]))
    logger.info('Response to editipobject {}'.format(response1))
    # Update BGP router ID with public IP of eth1 and BGP ASN
    response2 = update_routerId_asn(hostname, api_key, pa_dmz_pub_ip, pa_asn)
    logger.info('Response to updateRouterIdAndAsn {}'.format(response2))
    # Update next hop of static route to match subnet gw
    response3 = update_default_route_nexthop(hostname, api_key, pa_dmz_subnet_gw)
    logger.info('Response to updateDefaultRouteNextHop {}'.format(response3))
    # Add ApiKey to deactivate License
    response4 = config_deactivate_license_apikey(hostname, api_key, license_api_key)
    return [response1, response2, response3, response4]


def editIpObject(hostname, api_key, name, value):
    """
    Function to edit/update an existing IP Address object on a PA Node
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{0}']/ip-netmask".format(
        name)
    element = "<ip-netmask>{0}</ip-netmask>".format(value)
    return pan_edit_config(hostname, api_key, xpath, element)


def update_routerId_asn(hostname, api_key, routerId, routerAsn, virtualRouter="default"):
    """
    Function to edit/update BGP RourterID(Public IP) and ASN on a PA Node
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='{0}']/protocol/bgp".format(
        virtualRouter)
    element = "<router-id>{0}</router-id><local-as>{1}</local-as>".format(routerId, routerAsn)
    return pan_set_config(hostname, api_key, xpath, element)


def update_default_route_nexthop(hostname, api_key, subnetGateway, virtualRouter="default"):
    """Function to update default route virtual router
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='{0}']/routing-table/ip/static-route/entry[@name='default']/nexthop".format(
        virtualRouter)
    element = "<ip-address>{0}</ip-address>".format(subnetGateway)
    return pan_set_config(hostname, api_key, xpath, element)


def updateRouteNexthop(route, hostname, api_key, subnetGateway, interface, virtualRouter="default"):
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
    element = "<destination>{0}</destination><interface>{1}" \
              "</interface><nexthop><ip-address>{2}</ip-address></nexthop>".format(route, interface, subnetGateway)

    return pan_set_config(hostname, api_key, xpath, element)


def update_bgp_tunnel_ip_pool(ipSegment, tableConn, instanceId, paGroupName, Dryrun=False):
    logger.info('Called updateBgpTunnelIpPool with {} {} {} {}'.format(ipSegment, tableConn, instanceId, paGroupName))
    """
    Updates the BgpTunnelIpPool table attributes Available=NO, and add instanceId and PaGroup names to the item
    """

    try:
        # Update BgpTunnelIpPool table Attribute "Available"="NO"
        if not Dryrun: tableConn.update_item(Key={'IpSegment': ipSegment},
                                             AttributeUpdates={'Available': {'Value': 'NO', 'Action': 'PUT'},
                                                               'InstanceId': {'Value': instanceId, 'Action': 'PUT'},
                                                               'PaGroupName': {'Value': paGroupName, 'Action': 'PUT'}})
        logger.info(
            "Successfully Updated BgpIpPoolTable attribute Available=NO, InstanceId: {} and PaGroupName: {}".format(
                instanceId,
                paGroupName))
    except Exception as e:
        logger.error("Error from updateBgpTunnelIpPool, {}".format(str(e)))


def get_available_bgp_tunnel_ip_pool(tableName, instanceId, paGroupName):
    logger.info(
        'Called getAvailableBgpTunnelIpPool(tableName, instanceId, paGroupName) {} {} {}'.format(tableName, instanceId,
                                                                                                 paGroupName))
    """Scans the BgpTunnleIpPool table with attribute 'Avaliable=YES', if it 
    finds any items with this condition returns that item otherwise returns false
    Calls the updateBgpTunnleIpPool function to update the attribute 'Available' to NO
    """
    try:
        logger.info("Fetching BgpTunnelIpPool data with filter status=available")
        table = dynamodb.Table(tableName)
        response = table.scan(FilterExpression=Attr('Available').eq('YES'))['Items']
        if response:
            # Update BgpTunnelIpPool table Attribute "Available"="NO"
            update_bgp_tunnel_ip_pool(response[0]['IpSegment'], table, instanceId, paGroupName)
            return response[0]
        else:
            return False
    except Exception as e:
        logger.error("getAvailableBgpTunnelIpPool failed, Error: {}".format(str(e)))


def updateVpcTable(tableName, data, status):
    """Updates the Transit VpcTable with VpcId, Node1VpnId, Node2VpnId, Region, IpSegment and CurrentStatus
    """
    try:
        # VpcId is the primary key for VpcTable
        table = dynamodb.Table(tableName)
        response = table.update_item(Key={'VpcId': data['VpcId']},
                                     AttributeUpdates={'CurrentStatus': {'Value': status, 'Action': 'PUT'},
                                                       'Node1VpnId': {'Value': data['VpnN1'], 'Action': 'PUT'},
                                                       'Node2VpnId': {'Value': data['VpnN2'], 'Action': 'PUT'},
                                                       'Region': {'Value': data['Region'], 'Action': 'PUT'},
                                                       'IpSegment': {'Value': data['IpSegment'], 'Action': 'PUT'}})
    except Exception as e:
        logger.error("Updating Transit VpcTalbe is Failed, Error: {}".format(str(e)))


def delete_vpn_connection(VpnConnectionId, DryRun=False):
    try:
        response = ec2_client.delete_vpn_connection(
            VpnConnectionId=VpnConnectionId,
            DryRun=DryRun
        )
        return 'success'
    except Exception as e:
        logger.info('Got error {} deleting vpn connection'.format(e))
        return 'error'


def delete_cgw(cgwId, DryRun=False):
    try:
        response = ec2_client.delete_customer_gateway(
            CustomerGatewayId=cgwId,
            DryRun=DryRun
        )
        return 'success'
    except Exception as e:
        logger.info('Got error {} deleting cgw'.format(e))
        return 'error'


def create_vpn_connection_upload_to_s3(Region, tgwId, cgwId, tunnelOneCidr, tunnelTwoCidr, tag, bucketName,
                                       assumeRoleArn=None):
    """Creates VPN connection and upload the VPN configuration to the S3 bucket
    """
    try:
        tags = [{'Key': 'Name', 'Value': tag}]
        ec2Connection = boto3.client('ec2', region_name=Region)
        response = ec2Connection.create_vpn_connection(
            CustomerGatewayId=cgwId,
            Type='ipsec.1',
            TransitGatewayId=tgwId,
            DryRun=False,
            Options={
                'StaticRoutesOnly': False,
                'TunnelOptions': [
                    {
                        'TunnelInsideCidr': tunnelOneCidr
                    },
                    {
                        'TunnelInsideCidr': tunnelTwoCidr
                    }
                ]
            }
        )
        ec2Connection.create_tags(Resources=[response['VpnConnection']['VpnConnectionId']], Tags=tags)
        # Uploading VPN configuration to S3 bucket
        if assumeRoleArn:
            uploadObjectToS3(response, bucketName, assumeRoleArn)
        else:
            uploadObjectToS3(response, bucketName)
        return response['VpnConnection']['VpnConnectionId']
    except Exception as e:
        logger.error("Error Creating VPN Connection, Error: {}".format(str(e)))


def uploadObjectToS3(vpnConfiguration, bucketName, assumeRoleArn=None):
    """Uploads an object(VPN Conf file) to S3 bucket
    """
    try:
        s3Connection = boto3.resource('s3')
        fileName = vpnConfiguration['VpnConnection']['VpnConnectionId'] + '.xml'
        vpnConfig = vpnConfiguration['VpnConnection']['CustomerGatewayConfiguration']
        # open(filePath).write(vpnConfiguration['VpnConnection']['CustomerGatewayConfiguration'])
        if assumeRoleArn:
            stsConnection = boto3.client('sts')
            assumedrole = stsConnection.assume_role(RoleArn=assumeRoleArn, RoleSessionName="Sample")
            s3 = boto3.resource('s3', aws_access_key_id=assumedrole['Credentials']['AccessKeyId'],
                                aws_secret_access_key=assumedrole['Credentials']['SecretAccessKey'],
                                aws_session_token=assumedrole['Credentials']['SessionToken'])
            s3.Object(bucketName, fileName).put(Body=vpnConfig)
            return True
        s3Connection.Object(bucketName, fileName).put(Body=vpnConfig)
        return True
    except Exception as e:
        logger.error("Error uploading file to S3 Bucket, Error : {}".format(str(e)))
        return False


def create_cgw(cgwIp, cgwAsn, Region, tag):
    logger.info('Called createCgw(cgwIp, cgwAsn, Region, tag) {} {} {} {}'.format(cgwIp, cgwAsn, Region, tag))
    """Creates CGW and returns CgwId
    """
    try:
        tags = [{'Key': 'Name', 'Value': tag}]
        ec2Connection = boto3.client('ec2', region_name=Region)
        response = ec2Connection.create_customer_gateway(BgpAsn=int(cgwAsn), PublicIp=cgwIp, Type='ipsec.1')
        ec2Connection.create_tags(Resources=[response['CustomerGateway']['CustomerGatewayId']], Tags=tags)
        return response['CustomerGateway']['CustomerGatewayId']
    except Exception as e:
        logger.error("Error in createCgw(), Error: {}".format(str(e)))
        return False


def check_cgw(awsRegion, fwUntrustPubIP, n2Eip):
    logger.info('Called checkCgw(awsRegion, fwUntrustPubIP, n2Eip) {} {} {}'.format(awsRegion, fwUntrustPubIP, n2Eip))
    """Verifies whether the CGWs are already created or not, returns either a list of cgwIds or False
    """
    try:
        cgwIds = []
        ec2_conn = boto3.client('ec2', region_name=awsRegion)
        filters = [{'Name': 'ip-address', 'Values': [fwUntrustPubIP]}]
        response = ec2_conn.describe_customer_gateways(Filters=filters)['CustomerGateways']
        if response:
            for cgw in response:
                if cgw['State'] == 'available':
                    cgwIds.append(cgw['CustomerGatewayId'])
        filters = [{'Name': 'ip-address', 'Values': [n2Eip]}]
        response = ec2_conn.describe_customer_gateways(Filters=filters)['CustomerGateways']
        if response:
            for cgw in response:
                if cgw['State'] == 'available':
                    cgwIds.append(cgw['CustomerGatewayId'])
        if cgwIds:
            return cgwIds
        else:
            return False
    except Exception as e:
        logger.error("Error from checkCgw, Error: {}".format(str(e)))
        return False


def pa_group_configure_vpn(api_key, paGroup, vpnConfigBucket, N1VpnId, N2VpnId, ikeProfile="default",
                           ipsecProfile="default", pa_dmz_inf="eth1", virtualRouter="default",
                           zone="UNTRUST"):
    """Function to configure VPN with a PAGroup and a VPC. Each node in the PAGroup will establish a VPN with the VPC.
    """
    # Configure VPN on Node1
    vpnN1Conf = loadVpnConfigFromS3(vpnConfigBucket, N1VpnId)
    peerGroup = "Active"  # Incase needed, this can come from PaGroupInfo eg: paGroup['PaN1Type'] = "Active"
    N1VpnStatus = pa_configure_vpn(paGroup['N1Mgmt'], api_key, vpnN1Conf, peerGroup, ikeProfile, ipsecProfile,
                                   pa_dmz_inf,
                                   virtualRouter, zone)

    # Configure VPN on Node2
    vpnN2Conf = loadVpnConfigFromS3(vpnConfigBucket, N2VpnId)
    peerGroup = "Passive"  # Incase needed, this can come from PaGroupInfo eg: paGroup['PaN1Type'] = "Active"
    N2VpnStatus = pa_configure_vpn(paGroup['N2Mgmt'], api_key, vpnN2Conf, peerGroup, ikeProfile, ipsecProfile,
                                   pa_dmz_inf,
                                   virtualRouter, zone)

    # Return False if something fails
    if not N1VpnStatus or not N2VpnStatus:
        pan_rollback(paGroup['N1Mgmt'], api_key)
        pan_rollback(paGroup['N2Mgmt'], api_key)
        return False
    else:
        pan_commit(paGroup['N1Mgmt'], api_key, message="VpnConfigured N1VpnId: {}".format(N1VpnId))
        pan_commit(paGroup['N2Mgmt'], api_key, message="VpnConfigured N2VpnId: {}".format(N2VpnId))
        return True


def pa_configure_vpn(hostname, api_key, vpnConfDict, peerGroup, ikeProfile="default", ipsecProfile="default",
                     pa_dmz_inf="ethernet1/1", virtualRouter="default", zone="UNTRUST"):
    """Function to configure IPSec vpn on a PA Node
    """
    try:
        # Configure T1 IKE
        create_ike_gateway(hostname, api_key,
                           "-".join(["ike", vpnConfDict['id'], "0"]),
                           vpnConfDict['t1_ike_psk'], ikeProfile,
                           pa_dmz_inf, vpnConfDict['t1_ike_peer'])
        # Configure T2 IKE
        create_ike_gateway(hostname, api_key,
                           "-".join(["ike", vpnConfDict['id'], "1"]),
                           vpnConfDict['t2_ike_psk'], ikeProfile,
                           pa_dmz_inf, vpnConfDict['t2_ike_peer'])
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
    except:
        print("PA VPN configuration failed", sys.exc_info()[0])
        return False

    logger.info('Got responses to api request Ipsec tunnel {} {} \nPeer Group {} {} '
                .format(response1, response2, response3, response4))
    return True


def getFirewallStatus(fwIP, api_key):
    fwip = fwIP

    """
    Gets the firewall status by sending the API request show chassis status.
    :param fwMgtIP:  IP Address of firewall interface to be probed
    :param api_key:  Panos API key
    """
    global gcontext

    url = "https://%s/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=%s" % (fwip, api_key)
    # Send command to fw and see if it times out or we get a response
    logger.info("Sending command 'show chassis status' to firewall")
    try:
        response = requests.get(url, verify=False, timeout=10)
        response.raise_for_status()
    except requests.exceptions.Timeout as fwdownerr:
        logger.debug("No response from FW. So maybe not up!")
        return 'no'
        # sleep and check again?
    except requests.exceptions.HTTPError as fwstartgerr:
        '''
        Firewall may return 5xx error when rebooting.  Need to handle a 5xx response
        raise_for_status() throws HTTPError for error responses
        '''
        logger.infor("Http Error: {}: ".format(fwstartgerr))
        return 'cmd_error'
    except requests.exceptions.RequestException as err:
        logger.debug("Got RequestException response from FW. So maybe not up!")
        time.sleep(10)
        return 'cmd_error'
    else:
        logger.debug("Got response to 'show chassis status' {}".format(response))

        resp_header = ET.fromstring(response.content)
        logger.debug('Response header is {}'.format(resp_header))

        if resp_header.tag != 'response':
            logger.debug("Did not get a valid 'response' string...maybe a timeout")
            time.sleep(10)
            return 'cmd_error'

        if resp_header.attrib['status'] == 'error':
            logger.debug("Got an error for the command")
            time.sleep(10)
            return 'cmd_error'

        if resp_header.attrib['status'] == 'success':
            # The fw responded with a successful command execution. So is it ready?
            for element in resp_header:
                if element.text.rstrip() == 'yes':
                    logger.info("FW Chassis is ready to accept configuration and connections")
                    return 'yes'
                else:
                    logger.info("FW Chassis not ready, still waiting for dataplane")
                    time.sleep(10)
                    return 'almost'


class FWNotUpException(Exception):
    pass


def getApiKey(hostname, username, password):
    """
    Generate the API key from username / password
    """

    call = "https://%s/api/?type=keygen&user=%s&password=%s" % (hostname, username, password)
    api_key = ""
    while True:
        try:
            # response = urllib.request.urlopen(url, data=encoded_data, context=ctx).read()
            response = send_request(call)

        except FWNotUpException as updateerr:
            logger.info("No response from FW. Wait 30 secs before retry")
            time.sleep(30)
            # raise FWNotUpException("Timeout Error")
            continue

        else:
            api_key = ET.XML(response.content)[0][0].text
            logger.info("FW Management plane is Responding so checking if Dataplane is ready")
            logger.debug("Response to get_api is {}".format(response))
            return api_key


def send_request(call):
    """
    Handles sending requests to API
    :param call: url
    :return: Retruns result of call. Will return response for codes between 200 and 400.
             If 200 response code is required check value in response
    """
    headers = {'Accept-Encoding': 'None',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

    try:
        r = requests.get(call, headers=headers, verify=False, timeout=5)
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        '''
        Firewall may return 5xx error when rebooting.  Need to handle a 5xx response 
        '''
        logger.debug("DeployRequestException Http Error:")
        raise FWNotUpException("Http Error:")
    except requests.exceptions.ConnectionError as errc:
        logger.debug("DeployRequestException Connection Error:")
        raise FWNotUpException("Connection Error")
    except requests.exceptions.Timeout as errt:
        logger.debug("DeployRequestException Timeout Error:")
        raise FWNotUpException("Timeout Error")
    except requests.exceptions.RequestException as err:
        logger.debug("DeployRequestException RequestException Error:")
        raise FWNotUpException("Request Error")
    else:
        return r


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


# def getApiKey(hostname, username, password):
#     '''Generate API keys using username/password
#     API Call: http(s)://hostname/api/?type=keygen&user=username&password=password
#     '''
#     data = {
#         'type': 'keygen',
#         'user': username,
#         'password': password
#     }
#     response = makeApiCall(hostname, data)
#     return xml.etree.ElementTree.XML(response)[0][0].text


def pan_op_cmd(hostname, api_key, cmd):
    """Function to make an 'op' call to execute a command
    """
    data = {
        "type": "op",
        "key": api_key,
        "cmd": cmd
    }
    return make_api_call(hostname, data)


def pan_commit(hostname, api_key, message=""):
    """Function to commit configuration changes
    """
    data = {
        "type": "commit",
        "key": api_key,
        "cmd": "<commit>{0}</commit>".format(message)
    }
    return make_api_call(hostname, data)


def config_deactivate_license_apikey(hostname, api_key, license_api_key):
    """Function to configure DeactivateLicense API Key
    This function is used during initialization of a PA Node and requires internet connectivity
    """
    cmd = "<request><license><api-key><set><key>" + license_api_key + "</key></set></api-key></license></request>"
    return pan_op_cmd(hostname, api_key, cmd)


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


def pan_rollback(hostname, api_key, username="admin"):
    """Function to rollback uncommited changes
    """
    # https://firewall/api/?key=apikey&type=op&cmd=<revert><config><partial><admin><member>admin-name</member></admin></partial></config></revert>
    # panOpCmd(hostname, api_key, cmd)
    cmd = "<revert><config><partial><admin><member>" + username + "</member></admin></partial></config></revert>"
    pan_op_cmd(hostname, api_key, cmd)


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


def create_ike_gateway(hostname, api_key, name, psk, ikeProfile, pa_dmz_inf, peerIp):
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

    return pan_set_config(hostname, api_key, xpath, element)

    xpath2 = "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='{0}']/local-address".format(
        name)
    element2 = "<ip>{0}</ip>".format(src_ip)

    pan_set_config(hostname, api_key, xpath2, element2)


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


class XmlListConfig(list):
    def __init__(self, aList):
        for element in aList:
            if element:
                # treat like dict
                if len(element) == 1 or element[0].tag != element[1].tag:
                    self.append(XmlDictConfig(element))
                # treat like list
                elif element[0].tag == element[1].tag:
                    self.append(XmlListConfig(element))
            elif element.text:
                text = element.text.strip()
                if text:
                    self.append(text)


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


def retrieve_fw_ip(instance_id):
    """
    Retrieve the IP of the Instance

    @param instance_id The id of the instance
    @type ```str```
    """

    eni_response = ec2_client.describe_network_interfaces(
        Filters=[{'Name': "attachment.instance-id", 'Values': [instance_id]},
                 {'Name': "attachment.device-index", 'Values': ["1"]}])

    logger.info("Describe network interfaces response: {}".format(eni_response))

    eniId = ""
    for eni in eni_response['NetworkInterfaces']:
        eniId = eni['NetworkInterfaceId']

    if eniId == "":
        logger.error('Mgmt ENI ID not found for instance: ' + instance_id)
        return False

    logger.info('Eni ID (eth1) for instance : ' + instance_id + ' is: ' + eniId)
    try:
        response = ec2_client.describe_network_interfaces(NetworkInterfaceIds=[eniId])
    except Exception as e:
        logger.error("[Describe network interfaces failed while retrieving fw ip]: {}".format(e))
        return False

    ip = "NO_IP"
    try:
        for i in response['NetworkInterfaces']:
            logger.info(i['PrivateIpAddresses'])
            ip = i['PrivateIpAddress']
    except Exception as e:
        logger.error("[FW IP Address in retrieve fw ip]: {}".format(e))
        ip = "NO_PrivateIP_ADDR"

    if ip.find("NO_") >= 0:
        logger.error('We failed to get either EIP or Private IP for instance: ' + str(instance_id) + ' IP: ' + ip)
        logger.error('We will not proceed further with this Instance: ' + str(instance_id))
        return False
    else:
        logger.info('The IP address of the fw device is: {}'.format(ip))
        return ip


def get_cidr(subnetId):
    """

    :param subnetId:
    :return: returns subnet cidr as string x.x.x.x/x
    Get the cidr block from a subnetId
    """
    try:
        response = ec2_client.describe_subnets(SubnetIds=[subnetId])
    except Exception as e:
        logger.info("Failed to get subnet cidr from subnet id {}".format(e))

    subnet_cidr = response['Subnets'][0]['CidrBlock']
    return subnet_cidr


def update_tgw_firewall(vpc_summary_route, fw_trust_ip, fw_untrust_ip, api_key, trustAZ_subnet_cidr, fw_untrust_int):
    """
    Parse the repsonse from makeApiCall()
    :param vpc_summary_route:
    :param fw_trust_ip:
    :param fw_untrust_ip:
    :param api_key:
    :param trustAZ_subnet_cidr:
    :param fw_untrust_int:
    :return:
    If we see the string 'yes' in the repsonse we will assume that the firewall is up and continue with the firewall
    configuration
    """

    class FWNotUpException(Exception):
        pass

    err = 'no'
    while (True):
        err = getFirewallStatus(fw_trust_ip, api_key)
        if err == 'cmd_error':
            logger.info("[ERROR]: Command error from fw ")
            time.sleep(10)
            raise FWNotUpException('FW is not up!  Request Timeout')
            # terminate('false')
            # return
        elif err == 'no':
            # logger.info("[INFO] FW is not up...yet")
            time.sleep(10)
            # continue
            raise FWNotUpException('FW is not up!')
        elif err == 'almost':
            # this means autocommit is happening
            time.sleep(10)
            # continue
            raise FWNotUpException('FW is not up. Nic responds but DP not ready!')
        elif err == 'yes':
            logger.info("[INFO]: FW is up")
            break


def get_gw_ip(cidr):
    ip = netaddr.IPNetwork(cidr)
    iplist = list(ip)
    return iplist[1]


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
    logger.info('Querying for subnet')
    logger.debug('calling ec2.describe_subnets with args: %s', kwargs)

    try:
        subnets = ec2_client.describe_subnets(**kwargs)['Subnets']
    except:
        logger.debug('No Classic subnet found matching query.')
        return None
    logger.debug("Result: %s", subnets)
    if len(subnets) < 1:
        raise SystemExit("Error: 0 subnets found matching: {}".format(kwargs))
    if len(subnets) > 1:
        raise SystemExit("Error: {} subnets found matching: {}".format(len(subnets), kwargs))
    return subnets[0]


def get_tgw_vpn_attachmentid(resource_id):
    attachment_id = ''
    response = 0
    attachment_count = 0
    while (attachment_count == 0):
        try:
            ec2_client = boto3.client('ec2', region_name=Region)
            response = ec2_client.describe_transit_gateway_attachments(
                TransitGatewayAttachmentIds=[],
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [
                            str(resource_id),
                        ]
                    },
                ],
                MaxResults=123,
                DryRun=False
            )
            attachment_count = len(response['TransitGatewayAttachments'])
            if attachment_count > 0:
                logger.info(
                    'Got response {} looking for vpn attachmentid from resourceid {}'.format(response, resource_id))
                state = response['TransitGatewayAttachments'][0].get('State')
                logger.info('Attachment state is {}'.format(state))
                attachment_id = response['TransitGatewayAttachments'][0].get('TransitGatewayAttachmentId')
                break
        except Exception as e:
            time.sleep(5)
            print('{}'.format(e))
    return attachment_id

def get_tgw_vpn_attachment_data(resource_id):
    attachment_id = ''
    response = 0
    attachment_count = 0
    while (attachment_count == 0):
        try:
            ec2_client = boto3.client('ec2', region_name=Region)
            response = ec2_client.describe_transit_gateway_attachments(
                TransitGatewayAttachmentIds=[],
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [
                            str(resource_id),
                        ]
                    },
                ],
                MaxResults=123,
                DryRun=False
            )
            logger.info(
                'Got response {} looking for vpn attachmentid from resourceid {}'.format(response, resource_id))
            attachment_count = len(response['TransitGatewayAttachments'])
            if attachment_count > 0:
                state = response['TransitGatewayAttachments'][0].get('State')
                logger.info('Attachment state is {}'.format(state))
                break
            else:
                logger.info('Attachment count is zero')
        except Exception as e:
            time.sleep(5)
            print('{}'.format(e))
    return response['TransitGatewayAttachments'][0]


def create_vpn_association(attachment_id, tgw_route_table_id):
    try:
        response = ec2_client.associate_transit_gateway_route_table(
            TransitGatewayRouteTableId=tgw_route_table_id,
            TransitGatewayAttachmentId=attachment_id,
            DryRun=False
        )
        return True
    except Exception as e:
        logger.info('Got vpn association error'.format(e))
        return False


def create_vpn_propagation(attachment_id, tgw_route_table_id):
    try:
        response1 = ec2_client.enable_transit_gateway_route_table_propagation(
            TransitGatewayRouteTableId=tgw_route_table_id,
            TransitGatewayAttachmentId=attachment_id,
            DryRun=False
        )
        return True
    except Exception as e:
        logger.info('Got vpn propagation error'.format(e))
        return False


## START LAUNCH CODE
def create_vpn(fwUntrustPubIP, gwMgmtPubIp, pa_asn, Region, cgw1Tag, table_name, tgwId,
               api_key, bucketName, tag, instanceId, TransitGatewayRouteTableId):
    """

    :param fwUntrustPubIP:
    :param gwMgmtPubIp:
    :param fwUntrustPrivIP:
    :param fwUntrustSubnet:
    :param pa_asn:
    :param Region:
    :param cgw1Tag:
    :param table_name:
    :param tgwId:
    :param username:
    :param password:
    :param bucketName:
    :param tag:
    :param instanceId:
    :return:
    Main function that will configure the firewall and VPN connections.
    """

    cgwId = create_cgw(fwUntrustPubIP, pa_asn, Region, cgw1Tag)

    response = get_available_bgp_tunnel_ip_pool(table_name, instanceId, cgw1Tag)
    N1T2 = response['N1T2']
    N1T1 = response['N1T1']

    vpnId = create_vpn_connection_upload_to_s3(Region, tgwId, cgwId, N1T1, N1T2, tag, bucketName, assumeRoleArn=None)

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

    update_bgp_table(table_name, vpnId, cgwId, instanceId)
    logger.info('Reserving IP address in BGP table')

    peerGroup = 'tgw-out'
    confVpnStatus = pa_configure_vpn(gwMgmtPubIp, api_key, vpnConfDict, peerGroup,
                                     ikeProfile="default", ipsecProfile="default",
                                     pa_dmz_inf="ethernet1/1", virtualRouter="default", zone="Untrust")

    attachment_id = get_tgw_vpn_attachmentid(str(vpnId))
    if attachment_id:
        logger.info('latest attachment id is {}'.format(attachment_id))
        create_vpn_association(attachment_id, TransitGatewayRouteTableId)
        create_vpn_propagation(attachment_id, TransitGatewayRouteTableId)
    else:
        logger.info('Didnt get attachmentid for vpn')

    if not confVpnStatus:
        pan_rollback(gwMgmtPubIp, api_key)
        return False
    else:
        pan_commit(gwMgmtPubIp, api_key, message="VpnConfigured")
        return True


###END LAUNCH CODE

def retrieve_fw_ip(instance_id):
    """
    Retrieve the IP of the Instance

    :param instance_id: The id of the instance
    :type instance_id: str
    """

    eni_response = ec2_client.describe_network_interfaces(
        Filters=[{'Name': "attachment.instance-id", 'Values': [instance_id]},
                 {'Name': "attachment.device-index", 'Values': ["1"]}])

    logger.info("Describe network interfaces response: {}".format(eni_response))

    eniId = ""
    for eni in eni_response['NetworkInterfaces']:
        eniId = eni['NetworkInterfaceId']

    if eniId == "":
        logger.error('Mgmt ENI ID not found for instance: ' + instance_id)
        return False

    logger.info('Eni ID (eth1) for instance : ' + instance_id + ' is: ' + eniId)
    try:
        response = ec2_client.describe_network_interfaces(NetworkInterfaceIds=[eniId])
    except Exception as e:
        logger.error("[Describe network interfaces failed while retrieving fw ip]: {}".format(e))
        return False

    ip = "NO_IP"
    try:
        for i in response['NetworkInterfaces']:
            logger.info(i['PrivateIpAddresses'])
            ip = i['PrivateIpAddress']
    except Exception as e:
        logger.error("[FW IP Address in retrieve fw ip]: {}".format(e))
        ip = "NO_PrivateIP_ADDR"

    if ip.find("NO_") >= 0:
        logger.error('We failed to get either EIP or Private IP for instance: ' + str(instance_id) + ' IP: ' + ip)
        logger.error('We will not proceed further with this Instance: ' + str(instance_id))
        return False
    else:
        logger.info('The IP address of the fw device is: {}'.format(ip))
        return ip


def terminate_gw(event, tablename):
    """

    :param message:
    message = {
            'lambda_bucket_name': lambda_bucket_name,
            'event-name': 'gw-terminate',
            'instance-id': ec2_instanceid,
            'asg_name': asg_name,
            'asg_hookname': lifecycle_hook_name
        }
    :param tablename: BGP Tunnel info
    :return:

    Handles the deletion of the VPN connection and the CGW. Releases the Tunnel IPs back to the pool in dynamodb
    """
    context = ''
    tablename = tablename
    table = dynamodb.Table(tablename)
    global this_func_name
    global lambda_function_arn

    """
    Content of message
    parameters = {
            'lambda_bucket_name': lambda_bucket_name,
            'event-name': 'gw-terminate',
            'instance-id': ec2_instanceid,
            'asg_name': asg_name,
            'asg_hookname': lifecycle_hook_name
        }
    """
    instance_id = event.get('instance-id')

    response = table.scan(FilterExpression=Attr('InstanceId').eq(instance_id))
    cgwId = response['Items'][0]['cgwId']
    vpnConnection_id = response['Items'][0]['vpnId']

    if delete_vpn_connection(vpnConnection_id) == 'error':
        logger.info("Failed to delete vpn connection")
        # terminate('false')
        return 'error'
    else:
        success = 'success'
        logger.info("Deleted vpn connection")

    if delete_cgw(cgwId, DryRun=False) == 'error':
        logger.info("Failed to delete cgw")
        # terminate('false')
        return 'error'
    else:
        success = 'success'
        logger.info("Deleted cgw")

    logger.info('Calling release_ips with instance {} from table {}'.format(instance_id, tablename))

    release_ips(tablename, instance_id)

    done('true', context, success)
    return


def done(success, context, asg_message):
    """
    Method to send a successful response to an
    ASG lifecycle action.

    :param success:
    :param context:
    :param asg_message:
    :return:
    """
    result = "CONTINUE"

    # call autoscaling
    try:
        asg.complete_lifecycle_action(
            AutoScalingGroupName=asg_message['AutoScalingGroupName'],
            LifecycleHookName=asg_message['LifecycleHookName'],
            LifecycleActionToken=asg_message['LifecycleActionToken'],
            LifecycleActionResult=result)
    except Exception as e:
        logger.error("[complete_lifecycle_action]: {}".format(e))
        return False

    return True


def release_ips(tablename, instance_id):
    strinstance = instance_id
    table = dynamodb.Table(tablename)
    logger.info('Releasing instance {} from table {}'.format(tablename, strinstance))


def release_ips(tablename, instanceId):
    """
    When the Firewall is terminated we release the IP addresses from the IP pool and release them in the
    Dynamodb table.
    :param tablename:
    :param instanceId:
    :return:
    """
    strinstance = instanceId
    table = dynamodb.Table(tablename)

    try:
        response = table.scan(FilterExpression=Attr('InstanceId').eq(strinstance))

        keyvalue = response['Items'][0]['IpSegment']

        response = table.update_item(
            Key={'IpSegment': keyvalue},
            UpdateExpression="set Available = :val1, InstanceId = :val2, cgwId = :val2, vpnId = :val2",
            ExpressionAttributeValues={
                ':val1': "YES",
                ':val2': "None"
            },
            ReturnValues="UPDATED_NEW"
        )
        return
    except Exception as e:
        logger.info('Got error {}'.format(e))
        return 'false'


def update_bgp_table(tableName, vpnId, cgwId, instanceId):
    tablename = tableName
    strinstance = instanceId
    table = dynamodb.Table(tablename)
    """Updates the BGP table with vpnId and cgwId
    """

    response = table.scan(FilterExpression=Attr('InstanceId').eq(strinstance))

    keyvalue = response['Items'][0]['IpSegment']
    try:
        response = table.update_item(
            Key={'IpSegment': keyvalue},
            UpdateExpression="set vpnId = :val1, cgwId = :val2",
            ExpressionAttributeValues={
                ':val1': vpnId,
                ':val2': cgwId
            },
        )
        return
    except Exception as e:
        logger.error("Updating Table {} is Failed, Error: {}".format(tableName, str(e)))


def terminate(value):
    print(value)
    exit(0)


def config_fw_lambda_handler(event, context):
    """

    :param event:
        event = {
            'lambda_bucket_name': lambda_bucket_name,
            'event-name': 'gw-terminate/gw-launch',
            'instance-id': ec2_instanceid,
            'asg_name': asg_name,
            'asg_hookname': lifecycle_hook_name
        }
    :param context:

    Handles the configuration of the VPN connection between the firewall and AWS CGW.

    :return:
    """
    logger.info('[INFO] Got event{}'.format(event))
    context = ''
    table_name = os.environ['table_name']
    tgwId = os.environ['tgwId']
    Region = os.environ['Region']
    pa_asn = os.environ['N1Asn']

    username = os.environ['username']
    password = os.environ['password']

    cgw1Tag = 'justin-tag'
    tag = cgw1Tag

    event_type = event.get('event-name')
    if event_type == 'gw-terminate':
        instanceId = event.get('instance-id')

        if instanceId is None:
            logger.info("[ERROR]: didn't get Instance Id")
            return
        logger.info("[INFO]: Got GW terminate event")

        message = event.get('message')
        if instanceId is None:
            logger.info("[ERROR]: didn't get message")
            return
        logger.info("[INFO]: Got GW terminate event")

        terminate_gw(event, table_name)

        return

    elif event_type == 'gw-launch':
        gwMgmtPubIp = event.get('fwMgmtIP')
        fwUntrustSubnet = event.get('fwUntrustSubnet')

        if gwMgmtPubIp is None:
            logger.info("[ERROR]: didn't get GW MGMT IP addresses")
            # terminate('false')
            return

        fwUntrustPubIP = event.get('fwUntrustPubIP')
        if fwUntrustPubIP is None:
            logger.info("[ERROR]: didn't get GW DP Public IP addresses")
            # terminate('false')
            return

        fwUntrustPrivIP = event.get('fwUntrustPrivIP')
        if fwUntrustPrivIP is None:
            logger.info("[ERROR]: didn't get FW DP Private IP addresses")
            # terminate('false')
            return

        instanceId = event.get('instance-id')
        if instanceId is None:
            logger.info("[ERROR]: didn't get Instance Id")
            # raise Exception('Failed to get ASG name in : ', inspect.stack()[1][3])
            # terminate('false')
            return

        lambda_bucket_name = event.get('lambda_bucket_name')
        if lambda_bucket_name is None:
            logger.info("[ERROR]: didn't get lambda bucket name")
            # terminate('false')
            return

        bucketName = lambda_bucket_name
        logger.info("[INFO]: Got gw launch event")
        config_gw(fwUntrustPubIP, gwMgmtPubIp, fwUntrustPrivIP, fwUntrustSubnet, pa_asn, Region, cgw1Tag, table_name,
                  tgwId, username, password, bucketName, tag, instanceId)
        return
    else:
        logger.info("[ERROR]: What event is this?")
        # terminate('false')
        return


if __name__ == '__main__':
    # event = {
    #     "fwMgmtIP": "99.80.157.206",
    #     "lambda_bucket_name": "jrh-tgw-boot",
    #     "event-name": "gw-launch",
    #     "fwUntrustPubIP": "108.129.5.189",
    #     "fwUntrustPrivIP": "10.0.2.136",
    #     "instance-id": "i-0b5789708de089d0a",
    #     "asg_name": "justin-ASGDemo-18MUM82XB0T7C",
    #     "asg_hookname": "justin-ASGLifecycleHookL-1UE27I8Y80VKR",
    #     "fwUntrustSubnet": "subnet-0da026d338af9d959"
    # }
    event = {
        "lambda_bucket_name": "us-east-1-autoscale",
        "event-name": "gw-terminate",
        "instance-id": "i-0778420feacdb7dee",
        "asg_name": "satstack1ASG",
        "asg_hookname": "satstack1ASG-life-cycle-terminate"
    }

    context = ''
    config_fw_lambda_handler(event, context)
