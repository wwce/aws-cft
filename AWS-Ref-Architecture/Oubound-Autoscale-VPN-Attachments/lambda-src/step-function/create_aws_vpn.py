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
import os
import boto3
import sys
from boto3.dynamodb.conditions import Attr

sys.path.append('asglib/')
import tgwaslib as lib

from botocore.exceptions import ClientError

Region = os.environ['Region']
dynamodb = boto3.resource('dynamodb', region_name=Region)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

subnets = []

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
            result = uploadObjectToS3(response, bucketName, assumeRoleArn)
        else:
            result = uploadObjectToS3(response, bucketName)
        if result:
            logger.info('Successfully uploaded vpn config file to S3')
            return response['VpnConnection']['VpnConnectionId']
        else:
            logger.info('VPN created but unable to upload config file to S3')
            return
    except Exception as e:
        logger.error("Error Creating VPN Connection, Error: {}".format(str(e)))
        return


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
        return


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

def find_subnet_by_id(subnet_id):
    """
    find a subnet by subnet ID. Sets a Filter based on the subnet_id and calls find_classic_subnet()
    :param subnet_id:

    """
    kwargs = {
        'SubnetIds': [subnet_id]
    }
    return find_classic_subnet(kwargs)


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



def create_tgw_vpn(fwUntrustPubIP, pa_asn, Region, cgw1Tag, table_name, tgwId, bucketName, tag, instanceId):

    """

    :param fwUntrustPubIP:
    :param pa_asn:
    :param Region:
    :param cgw1Tag:
    :param table_name:
    :param tgwId:
    :param bucketName:
    :param tag:
    :param instanceId:
    :return:
    """

    cgwId = create_cgw(fwUntrustPubIP, pa_asn, Region, cgw1Tag)

    tunnel_ints = get_available_bgp_tunnel_ip_pool(table_name, instanceId, cgw1Tag)
    N1T2 = tunnel_ints.get('N1T2')
    N1T1 = tunnel_ints.get('N1T1')
    vpnId = ''
    if cgwId and N1T1 and N1T2:
        vpnId = create_vpn_connection_upload_to_s3(Region, tgwId, cgwId, N1T1, N1T2, tag, bucketName, assumeRoleArn=None)
        update_bgp_table(table_name, vpnId, cgwId, instanceId)
        logger.info('Reserving IP address in BGP table')
    else:
        logger.info('Unable to create cgw input parameters')
    return vpnId

def lambda_handler(event, context):
    logger.info("Got Event {}".format(event))
    Region = os.environ['Region']
    table_name = os.environ['table_name']
    tgwId = os.environ['tgwId']
    pa_asn = os.environ['N1Asn']
    TransitGatewayRouteTableId = os.environ['tgwRouteId']
    fw1_trust_ip = os.environ['fw1TrustIp']
    fw2_trust_ip = os.environ['fw2TrustIp']
    fw1_untrust_pub_ip = os.environ['fw1UntrustPubIp']
    fw2_untrust_pub_ip = os.environ['fw2UntrustPubIp']
    fw1instanceId = os.environ['fw1instanceId']
    fw2instanceId = os.environ['fw2instanceId']
    api_key = os.environ['apikey']
    lambda_bucket_name = os.environ['lambda_bucket_name']


    cgw1Tag = fw1instanceId
    cgw2Tag = fw2instanceId
    tag1 = fw1instanceId
    tag2 = fw2instanceId

    fw1_vpnId = create_tgw_vpn(pa_asn, Region, cgw1Tag, table_name, tgwId,lambda_bucket_name, tag1, fw1instanceId)

    logger.info('created fw1 vpn with vpnId {}'.format(fw1_vpnId))

    fw2_vpnId = create_tgw_vpn(pa_asn, Region, cgw1Tag, table_name, tgwId,lambda_bucket_name, tag1, fw2instanceId)

    logger.info('created fw2 vpn with vpnId {}'.format(fw2_vpnId))

    if fw1_vpnId and fw2_vpnId:
        data = {
            'action': 'config_fw',
            'fw1_vpnId' : fw1_vpnId,
            'fw2_vpnId' : fw2_vpnId,
            }
    else:
        data = {
            'action': 'failed'
            }
    return data







