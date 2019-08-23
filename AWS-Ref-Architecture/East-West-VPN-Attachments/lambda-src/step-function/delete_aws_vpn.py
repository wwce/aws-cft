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
import boto3
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

from boto3.dynamodb.conditions import Attr

Region = os.environ['Region']
table_name = os.environ['table_name']

dynamodb = boto3.resource('dynamodb', region_name=Region)
lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')


def release_ips(tablename, vpnId):
    """
    When the Firewall is terminated we release the IP addresses from the IP pool and release them in the
    Dynamodb table.
    :param tablename:
    :param instanceId:
    :return:
    """
    strinstance = vpnId
    table = dynamodb.Table(tablename)

    try:
        response = table.scan(FilterExpression=Attr('vpnId').eq(strinstance))

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


def delete_vpn_connection(VpnConnectionId, DryRun=False):
    try:
        response = ec2_client.delete_vpn_connection(
            VpnConnectionId=VpnConnectionId,
            DryRun=DryRun
        )
        logger.info('Deleted vpn connection {}'.format(VpnConnectionId))
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
        logger.info('Deleted cgw connection {}'.format(cgwId))
        return True
    except Exception as e:
        logger.info('Got error {} deleting cgw'.format(e))
        return False


def lambda_handler(event, context):
    logger.info('Got event {}'.format(event))
    # Delete vgw connections
    fw1_vpnId = event.get('fw1_vpnId')
    fw2_vpnId = event.get('fw2_vpnId')
    fw1_sec_vpnId = event.get('fw1_sec_vpnId')
    fw2_sec_vpnId = event.get('fw2_sec_vpnId')
    fw1_cgwId = event.get('fw1_cgwId')
    fw2_cgwId = event.get('fw2_cgwId')
    fw1_sec_cgwId = event.get('fw1_sec_cgwId')
    fw2_sec_cgwId = event.get('fw2_sec_cgwId')
    if fw1_vpnId:
        if delete_vpn_connection(fw1_vpnId):
            release_ips(table_name, fw1_vpnId)
    if fw2_vpnId:
        if delete_vpn_connection(fw2_vpnId):
            release_ips(table_name, fw2_vpnId)

    if fw1_cgwId:
        if delete_cgw(fw1_cgwId):
            logger.info('Deleted cgw {}'.format(fw1_cgwId))
    if fw2_cgwId:
        if delete_cgw(fw2_cgwId):
            logger.info('Deleted cgw {}'.format(fw2_cgwId))

    if fw1_sec_vpnId:
        if delete_vpn_connection(fw1_sec_vpnId):
            release_ips(table_name, fw1_sec_vpnId)
    if fw2_sec_vpnId:
        if delete_vpn_connection(fw2_sec_vpnId):
            release_ips(table_name, fw2_sec_vpnId)

    if fw1_sec_cgwId:
        if delete_cgw(fw1_sec_cgwId):
            logger.info('Deleted cgw {}'.format(fw1_sec_cgwId))
    if fw2_sec_cgwId:
        if delete_cgw(fw2_sec_cgwId):
            logger.info('Deleted cgw {}'.format(fw2_sec_cgwId))
    return








