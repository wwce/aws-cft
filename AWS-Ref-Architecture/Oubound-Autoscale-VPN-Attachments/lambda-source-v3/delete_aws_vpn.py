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


def find_vpn_details(tablename, InstanceId):
    """
    When the Firewall is terminated we release the IP addresses from the IP pool and release them in the
    Dynamodb table.
    :param tablename:
    :param instanceId:
    :return:
    """
    strinstance = InstanceId
    table = dynamodb.Table(tablename)

    try:
        response = table.scan(FilterExpression=Attr('InstanceId').eq(strinstance))
        logger.info('Table scan response {}'.format(response))
        vpnId = response['Items'][0]['vpnId']
        cgwId = response['Items'][0]['cgwId']

        return vpnId, cgwId

    except Exception as e:
        logger.info('Got error {}'.format(e))
        return 'false'


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
    '''

    {
    "LifecycleHookName": "ireland-ouASG-life-cycle-terminate",
    "AccountId": "106808901653",
    "RequestId": "0666f3d7-ca4c-46db-bf5e-2ad00b8382ca",
    "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
    "AutoScalingGroupName": "ireland-ouASG",
    "Service": "AWS Auto Scaling",
    "Time": "2020-01-23T15:48:09.045Z",
    "EC2InstanceId": "i-0e8915f1db3b49041",
    "NotificationMetadata": "{\"MGMT\": \"subnet-011d5429b04fdfee1,subnet-03a6f2e9711510e51\", \"UNTRUST\": \"subnet-0bd4e9305a390a949,subnet-0805cc8f73eae576b\", \"TRUST\": \"subnet-081e022dea36f09c4,subnet-0b974e8aff9eecdbe\", \"SGM\": \"sg-0c0acf90d8d7e2681\", \"SGU\": \"sg-01cc400735fc3f214\", \"SGT\": \"sg-01b86eda4f224bc8f\", \"apikey\": \"LUFRPT1qS2xCRmZ6WVMrREtrK00yUGt4dVRna2lkY1U9cmgyaE93L3VoZ2U3WUgxeFpGVE1wOUNtdlM2S0Z5Z25ObG8wbmZoNXpuWT0=\"}",
    "LifecycleActionToken": "56ca26d6-0ee8-4d8c-b557-ecb8a092b7e7",
    "Action": "destroy_vpn"
    }

    '''
    InstanceId = event['EC2InstanceId']
    logger.info('Got event {}'.format(event))
    # Delete vgw connections
    fw1_vpnId, fw1_cgwId = find_vpn_details(table_name, InstanceId)
    if fw1_vpnId and fw1_cgwId:

        if delete_vpn_connection(fw1_vpnId):
            release_ips(table_name, fw1_vpnId)
            delete_cgw(fw1_cgwId)
            logger.info('Deleted cgw {}'.format(fw1_cgwId))

    if event.get('Autoscale_Action') == 'create':
        logger.info('Setting config_fw_success')
        data = {
            'Action': 'cfn_fail'
        }
    else:
        data = {
            'Action': 'cfn_success'
        }
    event.update(data)
    return event









