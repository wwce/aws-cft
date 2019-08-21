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
import json
import logging
import boto3
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')


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


def lambda_handler(event, context):
    logger.info('got event {} context {}'.format(event, context))
    # event = {
    #         'Action': 'config_aws_failed',
    #         'fw1_vpnId' : fw1_vpnId,
    #         'fw1_cgwId' : fw1_cgwId,
    #         'fw2_vpnId' : fw2_vpnId,
    #         'fw2_cgwId' : fw2_cgwId
    #         }

    if event.get('fw1_vpnId'):
        if delete_vpn_connection(event.get('fw1_vpnId')):
            logger.info('Deleted vpn connection {}'.format(event.get('fw1_vpnId')))
    if event.get('fw2_vpnId'):
        if delete_vpn_connection(event.get('fw2_vpnId')):
            logger.info('Deleted vpn connection {}'.format(event.get('fw2_vpnId')))

    return event



