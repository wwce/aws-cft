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
import ssl
import logging
import urllib
import os
import boto3
from botocore.exceptions import ClientError
import urllib3
from boto3.dynamodb.conditions import Attr
import time

import netaddr

api_key = os.environ['apikey']
Region = os.environ['Region']
export_rule = 'send_vpc_summary'
fw1 = os.environ['fw1MgmtIp']
fw2 = os.environ['fw2MgmtIp']
tgw_route_table_id = os.environ['tgwAssociationRt']

urllib3.disable_warnings()

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')


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


def panCommit(hostname, api_key, message=""):
    """Function to commit configuration changes
    """
    data = {
        "type": "commit",
        "key": api_key,
        "cmd": "<commit>{0}</commit>".format(message)
    }
    return make_api_call(hostname, data)


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


def update_as_path(hostname, export_rule, api_key, prepend_length, virtualRouter='default'):
    """
    Function to edit/update AS Path length in export rule
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/" \
            "virtual-router/entry[@name='{0}']/protocol/bgp/policy/export/" \
            "rules/entry[@name='{1}']/action/allow/update/as-path".format(virtualRouter, export_rule)

    element = "<prepend>{0}</prepend>".format(prepend_length)
    return pan_set_config(hostname, api_key, xpath, element)


def get_vpn_connections():
    vpn_ids = []
    attachments = ec2_client.describe_transit_gateway_attachments(Filters=
                                                                  [{'Name': 'resource-type', 'Values': ['vpn']},
                                                                   {'Name': 'state',
                                                                    'Values': ['available', 'pending']}])
    attachment_list = attachments.get('TransitGatewayAttachments')
    if len(attachment_list) > 0:
        for vpn_attachment in attachment_list:
            if vpn_attachment.get('ResourceId'):
                vpn_ids.append(vpn_attachment)
        return vpn_ids
    else:
        logger.info('Found no vpn attachments to delete')
        return vpn_ids


def create_vpn_association(attachment_id, tgw_route_table_id):
    try:
        logger.info(
            'Creating association of attachmentid {} and route_table_id {}'.format(attachment_id, tgw_route_table_id))
        response = ec2_client.associate_transit_gateway_route_table(
            TransitGatewayRouteTableId=tgw_route_table_id,
            TransitGatewayAttachmentId=attachment_id,
            DryRun=False
        )
        return True
    except Exception as e:
        logger.info('Got vpn association error {}'.format(e))
        return False


def create_vpn_propagation(attachment_id, tgw_route_table_id):
    try:
        logger.info(
            'Creating propagation of attachmentid {} and route_table_id {}'.format(attachment_id, tgw_route_table_id))
        response1 = ec2_client.enable_transit_gateway_route_table_propagation(
            TransitGatewayRouteTableId=tgw_route_table_id,
            TransitGatewayAttachmentId=attachment_id,
            DryRun=False
        )
        return True
    except Exception as e:
        logger.info('Got vpn propagation error {}'.format(e))
        return False

def get_attachment_state(attachment):
    attachment_data =  ec2_client.describe_transit_gateway_attachments(TransitGatewayAttachmentIds = [attachment.get('TransitGatewayAttachmentId')])
    attachment_state = attachment_data['TransitGatewayAttachments'][0]['State']
    return attachment_state


def lambda_handler(event, context):
    primary_prepend_length = '1'
    secondary_prepend_length = '2'
    # update_as_path(fw1, export_rule, api_key, primary_prepend_length)
    # panCommit(fw1, api_key, message="")
    # update_as_path(fw2, export_rule, api_key, secondary_prepend_length)
    # panCommit(fw2, api_key, message="")

    tgws = []
    table_list = ec2_client.describe_transit_gateway_route_tables(Filters=[
        {'Name': 'tag:Propagate', 'Values': ['EW']}
    ])
    tables = table_list.get('TransitGatewayRouteTables')

    for table in tables:
        tgws.append(table.get('TransitGatewayRouteTableId'))

    logger.info('These tables are tagged for East West Route Propagation {}'.format(tgws))
    #
    #
    attachments = get_vpn_connections()
    for attachment in attachments:
        while True:
            logger.info('Processing Attachment {}'.format(attachment))
            attachment_state = get_attachment_state(attachment)
            if attachment_state == 'available' and not attachment.get('Association'):
                logger.info('Setting propagation for attachment {}'.format(attachment.get('TransitGatewayAttachmentId')))
                [create_vpn_propagation(attachment.get('TransitGatewayAttachmentId'), tgwrt) for tgwrt in tgws]
                res = create_vpn_association(attachment.get('TransitGatewayAttachmentId'), tgw_route_table_id)
                break

            elif attachment_state == 'available' and attachment.get('Association'):
                logger.info('Attachment {} is already association with route table'.format(
                        attachment.get('TransitGatewayAttachmentId')))
                break
            elif attachment_state == 'pending':
                logger.info('Waiting for attachment to come up')
                time.sleep(20)
            else:
                logger.info('Attachment is in an unknown state - moving on')
                break
        logger.info('Finished Processing Attachment {}'.format(attachment.get('TransitGatewayAttachmentId')))

if __name__ == '__main__':
    event = {}
    context = ()
    lambda_handler(event, context)



