"""
# /*****************************************************************************
# * Copyright (c) 2019, Palo Alto Networks. All rights reserved.              *
# *                                                                           *
# * This Software is the property of Palo Alto Networks. The Software and all *
# * accompanying documentation are copyrighted.                               *
# *****************************************************************************/
#
# Copyright 2019 Palo Alto Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Author: Justin Harris <jharris@paloaltonetworks.com>
"""


import boto3
import logging
import os
import cfnresponse
import ipaddress



logger = logging.getLogger()
logger.setLevel(logging.INFO)


def createBGPTunnelIpTable(tableName):
    """
    Updates BgpTunnelIpPool table with  attributes IpSegment, N1T1, N1T2, N2T1, N2T2 and Available=YES
    """
    try:
        dynamodb = boto3.resource('dynamodb')
        table=dynamodb.Table(tableName)
        exceptionList=['169.254.0.0/28', '169.254.1.0/28', '169.254.2.0/28', '169.254.3.0/28', '169.254.4.0/28', '169.254.5.0/28', '169.254.169.240/28']
        tunnelCidrRange = ipaddress.ip_network('169.254.0.0/16')
        count=0
        for subnet_28 in tunnelCidrRange.subnets(new_prefix=28):
            if count<20:
                if not str(subnet_28) in exceptionList:
                    range28 = [subnet_28]
                    for subnet_30 in subnet_28.subnets(new_prefix=30):
                        range28.append(subnet_30)
                    item={
                        'IpSegment': str(range28[0]),
                        'N1T1': str(range28[1]),
                        'N1T2': str(range28[2]),
                        'N2T1': str(range28[3]),
                        'N2T2': str(range28[4]),
                        'Available': 'YES'
                    }
                    table.put_item(Item=item)
                    count+=1
        print ("Updating {} with 20 entries Done, the last item is: 169.254.12.208/28".format(tableName))
        return 'Success'
    except Exception as e:
        print ("Updating {} is Failed, Error: {}".format(tableName,str(e)))
        return 'Failed'

def createDbtable_lambda_handler(event, context):
    """
    Creates the Dynamodb table used for VPN connection tracking and IP allocation
    :param event:
    :param context:
    :return:
    """
    table_name = os.environ['table_name']
    if event['RequestType'] == 'Create':
        response = createBGPTunnelIpTable(table_name)
        responseData = {}
        responseData['data'] = response
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        logger.info("Sending cfn success message ")
        return
    if event['RequestType'] == 'Delete':
        #TODO Add delete function
        responseData = {}
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        return
    if event['RequestType'] == 'Update':
        # TODO Add update function
        responseData = {}
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        return


if __name__ == '__main__':
    event = {'RequestType':'Create'}
    context = ''
    createDbtable_lambda_handler(event, context)