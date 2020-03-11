"""
/*****************************************************************************
 * Copyright (c) 2016, Palo Alto Networks. All rights reserved.              *
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
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info('Got event {}'.format(event))
    Region = os.environ['Region']
    asg = boto3.client('autoscaling', Region)
    # {
    #   "LifecycleHookName": "vpn-outASG-life-cycle-launch",
    #   "AccountId": "106808901653",
    #   "RequestId": "b135ba7d-a054-6060-8e0d-dc4e34042e68",
    #   "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
    #   "AutoScalingGroupName": "vpn-outASG",
    #   "Service": "AWS Auto Scaling",
    #   "Time": "2019-11-24T21:54:21.636Z",
    #   "EC2InstanceId": "i-0caf8366818c41bb9",
    #   "NotificationMetadata": "{\"MGMT\": \"subnet-0beddf8bb1c152657,subnet-0bbbdda8ce9e83870\", \"UNTRUST\": \"subnet-0fdc88a76d9fa7214,subnet-0056c067e24069d6a\", \"TRUST\": \"subnet-0e675eef937ef17af,subnet-09d69b4f6cd0751fe\", \"SGM\": \"sg-01ea99cbf258c3aee\", \"SGU\": \"sg-04e64feffff2df9a8\", \"SGT\": \"sg-0d905769014346510\", \"apikey\": \"LUFRPT1qS2xCRmZ6WVMrREtrK00yUGt4dVRna2lkY1U9cmgyaE93L3VoZ2U3WUgxeFpGVE1wOUNtdlM2S0Z5Z25ObG8wbmZoNXpuWT0=\"}",
    #   "LifecycleActionToken": "652b34ba-2981-4b5c-a6a7-f910721cda13",
    #   "Action": "manage_routes_success",
    #   "fwMgmtIP": "172.16.0.140",
    #   "lambda_bucket_name": "ireland-outbound-vpn",
    #   "event-name": "gw-launch",
    #   "fwUntrustPubIP": "34.253.54.211",
    #   "fwUntrustPrivIP": "172.16.1.190",
    #   "instance-id": "i-0caf8366818c41bb9",
    #   "asg_name": "vpn-outASG",
    #   "asg_hookname": "vpn-outASG-life-cycle-launch",
    #   "fwUntrustSubnet": "subnet-0fdc88a76d9fa7214",
    #   "fwMgmtSubnet": "subnet-0beddf8bb1c152657",
    #   "fw1_vpnId": "vpn-061e1efa130fb217e",
    #   "fw1_cgwId": "cgw-0099974c0abe54c75"
    # }
    result = "CONTINUE"
    a = event.get('AutoScalingGroupName')
    b = event.get('LifecycleHookName')
    c = event.get('LifecycleActionToken')
    logger.info('groupname {}'.format(a))
    logger.info('hookname {}'.format(b))
    logger.info('lifcycle {}'.format(c))

    try:
        res = asg.complete_lifecycle_action(
            AutoScalingGroupName=event.get('AutoScalingGroupName'),
            LifecycleHookName=event.get('LifecycleHookName'),
            LifecycleActionToken=event.get('LifecycleActionToken'),
            LifecycleActionResult=result)
        logger.info('Got result {}'.format(res))
    except Exception as e:
        logger.error("[complete_lifecycle_action]: {}".format(e))
        return False
    return True
