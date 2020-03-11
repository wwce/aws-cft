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
SUCCESS = "CONTINUE"
FAILED = "ABANDON"


def lambda_handler(event, context):
    Region = os.environ['Region']
    asg = boto3.client('autoscaling','Region')

    asg_message=event
    result = FAILED
    try:
        asg.complete_lifecycle_action(
            AutoScalingGroupName=asg_message['AutoScalingGroupName'],
            LifecycleHookName=asg_message['LifecycleHookName'],
            LifecycleActionToken=asg_message['LifecycleActionToken'],
            LifecycleActionResult=result)
            
    except Exception as e:
        logger.error("[complete_lifecycle_action]: {}".format(e))
        return False
    logger.info('Send lifecycle action message {}'.format(re))
    return True