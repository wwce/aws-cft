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
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    The entry point when this lambda function gets
    invoked.

    .. note:: The primary objective of this lambda funciton
              is to handle life-cycle hooks and to create / delete
              elastic network interfaces to assign / disassociate to / from
              instances.

    :param event: Encodes all the input variables to the lambda function, when
                      the function is invoked.
                      Essentially AWS Lambda uses this parameter to pass in event
                      data to the handler function.
    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :return: None

    {
        "LifecycleHookName": "ireland-ouASG-life-cycle-launch",
        "AccountId": "106808901653",
        "RequestId": "c255bf2a-0a49-7dc4-f416-8c3868e29c63",
        "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
        "AutoScalingGroupName": "ireland-ouASG",
        "Service": "AWS Auto Scaling",
        "Time": "2020-01-21T23:49:45.178Z",
        "EC2InstanceId": "i-0181e2c6d9a576231",
        "NotificationMetadata": "{\"MGMT\": \"subnet-011d5429b04fdfee1,subnet-03a6f2e9711510e51\", \"UNTRUST\": \"subnet-0bd4e9305a390a949,subnet-0805cc8f73eae576b\", \"TRUST\": \"subnet-081e022dea36f09c4,subnet-0b974e8aff9eecdbe\", \"SGM\": \"sg-0c0acf90d8d7e2681\", \"SGU\": \"sg-01cc400735fc3f214\", \"SGT\": \"sg-01b86eda4f224bc8f\", \"apikey\": \"LUFRPT1qS2xCRmZ6WVMrREtrK00yUGt4dVRna2lkY1U9cmgyaE93L3VoZ2U3WUgxeFpGVE1wOUNtdlM2S0Z5Z25ObG8wbmZoNXpuWT0=\"}",
        "LifecycleActionToken": "71ad4ebc-6d40-4214-b914-6b2276281234"
    }
    """

    event_type = ""
    logger.info('Got event {}'.format(event))
    # message = event['Records'][0]['Sns']['Message']
    # Retrieve event from SNS
    if 'LifecycleHookName' in event:
        message = (event)
        logger.info("Got message: {}".format(message))
        if 'LifecycleTransition' in message:
            if message.get('LifecycleTransition') == "autoscaling:EC2_INSTANCE_LAUNCHING":
                logger.info("Lifecyclehook Launching\n")
                event_type = 'launch'
            elif message.get('LifecycleTransition') == "autoscaling:EC2_INSTANCE_TERMINATING":
                logger.info("Lifecyclehook Terminating\n")
                event_type = 'terminate'
            else:
                logger.info("One of the other lifeycycle transition messages received\n")
                event_type = 'other'
        elif 'Event' in message:
            if message.get('Event') == "autoscaling:TEST_NOTIFICATION":
                logger.info("GOT TEST NOTIFICATION. Do nothing")

            elif message.get('Event') == "autoscaling:EC2_INSTANCE_LAUNCH":
                logger.info("GOT launch notification...will get launching event from lifecyclehook")
                # logger.info("[EVENT]: {}".format(event))

            elif message.get('Event') == "autoscaling:EC2_INSTANCE_TERMINATE":
                logger.info("GOT terminate notification....will get terminating event from lifecyclehook")

            elif message.get('Event') == "autoscaling:EC2_INSTANCE_TERMINATE_ERROR":
                logger.info("GOT a GW terminate error...raise exception for now")

            elif message.get('Event') == "autoscaling:EC2_INSTANCE_LAUNCH_ERROR":
                logger.info("GOT a GW launch error...raise exception for now")

    else:
        logger.info("[ERROR]: Something else entirely")
        raise Exception("[ERROR]: Something else entirely")

    logger.info('Message that we are parsing is {}'.format(message))

    lifecycle_hook_name = message['LifecycleHookName']
    asg_name = message['AutoScalingGroupName']
    ec2_instanceid = message['EC2InstanceId']
    logger.info('ec2_instanceid: ' + ec2_instanceid)

    logger.setLevel(logging.INFO)

    if event_type == 'terminate':
        logger.info('PANW EC2 Firewall Instance is terminating')
        parameters = {
            'Action': 'destroy_vpn',
            'Autoscale_Action': 'destroy'
        }

    if event_type == 'launch':
        logger.info('PANW EC2 Firewall Instance is launching')

        logger.info('LifecycleHookName: ' + message['LifecycleHookName'])

        logger.info("metadata type is {}".format(type(message['NotificationMetadata'])))

        parameters = {
            'Action': 'create_vpn',
            'Autoscale_Action': 'create'
        }

    logger.info('Updated parameters dict is {}'.format(parameters))
    event.update(parameters)
    logger.info('Updated event is {}'.format(event))
    return event

