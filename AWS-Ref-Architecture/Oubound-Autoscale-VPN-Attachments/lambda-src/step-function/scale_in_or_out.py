import json
import logging


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
    """

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    event_type = ""
    logger.info('Got event {}'.format(event))

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
            'Action': 'destroy_vpn'
        }

    if event_type == 'launch':
        logger.info('PANW EC2 Firewall Instance is launching')

        logger.info('LifecycleHookName: ' + message['LifecycleHookName'])

        logger.info("metadata type is {}".format(type(message['NotificationMetadata'])))

        parameters = {
            'Action': 'create_vpn'
        }

    logger.info('Updated parameters dict is {}'.format(parameters))
    event.update(parameters)
    logger.info('Updated event is {}'.format(event))
    return event