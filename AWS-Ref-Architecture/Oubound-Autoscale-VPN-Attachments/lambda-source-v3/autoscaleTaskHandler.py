import boto3
import sys, os
import json
import logging

import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ec2_client = boto3.client('ec2', )
Region = os.environ['Region']
init_fw_state_machine_arn = os.environ['InitFWStateMachine']

print('Loading function')


def start_state_function(state_machine_arn, data):
    logger.info('starting state machine with dict {}'.format(data))
    sfnConnection = boto3.client('stepfunctions')
    success_count = len(
        sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='SUCCEEDED')['executions'])
    running_count = len(
        sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='RUNNING')['executions'])

    logger.info('State machine running count is {} and success count is {}'.format(running_count, success_count))
    step_function_arns = []
    time.sleep(30)
    logger.info('Starting step function with input {}'.format(data))
    try:
        result = sfnConnection.start_execution(stateMachineArn=state_machine_arn, input=data)
    except execution as e:
        logger.info('Got exception {} starting step function'.format(e))
    logger.info('Got result from start execution '.format(result))
    logger.info('State maching ARN is {}'.format(result.get('executionArn')))
    step_function_arns.append(result.get('executionArn'))
    logger.info("Started StateMachine")
    time.sleep(30)
    success_count = len(
        sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='SUCCEEDED')['executions'])
    running_count = len(
        sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='RUNNING')['executions'])
    failed_count = len(
        sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='FAILED')['executions'])

    logger.info('State machine running count is {}, failed count is {} and success count is {}'
                .format(running_count, failed_count, success_count))
    if running_count == 0 and failed_count > 0:
        logger.info('Problems starting the step function')


def lambda_handler(event, context):
    logger.info("Got event: {}".format(event))
    data = event['Records'][0]['Sns']['Message']
    logger.info("Got message: {}".format(data))
    """
    {
        "LifecycleHookName": "vpn-outASG-life-cycle-launch",
        "AccountId": "106808901653",
        "RequestId": "b575b9fb-d658-c309-04ed-f4bd537d5305",
        "LifecycleTransition": "autoscaling:EC2_INSTANCE_LAUNCHING",
        "AutoScalingGroupName": "vpn-outASG",
        "Service": "AWS Auto Scaling",
        "Time": "2019-11-18T14:41:27.297Z",
        "EC2InstanceId": "i-07b0ca74b77725c69",
        "NotificationMetadata": "{\"MGMT\": \"subnet-0beddf8bb1c152657,subnet-0bbbdda8ce9e83870\", \"UNTRUST\": \"subnet-0fdc88a76d9fa7214,subnet-0056c067e24069d6a\", \"TRUST\": \"subnet-0e675eef937ef17af,subnet-09d69b4f6cd0751fe\", \"SGM\": \"sg-01ea99cbf258c3aee\", \"SGU\": \"sg-04e64feffff2df9a8\", \"SGT\": \"sg-0d905769014346510\", \"apikey\": \"LUFRPT1qS2xCRmZ6WVMrREtrK00yUGt4dVRna2lkY1U9cmgyaE93L3VoZ2U3WUgxeFpGVE1wOUNtdlM2S0Z5Z25ObG8wbmZoNXpuWT0\u003d\"}",
        "LifecycleActionToken": "57635768-ee89-41e1-9d13-bb61830a30ea"
    }
    """

    start_resp = start_state_function(init_fw_state_machine_arn, data)
    logger.info('Got respomse to start function {}'.format(start_resp))




