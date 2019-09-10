"""
Paloaltonetworks TransitGatewayInitialiseLambda.py

Script triggered from a custom resource.  The script performs two funcitons

1) The script will create route table entries in each VPC that use next hop of the
transit gateway attachment.  We use this script today as next hop TransitGatewayId is not supported in CFT yet
When CFT use the updated boto3 libraries we can remove this function and place the route entries using CFT.

2) The script will start a step function that will complete the configuration of the Paloaltonetworks firewalls
Two post deployment tasks are performed by the InitialiseFwlambda.py script associated with the step function

This software is provided without support, warranty, or guarantee.
Use at your own risk.

jharris@paloaltonetworks.com
"""

import logging
import os
import boto3
import cfnresponse
import sys
import time



Region = os.environ['Region']
ec2_client = boto3.client('ec2', )

logger = logging.getLogger()
logger.setLevel(logging.INFO)

defroutecidr = '0.0.0.0/0'



def add_route_tgw_nh(route_table_id, destination_cidr_block, transit_gateway_id):
    """
    Adds a route to a VPC route table with next hop of the TransitGatewayId
    :param route_table_id:
    :param destination_cidr_block:
    :param transit_gateway_id:
    :return:
    """


    resp = ec2_client.create_route(
        DryRun=False,
        RouteTableId=route_table_id,
        DestinationCidrBlock=destination_cidr_block,
        TransitGatewayId=transit_gateway_id,
    )
    logger.info("Got response to add_route_tgw_nh {} ".format(resp))
    return resp

def delete_route(route_table_id, destination_cidr_block):
    """
    Deletes a route from the VPC route table
    :param route_table_id:
    :param destination_cidr_block:
    :return:
    """

    resp = ec2_client.delete_route(
        DestinationCidrBlock=destination_cidr_block,
        RouteTableId=route_table_id,
    )
    logger.info("Got response to delete_route {} ".format(resp))
    return resp


def start_state_function(state_machine_arn):
    sfnConnection = boto3.client('stepfunctions')
    success_count = len(
        sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='SUCCEEDED')['executions'])
    running_count = len(
        sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='RUNNING')['executions'])

    logger.info('State machine running count is {} and success count is {}'.format(running_count, success_count))
    step_function_arns = []
    time.sleep(30)
    result = sfnConnection.start_execution(stateMachineArn=state_machine_arn)
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




def get_vpn_connections():

    vpn_ids = []
    attachments = ec2_client.describe_transit_gateway_attachments(Filters=[{'Name': 'resource-type', 'Values': ['vpn']}])
    attachment_list = attachments.get('TransitGatewayAttachments')
    if len(attachment_list) > 0:
        for vpn_attachment in attachment_list:
            if vpn_attachment.get('ResourceId'):
                vpn_ids.append(vpn_attachment.get('ResourceId'))
        return vpn_ids
    else:
        logger.info('Found no vpn attachments to delete')
        return False

def delete_vpn_connection(VpnConnectionId, DryRun=False):
    try:
        response = ec2_client.delete_vpn_connection(
            VpnConnectionId=VpnConnectionId,
            DryRun=DryRun
        )
        return True
    except Exception as e:
        logger.info('Got error {} deleting vpn connection'.format(e))
        return False

def lambda_handler(event, context):
    """
    Each VPC (including the security VPC) requires a static route directing traffic with a next hop of the
    TransitGatewayId.   In this case we take to route table id and  TransitGatewayId via environment variables from
    the CFT template.
    :param event:
    :param context:
    :return:
    """
    logger.info("Got event {} ".format(event))
    toTGWRouteTable = os.environ['toTGWRouteTableId']
    VPC0_route_table_id = os.environ['vpc0HostRouteTableid']
    VPC1_route_table_id = os.environ['vpc1HostRouteTableid']
    transit_gateway_id = os.environ['transitGatewayid']
    init_fw_state_machine_arn = os.environ['InitFWStateMachine']
    vnetroutecidr = os.environ['VpcCidrBlock']
    vpc_summary_route = os.environ['VpcSummaryRoute']

    responseData = {}
    responseData['data'] = 'Success'
    if event['RequestType'] == 'Create':
        if VPC0_route_table_id != 'Null':
            resp = add_route_tgw_nh(VPC0_route_table_id, defroutecidr, transit_gateway_id)
            logger.info("Got response to route update on VPC0 {} ".format(resp))
        if VPC0_route_table_id != 'Null':
            resp1 = add_route_tgw_nh(VPC1_route_table_id, defroutecidr, transit_gateway_id)
            logger.info("Got response to route update on VPC1 {} ".format(resp1))

        res2 = add_route_tgw_nh(toTGWRouteTable, vpc_summary_route, transit_gateway_id)
        logger.info("Got response to route update on SecVPC {} ".format(res2))

        start_resp = start_state_function(init_fw_state_machine_arn)
        logger.info("Calling start state function {} ".format(start_resp))
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        logger.info("Sending cfn success message ")

    elif event['RequestType'] == 'Update':
        print("Update something")
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")

    elif event['RequestType'] == 'Delete':
        print("Got Delete event")
        pass

        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")


