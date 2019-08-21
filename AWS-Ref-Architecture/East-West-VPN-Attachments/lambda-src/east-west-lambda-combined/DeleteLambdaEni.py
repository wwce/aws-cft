import boto3
import cfnresponse
import sys
import logging
from botocore.exceptions import ClientError
from time import sleep

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Fix this wherever your custom resource handler code is
# from common import cfn_custom_resources as csr


MAX_RETRIES = 5

ec2_client = boto3.client('ec2')
responseData = {}

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

def handler(event, context):
    global ec2_client

    vpc_id = event['ResourceProperties']['VPCID']
    region = event['ResourceProperties']['region']
    ec2_client = boto3.client('ec2', region_name=region)
    logger.info("Got event {}".format(event))

    if event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
        result = {'result': 'Don\'t trigger the rest of the code'}
        responseData = result
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        # csr.send(event, context, csr.SUCCESS, csr.validate_response_data(result))
        return
    try:
        # Get all network interfaces for given vpc which are attached to a lambda function
        interfaces = ec2_client.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'description',
                    'Values': ['AWS Lambda VPC ENI*']
                },
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                },
            ],
        )
        logger.info("Found these interface {}".format(interfaces))
        failed_detach = list()
        failed_delete = list()

        # Detach the above found network interfaces
        for interface in interfaces['NetworkInterfaces']:
            logger.info("Detaching interface {} from {}".format(interface, interfaces))
            detach_interface(failed_detach, interface)

        sleep(20)

        # Try detach a second time and delete each simultaneously
        for interface in interfaces['NetworkInterfaces']:
            logger.info("20secs later 2nd try detaching interface {} from {}".format(interface, interfaces))
            detach_and_delete_interface(failed_detach, failed_delete, interface)
            logger.info("Got exception detaching interface {} from {}".format(interface, interfaces))

        # Clean up VPN connections
        vpns = get_vpn_connections()
        if len(vpns) > 0:
            for vpn in vpns:
                delete_vpn_connection(vpn)

        if not failed_detach or not failed_delete:
            result = {'result': 'Network interfaces detached and deleted successfully'}
            responseData = result
            cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
            # csr.send(event, context, csr.SUCCESS, csr.validate_response_data(result))

        else:
            result = {'result': 'Network interfaces couldn\'t be deleted completely'}
            responseData = result
            cfnresponse.send(event, context, cfnresponse.FAILED, responseData, "CustomResourcePhysicalID")
            # csr.send(event, context, csr.FAILED, csr.validate_response_data(result))
            # print(response)



    except Exception:
        print("Unexpected error:", sys.exc_info())
        result = {'result': 'Some error with the process of detaching and deleting the network interfaces'}
        responseData = result
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData, "CustomResourcePhysicalID")
        # csr.send(event, context, csr.FAILED, csr.validate_response_data(result))


def detach_interface(failed_detach, interface):
    try:

        if interface['Status'] == 'in-use':
            logger.info('Interface {} is "in-use": detaching'.format(interface))
            detach_response = ec2_client.detach_network_interface(
                AttachmentId=interface['Attachment']['AttachmentId'],
                Force=True
            )
            logger.info('Got response for Interface'.format(detach_response))
            # Sleep for 30 sec after every detachment
            sleep(30)
            logger.info("Sleeping 30 secs")

            if 'HTTPStatusCode' not in detach_response['ResponseMetadata'] or \
                    detach_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                failed_detach.append(detach_response)

    except ClientError as e:
        logger.info("Got exception {}".format(e))


def detach_and_delete_interface(failed_detach, failed_delete, interface, retries=0):
    detach_interface(failed_detach, interface)

    sleep(30)
    logger.info("Sleeping 30 secs")

    try:
        delete_response = ec2_client.delete_network_interface(
            NetworkInterfaceId=interface['NetworkInterfaceId'])
        logger.info('Delete response interface {} is {}'.format(interface['NetworkInterfaceId'], delete_response))

        if 'HTTPStatusCode' not in delete_response['ResponseMetadata'] or \
                delete_response['ResponseMetadata']['HTTPStatusCode'] != 200:
            failed_delete.append(delete_response)
    except ClientError as e:
        logger.info("Got exception {}".format(e))

        if retries <= MAX_RETRIES:
            if e.response['Error']['Code'] == 'InvalidNetworkInterface.InUse' or \
                    e.response['Error']['Code'] == 'InvalidParameterValue':
                retries = retries + 1
                logger.info("Check delete response {}".format(e.response))
                detach_and_delete_interface(failed_detach, failed_delete, interface, retries)
            else:
                logger.info('Raising runtime error')
                raise RuntimeError("Code not found in error")
        else:
            raise RuntimeError("Max Number of retries exhausted to remove the interface")