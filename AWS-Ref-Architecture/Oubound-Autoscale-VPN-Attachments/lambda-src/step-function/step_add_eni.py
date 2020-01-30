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
"""

from __future__ import print_function

import json
import logging
import os
import ssl
import requests
import urllib
import urllib3

import boto3
import time
import xml
import xml.etree.ElementTree as ET
from botocore.exceptions import ClientError


Namespace = ""
asg_name = ""


debug = ""

asg = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')
ec2_client = ec2.meta.client
lambda_client = boto3.client('lambda')
iam = boto3.client('iam')
events_client = boto3.client('events')
cloudwatch = boto3.client('cloudwatch')

valid_panfw_productcode_byol = {
    "6njl1pau431dv1qxipg63mvah": "VMLIC_BYOL",
    # AWS IC product codes
    "3bgub3avj7bew2l8odml3cxdx": "VMLIC_IC_BYOL",
}

urllib3.disable_warnings()

class FWNotUpException(Exception):
    pass

def remove_eni_in_subnet(subnet):
    """

    :param subnet:
    :return:
    """
    response = ec2_client.describe_network_interfaces(Filters=[{'Name': "subnet-id", 'Values': [str(subnet)]}])
    for i in response['NetworkInterfaces']:
        if i['Status'] == "available":
            logger.info('Removing Network Interfaces in Available state for subnetid : ' + subnet)
            eni_id = i['NetworkInterfaceId']
            logger.info(
                'Removing Eni ID: ' + eni_id + ' Desc: ' + i['Description'] + ' IP: ' + i[
                    'PrivateIpAddress'] + ' AZ: ' +
                i['AvailabilityZone'])
            try:
                ec2_client.delete_network_interface(NetworkInterfaceId=eni_id)
            except ClientError as e:
                logger.warning("[delete Eni for subnet]: {}".format(e))

    return


def remove_secondary_eni(message):
    """
    :param message:
    :return:
    """
    logger.info('Passed message {} to remove_secondary_eni'.format(message))
    # FIXME check the message format
    ec2_instanceid = message['EC2InstanceId']
    logger.info('Removing Network Interfaces for ec2_instanceid: ' + ec2_instanceid)

    # Detach all the ENIs first
    response = ec2_client.describe_network_interfaces(
        Filters=[{'Name': "attachment.instance-id", 'Values': [str(ec2_instanceid)]}])
    cnt = 0
    eni_ids = []
    for i in response['NetworkInterfaces']:
        eni_id = i['NetworkInterfaceId']
        attachment_data = i['Attachment']
        attachment_id = attachment_data['AttachmentId']
        #
        # Removing all Nics other than primary Nic created by ASG
        #
        if attachment_data['DeviceIndex'] != 0:
            try:
                logger.info(
                    'Detaching Eni ID:{} Desc:{} IP:{} AZ:{}'.format(eni_id, i['Description'], i['PrivateIpAddress'],
                                                                     i['AvailabilityZone']))
                logger.info('Detaching Attachment ID:{} DeviceIndex:{}'.format(attachment_id,
                                                                               str(attachment_data['DeviceIndex'])))
                detachresponse = ec2_client.detach_network_interface(AttachmentId=attachment_id)
                logger.info('Got response {} \nDetaching eni {}'.format(detachresponse, attachment_id))
                cnt = cnt + 1
                eni_ids.append(str(eni_id))
            except ClientError as e:
                logger.info("Detach Eni error: {}".format(e))
            try:
                delresponse = ec2_client.delete_network_interface(NetworkInterfaceId=eni_id)
                logger.info("Delete Eni response: {}".format(delresponse))
            except ClientError as e:
                logger.info("Delete Eni errror: {}".format(e))

    if cnt == 0:
        logger.warning('No more ENIs for delete.')
        return

    logger.info('Delete ENIs PANW ec2_instanceid: ' + str(ec2_instanceid) + ' ENI cnt: ' + str(cnt))
    logger.info('Delete ENIs: ' + str(eni_ids))

    # Now delete ENIs if they are in 'available' state
    fcnt = 0
    for timeout in range(0, 25):
        if fcnt == cnt:
            logger.info('Finally Done with deleting all ENIs')
            return
        try:
            response = ec2_client.describe_network_interfaces(
                NetworkInterfaceIds=eni_ids,
                Filters=[{'Name': 'status', 'Values': ['available']}])
            logger.info('response describe ints{}'.format(response))

            for i in response['NetworkInterfaces']:
                available_eni_id = i['NetworkInterfaceId']
                fcnt = fcnt + 1
                logger.info('deleting eni {} in list item {}'.format(available_eni_id, i))

                ec2_client.delete_network_interface(NetworkInterfaceId=available_eni_id)

        except ClientError as e:
            logger.info('Could not find available eni {}'.format(e))

        time.sleep(15)

    response = ec2_client.describe_network_interfaces(NetworkInterfaceIds=eni_ids)
    for i in response['NetworkInterfaces']:
        logger.error('Timed out waiting for detach ENI. Final cnt: ' + str(fcnt) + ' vs ' + str(cnt))
        logger.error(i)

    logger.error('Return from remove_secondary_eni due to detach issue')
    return


def count_eni(msg, ec2_instanceid):
    """

    :param msg:
    :param ec2_instanceid:
    :return:
    """
    response = ec2_client.describe_network_interfaces(
        Filters=[{'Name': "attachment.instance-id", 'Values': [str(ec2_instanceid)]}])
    # logger.info(response)
    cnt = 0
    for i in response['NetworkInterfaces']:
        cnt = cnt + 1
    logger.info(msg + ' PANW ec2_instanceid: ' + str(ec2_instanceid) + ' ENI cnt: ' + str(cnt))
    return cnt


def associate_address(allocation_id, eni_id):
    """

    :param allocation_id:
    :param eni_id:
    :return bool:
    """
    logger.info('EIP Associate AllocId: ' + str(allocation_id) + ' ENI Id: ' + str(eni_id))
    try:
        ec2_client.associate_address(AllocationId=allocation_id, NetworkInterfaceId=eni_id)
    except ClientError as e:
        logger.error("[associate_address failed]: {}".format(e))
        return False
    else:
        logger.info("Associated EIP")
        return True


def get_unassociated_eip(eip_list):
    """

    :param eip_list:
    :return:
    """
    logger.info("Trying to find and eip that is not associated")
    logger.info(eip_list)
    for eip_iter in eip_list:
        # is the public ip address associated with an instance id, if so don't use it
        logger.info('eip_iter is as follows:')
        logger.info(eip_iter)
        if "ec2_instanceid" not in eip_iter:
            if "AssociationId" not in eip_iter:
                address = eip_iter['PublicIp']
                if address:
                    return eip_iter
    return None


def get_ssl_context():
    """
    Create default ssl context
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options = ssl.PROTOCOL_TLSv1_2
    return ctx

def get_device_serial_no(instanceId, gwMgmtIp, fwApiKey):
    """
    Retrieve the serial number from the FW.

    :param gcontext: ssl context
    :param instanceId: instance Id
    :param gwMgmtIP: The IP address of the FW
    :param fwApiKey: Api key of the FW

    :return: The serial number of the FW
    :rtype: str
    """

    serial_no = None
    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return None

    logger.info('Retrieve the serial number from FW {} with IP: {}'.format(instanceId, gwMgmtIp))
    fw_cmd='<show><system><info/></system></show>'
    try:
        response = pan_op_cmd(gwMgmtIp, fwApiKey, fw_cmd)
        # response = runCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response is None:
            print('CFG_FW_GET_SERIAL_NO: Failed to run command: ' + fw_cmd)
            return None
    except Exception as e:
        print("[CFG_FW_GET_SERIAL_NO]: {}".format(e))
        return None

    resp = ET.fromstring(response)
    serial_info = resp.findall(".//serial")
    for info in serial_info:
        serial_no = info.text

    if not serial_no:
        logger.error("Unable to retrieve the serial number from device: {} with IP: {}".format(instanceId, gwMgmtIp))

    return serial_no

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
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')
    return urllib.request.urlopen(url, data=encoded_data, context=ctx).read()

def pan_op_cmd(hostname, api_key, cmd):
    """Function to make an 'op' call to execute a command
    """
    data = {
        "type": "op",
        "key": api_key,
        "cmd": cmd
    }
    return make_api_call(hostname, data)



def deactivate_fw_license(instanceId, gwMgmtIp, fwApiKey):
    """
    Call the FW to deactivate the license from the licensing
    server

    :param gcontext: ssl context
    :param instanceId: instance Id
    :param gwMgmtIP: The IP address of the FW
    :param fwApiKey: Api key of the FW

    :return: Api call status
    :rtype: bool
    """

    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return False

    logger.info('Deactivate and the license for FW: {} with IP: {}'.format(instanceId, gwMgmtIp))

    fw_cmd = "<request><license><deactivate><VM-Capacity><mode>auto</mode></VM-Capacity></deactivate></license></request>".format(
        gwMgmtIp, fwApiKey)
    try:
        response = pan_op_cmd(gwMgmtIp, fwApiKey, fw_cmd)
        # response = runCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response is None:
            print('CFG_FW_DELICENSE: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
        print("[CFG_FW_DELICENSE]: {}".format(e))
        return False

    return True

def send_request(call):
    """
    Handles sending requests to API
    :param call: url
    :return: Retruns result of call. Will return response for codes between 200 and 400.
             If 200 response code is required check value in response
    """
    headers = {'Accept-Encoding': 'None',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

    try:
        r = requests.get(call, headers=headers, verify=False, timeout=5)
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        '''
        Firewall may return 5xx error when rebooting.  Need to handle a 5xx response 
        '''
        logger.debug("DeployRequestException Http Error:")
        raise FWNotUpException("Http Error:")
    except requests.exceptions.ConnectionError as errc:
        logger.debug("DeployRequestException Connection Error:")
        raise FWNotUpException("Connection Error")
    except requests.exceptions.Timeout as errt:
        logger.debug("DeployRequestException Timeout Error:")
        raise FWNotUpException("Timeout Error")
    except requests.exceptions.RequestException as err:
        logger.debug("DeployRequestException RequestException Error:")
        raise FWNotUpException("Request Error")
    else:
        return r


def getApiKey(hostname, username, password):
    """
    Generate the API key from username / password
    """

    call = "https://%s/api/?type=keygen&user=%s&password=%s" % (hostname, username, password)
    api_key = ""
    while True:
        try:
            # response = urllib.request.urlopen(url, data=encoded_data, context=ctx).read()
            response = send_request(call)

        except FWNotUpException as updateerr:
            logger.info("No response from FW. Wait 30 secs before retry")
            time.sleep(30)
            # raise FWNotUpException("Timeout Error")
            continue

        else:
            api_key = ET.XML(response.content)[0][0].text
            logger.info("FW Management plane is Responding so checking if Dataplane is ready")
            logger.debug("Response to get_api is {}".format(response))
            return api_key


def handle_license(instanceId, fwMgmtIp, fwApiKey):
    serial_no = get_device_serial_no(instanceId, fwMgmtIp, fwApiKey)
    if not serial_no:
        logger.error('Unable to retrieve the serial no for device with IP: {}'.format(fwMgmtIp))
        return False

    logger.info('The serial number retrieved from device with IP: {} is {}'.format(fwMgmtIp, serial_no))

    try:
        instance_info = ec2_client.describe_instance_attribute(
            Attribute='productCodes',
            InstanceId=instanceId,
        )
    except Exception as e:
        logger.info("Exception occured while retrieving instance ID information: {}".format(e))

    logger.info('describe_instance_attribute:response: {}'.format(instance_info))
    valid_byol = False
    for code in instance_info['ProductCodes']:
        product_code_id = code.get("ProductCodeId", None)
        if product_code_id in valid_panfw_productcode_byol.keys():
            valid_byol = True
            break

    if valid_byol:
        for retry in range(1, 10):
            logger.info('Identified the fw license as BYOL. The fw will be de-licensed now.')
            try:
                ## TODO
                ret = deactivate_fw_license(instanceId, fwMgmtIp, fwApiKey)
                # ret = deactivate_fw_license_panorama(PIP, KeyPANWPanorama, serial_no)
            except Exception as e:
                logger.exception(
                    "Exception occurred during deactivate license for device: {} with IP: {}. Error:  {}".format(
                        instanceId, fwMgmtIp, e))
                break
            else:
                if not ret:
                    logger.error(
                        'Failed to deactivate the license for device: {} with IP: {}'.format(instanceId, fwMgmtIp))
                else:
                    logger.info(
                        'Successfully deactivated license for device: {} with IP: {}'.format(instanceId, fwMgmtIp))
                    break
                time.sleep(30)
    else:
        logger.info("This firewall device does not have a BYOL license.")

    logger.info('Termination sequence completed.')
    return True



def check_belongsto_az(list_subnet, az):
    """
    :param list_subnet
    :param az
    :return: chosensubnet/None
    """
    list_len = len(list_subnet)
    for i in range(list_len):
        response = ec2_client.describe_subnets(SubnetIds=[list_subnet[i]])
        logger.info('Retrived response for subnet data{}'.format(response))
        for r in response['Subnets']:
            subnetaz = r['AvailabilityZone']
            if subnetaz == az:
                chosensubnet = r['SubnetId']
                logger.info ("Found the required subnet for this instance :" +chosensubnet)
                return chosensubnet
    return None


def lifecycle_hook_abandon(asg_message):
    """
    Method to send a response to the
    auto scale life cycle action.

    :param asg_message:
    :return:
    """
    result = "ABANDON"

    # call autoscaling
    try:
        asg.complete_lifecycle_action(
            AutoScalingGroupName=asg_message['AutoScalingGroupName'],
            LifecycleHookName=asg_message['LifecycleHookName'],
            LifecycleActionToken=asg_message['LifecycleActionToken'],
            LifecycleActionResult=result)
    except Exception as e:
        logger.error("[complete_lifecycle_action]: {}".format(e))


def lifecycle_hook_success(asg_message):
    """
    Method to send a successful response to an
    ASG lifecycle action.

    :param asg_message:
    :return:
    """
    result = "CONTINUE"

    # call autoscaling
    try:
        asg.complete_lifecycle_action(
            AutoScalingGroupName=asg_message['AutoScalingGroupName'],
            LifecycleHookName=asg_message['LifecycleHookName'],
            LifecycleActionToken=asg_message['LifecycleActionToken'],
            LifecycleActionResult=result)
    except Exception as e:
        logger.error("[complete_lifecycle_action]: {}".format(e))
        return False

    return True


# Create a network interface, pass the Interface ID to callback
def create_eni(subnetid, security_groups, index):
    """
    Method to create and Elastic Network Interface
    :param subnetid:
    :param security_groups:
    :param index:
    :return:
    """
    # global nif
    # global eniId

    desc = asg_name + '-eth' + str(index)
    logger.info('Creating ENI for Subnet: ' + subnetid)
    logger.info('Creating ENI for SG: ' + security_groups)
    try:
        nif = ec2.create_network_interface(SubnetId=subnetid, Groups=[security_groups], Description=desc)
    except ClientError as error:
        logger.info("ERROR: ENI creation failed.\n")
        logger.info(error)
        return 'false'
    else:
        logger.info("INFO: ENI Created.\n")
        try:
            nif.modify_attribute(SourceDestCheck={'Value': False})
            nif.reload()
            response = nif.describe_attribute(Attribute='description')
            eni_id = response['NetworkInterfaceId']
            logger.info('Eni-id for newly created ENI is: ' + str(eni_id))
        except ClientError as e:
            logger.error("[create_eni modify attr, reload failed]: {}".format(e))
            logger.error('Deleting previously created ENI')
            logger.error(nif)
            logger.error('Nif id is: ' + str(nif.id))
            remove_eni(nif.id)
            return 'false'

        return eni_id, 'true'


def remove_eni(eni_id):
    """
    Method to disassociate an ENI from an instance.
    :param eni_id:
    :return:
    """
    try:
        ec2_client.delete_network_interface(NetworkInterfaceId=eni_id)
    except ClientError as e:
        logger.error("[removeEni]: {}".format(e))

    return


def wait_eni_ready(eni_id):
    """
    Method to check if an ENI is ready
    :param eni_id:
    :return:
    """
    try:
        waiter = ec2_client.get_waiter('network_interface_available')
        waiter.wait(NetworkInterfaceIds=[eni_id], Filters=[{'Name': 'status', 'Values': ['available']}])
    except ClientError:
        logger.info("ERROR: ENI failed to reach desired state\n")
        return 'false'
    else:
        return 'true'


def attach_eni(ec2_instance_id, eni_id, index):
    """
    Method to attach and ENI to an instance
    :param ec2_instance_id:
    :param eni_id:
    :param index:
    :return:
    """
    try:
        response = ec2_client.attach_network_interface(NetworkInterfaceId=eni_id, InstanceId=ec2_instance_id,
                                                       DeviceIndex=index)
        aid = response['AttachmentId']
        ec2_client.modify_network_interface_attribute(NetworkInterfaceId=eni_id,
                                                      Attachment={'AttachmentId': aid, 'DeleteOnTermination': True})
    except ClientError as e:
        logger.error("[attach/modify Eni]: {}".format(e))
        return 'false'

    else:
        logger.info('INFO: ENI attached EC2 instance for index: ' + str(index))
        return 'true'


def retrieve_fw_ip(ec2_instanceid, index):
    """
    Retrieve the IP of the Instance

    :param instancId: The id of the instance
    :type instance_id: str
    """

    eni_response = ec2_client.describe_network_interfaces(
        Filters=[{'Name': "attachment.instance-id", 'Values': [ec2_instanceid]},
                 {'Name': "attachment.device-index", 'Values': [str(index)]}])
    logger.info("Describe network interfaces response: {}".format(eni_response))

    try:
        for i in eni_response['NetworkInterfaces']:
            ip = i['PrivateIpAddress']

    except Exception as e:
        logger.error("[FW IP Address in Create CW]: {}".format(e))
        ip = "NO_PrivateIP_ADDR"

    if ip.find("NO_") >= 0:
        logger.error('We failed to get either EIP or Private IP for instance: ' + str(ec2_instanceid) + ' IP: ' + ip)
        logger.error('We will not proceed further with this Instance: ' + str(ec2_instanceid))

    return ip


def allocate_eip():
    try:
        eip = ec2_client.allocate_address(Domain='vpc')

    except ClientError as e:
        logger.info("[ERROR]: Unable to allocate elastic IP {}".format(e))
        return 'false'

    else:
        # Associate eip with Instance ID
        logger.info("[INFO]: Allocated elastic IP\n")
        return eip


def allocate_and_attach_eip(eip_id):
    eip_address_dict = ec2_client.describe_addresses()
    # List of IP addresses is not empty, so we may have an unassociated IP address?
    eip_list = eip_address_dict['Addresses']

    if not eip_list:
        eip = allocate_eip()
        if eip == 'false':
            return 'false'

    else:
        # There are some elastic IPs floating around, so find if one of the is not associated with an instance
        logger.info("[INFO]: Found some EIPs")
        eip = get_unassociated_eip(eip_list)
        # If the address is blank, then no unassociated addresses were found
        if eip is None:
            # So allocate an elastic ip
            eip = allocate_eip()
            if eip == 'false':
                return 'false'

    err = associate_address(eip['AllocationId'], eip_id)
    if err == 'false':
        return 'false'
    return eip


def terminate(success, asg_message, ec2_instanceid):
    if asg_message is None:
        return  # this is not via an ASG event, but via CFT custom resource.
    else:
        # log that we"re terminating and why
        if success == "false":
            logging.error("[ERROR]: Lambda function reporting failure to AutoScaling with error:\n")
            result = "ABANDON"
        else:
            logger.info("[INFO]: Lambda function reporting success to AutoScaling.")
            result = "CONTINUE"

        # call autoscaling
        asg.complete_lifecycle_action(
            AutoScalingGroupName=asg_message["AutoScalingGroupName"],
            LifecycleHookName=asg_message["LifecycleHookName"],
            LifecycleActionToken=asg_message["LifecycleActionToken"],
            InstanceId=ec2_instanceid,
            LifecycleActionResult=result)
        return


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
    global asg_name
    global Namespace

    global logger

    global debug

    debug = "Yes"
    apikey = os.environ['apikey']
    stackname = os.environ['StackName']
    region = os.environ['Region']

    lambda_bucket_name = os.environ['lambda_bucket_name']



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
                return
            elif message.get('Event') == "autoscaling:EC2_INSTANCE_LAUNCH":
                logger.info("GOT launch notification...will get launching event from lifecyclehook")
                # logger.info("[EVENT]: {}".format(event))
                return
            elif message.get('Event') == "autoscaling:EC2_INSTANCE_TERMINATE":
                logger.info("GOT terminate notification....will get terminating event from lifecyclehook")
                return
            elif message.get('Event') == "autoscaling:EC2_INSTANCE_TERMINATE_ERROR":
                logger.info("GOT a GW terminate error...raise exception for now")
                return
            elif message.get('Event') == "autoscaling:EC2_INSTANCE_LAUNCH_ERROR":
                logger.info("GOT a GW launch error...raise exception for now")
                return
    else:
        logger.info("[ERROR]: Something else entirely")
        raise Exception("[ERROR]: Something else entirely")

    logger.info('Message that we are parsing is {}'.format(message))

    lifecycle_hook_name = message['LifecycleHookName']
    asg_name = message['AutoScalingGroupName']
    ec2_instanceid = message['EC2InstanceId']
    logger.info('ec2_instanceid: ' + ec2_instanceid)

    if debug == 'Yes':
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)


    if event_type == 'terminate':
        logger.info('PANW EC2 Firewall Instance is terminating')
        fw_mgmt_ip = retrieve_fw_ip(ec2_instanceid, 1)
        logger.info('Generating apikey at {}'.format(fw_mgmt_ip))
        # fwApiKey = getApiKey(fw_mgmt_ip, username, password)
        fwApiKey = apikey
        handle_license(ec2_instanceid, fw_mgmt_ip, fwApiKey)

        remove_secondary_eni(message)

        # Add instance to firewall tablefwUntrustPrivIP
        parameters = {
            'lambda_bucket_name': lambda_bucket_name,
            'event-name': 'gw-terminate',
            'instance-id': ec2_instanceid,
            'asg_name': asg_name,
            'asg_hookname': lifecycle_hook_name
        }

        invoke_response = lambda_client.invoke(FunctionName=config_gw_func,
                                               InvocationType="Event", Payload=json.dumps(parameters))
        if invoke_response.get("StatusCode") == 202:
            logger.info("[INFO]: Got OK from invoke lambda functions for terminating. exiting...")
            lifecycle_hook_success(message)

        else:
            logger.info("[ERROR]: Something bad happened for launch. invoke_response = {}".format(invoke_response))
            terminate("false", message, ec2_instanceid)

        lifecycle_hook_abandon(message)
        return

    if event_type == 'launch':
        logger.info('PANW EC2 Firewall Instance is launching')


        logger.info('LifecycleHookName: ' + message['LifecycleHookName'])

        logger.info("metadata type is {}".format(type(message['NotificationMetadata'])))

        metadata = json.loads(message['NotificationMetadata'])
        logger.info('Metadata is: {}'.format(message['NotificationMetadata']))
        for k, v in metadata.items():
            logger.info("key {} value {}".format(k, v))
        mgmt_subnets = metadata['MGMT']
        untrust_subnets = metadata['UNTRUST']
        trust_subnets = metadata['TRUST']
        mgmt_security_group = metadata['SGM']
        untrust_security_group = metadata['SGU']
        trust_security_group = metadata['SGT']

        logger.info('Mgmt Subnet: ' + mgmt_subnets + ' Security-Group: ' + mgmt_security_group)
        logger.info('Untrust Subnet: ' + untrust_subnets + ' Security-Group: ' + untrust_security_group)
        logger.info('Trust Subnet: ' + trust_subnets + ' Security-Group: ' + trust_security_group)

        logger.info('Instance ID ec2_instanceid is {}'.format(message['EC2InstanceId']))
        val = str(message['EC2InstanceId'])
        logger.info('Calling describe interfaces for ec2_instanceid:'.format(val))
        while True:
            try:
                interfaces_dict = ec2_client.describe_network_interfaces(
                    Filters=[{'Name': "attachment.instance-id", 'Values': [val]},
                             {"Name": "attachment.device-index", "Values": ["0"]}]
                )
            except ClientError as e:
                logger.info('Got ClientError {}'.format(e))
                logger.info('Is interface 0 not ready?...Retrying')
                continue
            logger.info('Interface 0 ready and set to go')
            logger.info('Got interface index 0 {}'.format(interfaces_dict))
            break

        # Associate EIP to the first interface
        eni_id = (interfaces_dict.get("NetworkInterfaces")[0]).get("NetworkInterfaceId")
        fw_untrust_priv_ip = (interfaces_dict.get("NetworkInterfaces")[0]).get('PrivateIpAddress')
        ec2_client.modify_network_interface_attribute(NetworkInterfaceId=eni_id,
                                                      Description={"Value": "Egress Fw Mgmt"})
        if eni_id is None:
            logger.info("[ERROR] Netowrk Interface ID is None. Should not be!")
            lifecycle_hook_abandon(message)
            return
        # eniId = interfaces_dict["NetworkInterfaces"][0]["NetworkInterfaceId"]

        err = allocate_and_attach_eip(eni_id)
        if err == "false":
            logger.info("[ERROR] allocate and attach failed")
            # raise Exception("[ERROR] allocate and attach failed : " inspect.stack()[1][3]);
            lifecycle_hook_abandon(message)
            return
        else:
            logger.info("[INFO] allocate and attach successful")

            fw_untrust_pub_ip = err.get("PublicIp")
            if fw_untrust_pub_ip is None:
                logger.info("[ERROR]: fwUntrustPubIP is None")
                lifecycle_hook_abandon(message)
                return
            else:
                logger.info("[INFO]: fwUntrustPubIP is %s", fw_untrust_pub_ip)

        list_mgmt = mgmt_subnets.split(",")
        list_untrust = untrust_subnets.split(",")
        list_trust = trust_subnets.split(",")

        # get the az to which the instance belongs
        logger.info('The instance being considered is :' + ec2_instanceid)
        response = ec2_client.describe_instances(InstanceIds=[ec2_instanceid])
        logger.info('Retrived response{}'.format(response))
        az = ''
        for r in response['Reservations']:
            for i in r['Instances']:
                az = i['Placement']['AvailabilityZone']
                logger.info('The instance belongs to AvailabilityZone :' + az)

                # get the subnets for corresponding az of the instance
        mgmt_subnets = check_belongsto_az(list_mgmt, az)
        logger.info("The management subnet for this instance is: " + mgmt_subnets)
        untrust_subnets = check_belongsto_az(list_untrust, az)
        logger.info("The untrust subnet for this instance is: " + untrust_subnets)
        trust_subnets = check_belongsto_az(list_trust, az)
        logger.info("The trust subnet for this instance is: " + trust_subnets)

        # CreateEni for mgmt interface
        eni_id, err = create_eni(mgmt_subnets, mgmt_security_group, 1)
        if err == 'false':
            logger.info("Error: Eni creation failed\n")
            lifecycle_hook_abandon(message)
            return

        # Wait for the ENI to be 'available'
        err = wait_eni_ready(eni_id)
        if err == 'false':
            logger.info("ERROR: Failure waiting for ENI to be ready")
            lifecycle_hook_abandon(message)
            return

        # Attach the network interface to the instance

        mgmt_eni_id = eni_id
        err = attach_eni(ec2_instanceid, mgmt_eni_id, 1)
        if err == 'false':
            logger.info("ERROR: Failure attaching ENI to instance for eth1")
            remove_eni(mgmt_eni_id)
            lifecycle_hook_abandon(message)
            return
        else:
            logger.info("INFO: Success! Attached ENI to instance for eth1")

        # Get Mgmt IP
        try:
            response = ec2_client.describe_network_interfaces(NetworkInterfaceIds=[mgmt_eni_id])
        except Exception as e:
            logger.error("Describe NI failed for mgmt_enID: {}".format(e))

        ip = "NO_IP"

        try:
            for i in response['NetworkInterfaces']:
                ip = i['PrivateIpAddress']

        except Exception as e:
            logger.error("[FW IP Address in Create CW]: {}".format(e))
            ip = "NO_PrivateIP_ADDR"

        if ip.find("NO_") >= 0:
            logger.error(
                'We failed to get either EIP or Private IP for instance: ' + str(ec2_instanceid) + ' IP: ' + ip)
            logger.error('We will not proceed further with this Instance: ' + str(ec2_instanceid))

        fw_mgmt_ip = ip

        # CreateEni for Trust Subnet
        nif = ""
        eni_id, err = create_eni(trust_subnets, trust_security_group, 2)
        if err == 'false':
            logger.info("Error: Eni creation failed\n")

        logger.info(nif)
        # Wait for the ENI to be 'available'
        err = wait_eni_ready(eni_id)
        if err == 'false':
            logger.info("ERROR: Failure waiting for ENI to be ready")
            lifecycle_hook_abandon(message)
            return

        # Attach the network interface to the instance
        err = attach_eni(ec2_instanceid, eni_id, 2)
        if err == 'false':
            logger.info("ERROR: Failure attaching ENI to instance for eth2")
            remove_eni(eni_id)
            lifecycle_hook_abandon(message)
            return
        else:
            logger.info("INFO: Success! Attached ENI to instance for eth2")

        count_eni("ADD", ec2_instanceid)


        parameters = {
            'fwMgmtIP': fw_mgmt_ip,
            'lambda_bucket_name': lambda_bucket_name,
            'event-name': 'gw-launch',
            'fwUntrustPubIP': fw_untrust_pub_ip,
            'fwUntrustPrivIP': fw_untrust_priv_ip,
            'instance-id': ec2_instanceid,
            'asg_name': asg_name,
            'asg_hookname': lifecycle_hook_name,
            'fwUntrustSubnet': untrust_subnets,
            'fwMgmtSubnet': mgmt_subnets
        }
        logger.info('Updated parameters dict is {}'.format(parameters))
        event.update(parameters)
        logger.info('Updated event is {}'.format(event))
        return event

        # invoke_response = lambda_client.invoke(FunctionName=config_gw_func,
        #                                        InvocationType="Event", Payload=json.dumps(parameters))
        # if invoke_response.get("StatusCode") == 202:
        #     logger.info("[INFO]: Got OK from invoke lambda functions for launch. exiting...")
        #     lifecycle_hook_success(message)
        #
        # else:
        #     logger.info("[ERROR]: Something bad happened for launch. invoke_response = {}".format(invoke_response))
        #     terminate("false", message, ec2_instanceid)

        return

if __name__ ==  '__main__':
    event = {
        'LifecycleHookName': 'vpn-outASG-life-cycle-launch',
        'AccountId': '106808901653',
        'RequestId': '83a5ba35-847d-bf69-c4e6-5489d329d93d',
        'LifecycleTransition': 'autoscaling:EC2_INSTANCE_LAUNCHING',
        'AutoScalingGroupName': 'vpn-outASG',
        'Service': 'AWS Auto Scaling',
        'Time': '2019-11-21T09:53:35.840Z',
        'EC2InstanceId': 'i-0ba4321e3594b4cf9',
        'NotificationMetadata': '{\'MGMT\': \'subnet-0beddf8bb1c152657,subnet-0bbbdda8ce9e83870\', \'UNTRUST\': \'subnet-0fdc88a76d9fa7214,subnet-0056c067e24069d6a\', \'TRUST\': \'subnet-0e675eef937ef17af,subnet-09d69b4f6cd0751fe\', \'SGM\': \'sg-01ea99cbf258c3aee\', \'SGU\': \'sg-04e64feffff2df9a8\', \'SGT\': \'sg-0d905769014346510\', \'apikey\': \'LUFRPT1qS2xCRmZ6WVMrREtrK00yUGt4dVRna2lkY1U9cmgyaE93L3VoZ2U3WUgxeFpGVE1wOUNtdlM2S0Z5Z25ObG8wbmZoNXpuWT0=\'}',
        'LifecycleActionToken': '3e42a338-d23d-44a7-98e5-72de1892925f'
    }
    context = ''

    add_eni_lambda_handler(event, context)
