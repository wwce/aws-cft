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
import socket
import struct

import boto3

import cfnresponse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Enable creation of S3 bucket per-ASG
enable_s3 = False
num_nlb_port = 1280
start_nlb_port = 81
num_fw_az = 2

# Global Tunnables
dig = True
asg_tag_key = "PANW-ASG"
asg_delay = 30

Region = os.environ['Region']

logger = logging.getLogger()

####### GLobal Variables ############
"""
stackname=""
region=""
sg_vpc=""
sg_mgmt=""
sg_untrust=""
sg_trust=""
keyname=""
iamprofilebs=""
s3master=""
subnetmgmt=""
subnetuntrust=""
subnettrust=""
routetableidtrust=""
vpcid =""
imageID=""
instanceType=""
LambdaExecutionRole=""
LambdaENISNSTopic=""
ASGNotifierRole=""
ASGNotifierRolePolicy=""
LambdaS3Bucket=""
SubnetIDNATGW=""
SubnetIDLambda=""

apikey =""

ScalingPeriod=300
ScaleUpThreshold=50
ScaleDownThreshold=30
ScalingParameter=""
MinInstancesASG=1
MaximumInstancesASG=3

"""

error_line = "--------ERROR------ERROR-----ERROR------ERROR-------"

######## BOTO3 Clients and Resources #############
s3 = boto3.client('s3', region_name=Region)
asg = boto3.client('autoscaling', region_name=Region)
ec2 = boto3.resource('ec2', region_name=Region)
ec2_client = ec2.meta.client
lambda_client = boto3.client('lambda', region_name=Region)
iam = boto3.client('iam', region_name=Region)
events_client = boto3.client('events', region_name=Region)
cloudwatch = boto3.client('cloudwatch', region_name=Region)


def remove_alarm(asg_name):
    """

    :param asg_name:
    :return:
    """
    alarmname = asg_name + '-cw-cpu'
    common_alarm_func_del(alarmname)

    alarmname = asg_name + '-cw-as'
    common_alarm_func_del(alarmname)

    alarmname = asg_name + '-cw-su'
    common_alarm_func_del(alarmname)

    alarmname = asg_name + '-cw-gpu'
    common_alarm_func_del(alarmname)

    alarmname = asg_name + '-cw-gpat'
    common_alarm_func_del(alarmname)

    alarmname = asg_name + '-cw-dpb'
    common_alarm_func_del(alarmname)

    alarmname = asg_name + '-cw-sspu'
    common_alarm_func_del(alarmname)

    return


def remove_asg(stackname, elbtg, az, ScalingParameter, KeyPANWPanorama, force, delete_stack):
    """

    :param stackname:
    :param elbtg:
    :param az:
    :param ScalingParameter:
    :param KeyPANWPanorama:
    :param force:
    :param delete_stack:
    :return:
    """

    asg_response = asg.describe_auto_scaling_groups()
    found = False
    logger.info('ASG i[AutoScalingGroupName]: ' + asg_response['AutoScalingGroupName'])
    asg_grp_name = asg_response['AutoScalingGroupName']

    logger.info('Remove ASG: ' + asg_grp_name)

    try:
        logger.info('Disable metrics collection and Set Min and Desired Capacity to 0 for ASG: ' + asg_grp_name)
        asg.disable_metrics_collection(AutoScalingGroupName=asg_grp_name)
        scaleout = asg_grp_name + '-scaleout'
        asg.update_auto_scaling_group(AutoScalingGroupName=asg_grp_name, MinSize=0, DesiredCapacity=0)
        # asg.put_scheduled_update_group_action(AutoScalingGroupName=asg_grp_name, ScheduledActionName=scaleout, MinSize=0, DesiredCapacity=0)
    except Exception as e:
        logger.info('Could not disable_metrics_collection and Set Min/Desired Capacity to 0 for ASG. Reason below')
        logger.info("[RESPONSE]: {}".format(e))
        if force == False:
            remove_alarm(asg_grp_name)
            return False

    remove_alarm(asg_grp_name)

    policyname = asg_grp_name + '-scalein'
    logger.info('Deleting ScalePolicyIn :' + policyname)
    try:
        asg.delete_policy(AutoScalingGroupName=asg_grp_name, PolicyName=policyname)
    except Exception as e:
        logger.info("[ScaleIn Policy]: {}".format(e))

    policyname = asg_grp_name + '-scaleout'

    logger.info('Deleting ScalePolicyOut :' + policyname)
    try:
        asg.delete_policy(AutoScalingGroupName=asg_grp_name, PolicyName=policyname)
    except Exception as e:
        logger.info("[ScaleOut Policy]: {}".format(e))

    response = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_grp_name])
    lc_name = ""
    try:
        for i in response['AutoScalingGroups']:
            logger.info('i of response[AutoScalingGroups]:')
            logger.info(i)
            lc_name = i['LaunchConfigurationName']
    except Exception as e:
        logger.info("[LC config Name]: {}".format(e))

    if lc_name == "":
        logger.critical('LC for ASG not found: ' + asg_grp_name)
        if force == False:
            return False

    remove_asg_life_cycle(asg_grp_name)

    logger.info('Deleting ASG : ' + asg_grp_name)
    try:
        if force == True:
            asg.delete_auto_scaling_group(AutoScalingGroupName=asg_grp_name, ForceDelete=True)
        else:
            asg.delete_auto_scaling_group(AutoScalingGroupName=asg_grp_name)
    except Exception as e:
        logger.info('Could not remove ASG. Reason below')
        logger.info("[ASG DELETE]: {}".format(e))
        if force == False:
            return False

    logger.info('Deleting Lanuch-configuration for ASG: ' + asg_grp_name)
    try:
        asg.delete_launch_configuration(LaunchConfigurationName=lc_name)
    except Exception as e:
        logger.info('Could not remove ASG. Reason below')
        logger.info("[ASG DELETE LC]: {}".format(e))
        if force == False:
            return False

    return True


def remove_asg_life_cycle(asg_name):
    """

    :param asg_name:
    :return:
    """
    logger.info('Removing Life Cycle Hooks for ASG: ' + asg_name)
    hookname = asg_name + '-life-cycle-launch'
    try:
        asg.delete_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name)
    except Exception as e:
        logger.info("[ASG life-cycle Hook Launch]: {}".format(e))
    hookname = asg_name + '-life-cycle-terminate'
    try:
        asg.delete_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name)
    except Exception as e:
        logger.info("[ASG life-cycle Hook Terminate]: {}".format(e))
    return


def get_cw_name_space(stackname, asg_name):
    """

    :param stackname:
    :param asg_name:
    :return:
    """
    name = asg_name
    return name[-63:len(name)]


def common_alarm_func_add(asg_name, metricname, namespace, arn_scalein, arn_scaleout, alarmname, desc, Unit):
    """

    Method that supports a common interface to add cloud watch alarms along with the associated threshold
    metrics.

    :param asg_name: Name of the ASG that this alarm is associated with.
    :param metricname: Name of the metric.
    :param namespace: Name of the namespace.
    :param arn_scalein: ARN of the scale-in metric.
    :param arn_scaleout: ARN of the scale-out metric.
    :param alarmname: Name of the alarm that will be raised.
    :param desc: Description of the alarm
    :param Unit: The unit to be used.
    :return: bool
    """
    d1 = desc + " High"
    a1 = alarmname + '-high'
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
                                    AlarmActions=[arn_scaleout],
                                    ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
                                    Threshold=float(ScaleUpThreshold), Statistic="Average", Namespace=namespace,
                                    ComparisonOperator="GreaterThanThreshold", Period=ScalingPeriod, Unit=Unit)
    except Exception as e:
        logger.error('Failed to add High Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm High Add]: {}".format(e))
        return False

    a1 = alarmname + '-low'
    d1 = desc + " Low"
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
                                    AlarmActions=[arn_scalein],
                                    ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
                                    Threshold=float(ScaleDownThreshold), Statistic="Average", Namespace=namespace,
                                    ComparisonOperator="LessThanThreshold", Period=ScalingPeriod,
                                    Unit=Unit)
    except Exception as e:
        logger.error('Failed to add Low Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm Low Add]: {}".format(e))
        return False

    return True


def common_alarm_func_del(alarmname):
    """
    Common interface to delete alarms
    :param alarmname: Name of the alarm to delete.
    :return: None
    """
    a1 = alarmname + '-high'
    cloudwatch.delete_alarms(AlarmNames=[a1])

    a1 = alarmname + '-low'
    cloudwatch.delete_alarms(AlarmNames=[a1])
    return


## CloudWatch Alarms
def AddDataPlaneCPUUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the DataPlaneCPUUtilization Alarm. This alarm
    will trigger when the Data Plane CPU Utilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating dataPlane CPU High CloudWatch alarm for ASG: ' + asg_name)

    alarmname = asg_name + '-cw-cpu'
    return common_alarm_func_add(asg_name, "DataPlaneCPUUtilizationPct", get_cw_name_space(stackname, asg_name),
                                 arn_scalein, arn_scaleout,
                                 alarmname, "DataPlane CPU Utilization", 'Percent')


def DelDataPlaneCPUUtilization(asg_name):
    """
    Method to delete the DataPlaneCPUUtilization Alarm. This alarm
    will trigger when the Data Plane CPU Utilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting dataPlane CPU High CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-cpu'
    common_alarm_func_del(alarmname)
    return


def AddActiveSessions(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the ActiveSessions Alarm. This alarm
    will trigger when the Active Sessions exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname = asg_name + '-cw-as'
    return common_alarm_func_add(asg_name, "panSessionActive", get_cw_name_space(stackname, asg_name), arn_scalein,
                                 arn_scaleout,
                                 alarmname, "Active Sessions", 'Count')


def DelActiveSessions(asg_name):
    """
    Method to delete the Active Sessions alarm

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname = asg_name + '-cw-as'
    common_alarm_func_del(alarmname)
    return


def AddSessionUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the SessionUtilization Alarm. This alarm
    will trigger when the SessionUtilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-su'
    return common_alarm_func_add(asg_name, "panSessionUtilization", get_cw_name_space(stackname, asg_name),
                                 arn_scalein, arn_scaleout,
                                 alarmname, "Session Utilization", 'Percent')


def DelSessionUtilization(asg_name):
    """
        Method to delete the Session Utilization alarm

        :param asg_name: Name of the ASG
        :return: None
    """
    logger.info('Deleting Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-su'
    common_alarm_func_del(alarmname)
    return


def AddGPGatewayUtilization(asg_name, arn_scalein, arn_scaleout):
    """
        Method to create the GPGatewayUtilization Alarm. This alarm
        will trigger when the GPGatewayUtilization exceeds the
        specified threshold.

        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    """
    logger.info('Creating GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-gpu'
    return common_alarm_func_add(asg_name, "panGPGatewayUtilizationPct", get_cw_name_space(stackname, asg_name),
                                 arn_scalein, arn_scaleout,
                                 alarmname, "GP Gateway Utilization", 'Percent')


def DelGPGatewayUtilization(asg_name):
    """
    Method to delete the GP Session Utilization alarm

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-gpu'
    common_alarm_func_del(alarmname)
    return


def AddGPActiveTunnels(asg_name, arn_scalein, arn_scaleout):
    """
        Method to create the GPActiveTunnels Alarm. This alarm
        will trigger when the GP Active Tunnels  exceeds the
        specified threshold.

        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    """
    logger.info('Creating GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-gpat'
    return common_alarm_func_add(asg_name, "panGPGWUtilizationActiveTunnels",
                                 get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                                 alarmname, "GP Gateway Utilization", 'Count')


def DelGPActiveTunnels(asg_name):
    """
    Method to delete the GP GPActiveTunnels alarm

    :param asg_name: Name of the ASG
    :return: None
    """

    logger.info('Deleting GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-gpat'
    common_alarm_func_del(alarmname)
    return


def AddDataPlaneBufferUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the DataPlaneBufferUtilization Alarm. This alarm
    will trigger when the DataPlaneBufferUtilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating DP Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-dpb'
    return common_alarm_func_add(asg_name, "DataPlanePacketBufferUtilization",
                                 get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                                 alarmname, "Data Plane Packet Buffer Utilization", 'Percent')


def DelDataPlaneBufferUtilization(asg_name):
    """
    Method to delete the DatePlaneBufferUtilization  alarm

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting DP Packet Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-dpb'
    common_alarm_func_del(alarmname)
    return


def AddSessionSslProxyUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the SessionSslProxyUtilization Alarm. This alarm
    will trigger when the SessionSslProxyUtilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating Session SSL Proxy  Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-sspu'
    return common_alarm_func_add(asg_name, "panGPGatewayUtilizationPct", get_cw_name_space(stackname, asg_name),
                                 arn_scalein, arn_scaleout,
                                 alarmname, "Session SSL Proxy Utilization", 'Percent')
    return


def DelSessionSslProxyUtilization(asg_name):
    """
    Method to delete the SessionSslProxyUtilization alarm

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting Session SSL Proxy Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname = asg_name + '-cw-sspu'
    common_alarm_func_del(alarmname)
    return


cw_func_add_alarms = {'DataPlaneCPUUtilizationPct': AddDataPlaneCPUUtilization,
                      'panSessionActive': AddActiveSessions,
                      'panSessionUtilization': AddSessionUtilization,
                      'panGPGatewayUtilizationPct': AddGPGatewayUtilization,
                      'panGPGWUtilizationActiveTunnels': AddGPActiveTunnels,
                      'panSessionSslProxyUtilization': AddSessionSslProxyUtilization,
                      'DataPlanePacketBufferUtilization': AddDataPlaneBufferUtilization}

cw_func_del_alarms = {'DataPlaneCPUUtilizationPct': DelDataPlaneCPUUtilization,
                      'panSessionActive': DelActiveSessions,
                      'panSessionUtilization': DelSessionUtilization,
                      'panGPGatewayUtilizationPct': DelGPGatewayUtilization,
                      'panGPGWUtilizationActiveTunnels': DelGPActiveTunnels,
                      'panSessionSslProxyUtilization': DelSessionSslProxyUtilization,
                      'DataPlanePacketBufferUtilization': DelDataPlaneBufferUtilization}


def fix_subnets(data1):
    """

    :param data1:
    :return:
    """
    data = str(data1)
    data = data.replace("'", "")
    data = data.replace("[", "")
    data = data.replace("]", "")
    return data


def fix_unicode(data):
    """
        Method to convert opaque data from unicode to utf-8
        :param data: Opaque data
        :return: utf-8 encoded data
    """
    if isinstance(data, str):
        return data.encode('utf-8')
    elif isinstance(data, dict):
        data = dict((fix_unicode(k), fix_unicode(data[k])) for k in data)
    elif isinstance(data, list):
        for i in range(0, len(data)):
            data[i] = fix_unicode(data[i])

    return data


def create_asg_life_cycle(asg_name):
    """
    Method to register ASG life cycle hook actions.


    When and ASG lifecycle hook is triggered the targets as registered
    by this method get triggered with the appropriate data fields.

    :param asg_name: Name of the ASG.
    :return: bool
    """
    logger.info('Creating Life Cycle Hook for ASG: ' + asg_name)
    hookname = asg_name + '-life-cycle-launch'

    metadata = {
        'MGMT': subnetmgmt,
        'UNTRUST': subnetuntrust,
        'TRUST': subnettrust,
        'SGM': sg_mgmt,
        'SGU': sg_untrust,
        'SGT': sg_trust,
        'apikey': apikey
    }

    try:
        asg.put_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name,
                               LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
                               RoleARN=ASGNotifierRole, NotificationTargetARN=LambdaENISNSTopic,
                               DefaultResult="ABANDON", HeartbeatTimeout=300,
                               NotificationMetadata=json.dumps(metadata))
    except Exception as e:
        logger.error("[ASG LifeCycle Hook Launch. ROLLBACK]: {}".format(e))
        return False

    hookname = asg_name + '-life-cycle-terminate'
    try:
        asg.put_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name,
                               LifecycleTransition="autoscaling:EC2_INSTANCE_TERMINATING",
                               RoleARN=ASGNotifierRole, NotificationTargetARN=LambdaENISNSTopic,
                               DefaultResult="CONTINUE", HeartbeatTimeout=300,
                               NotificationMetadata=json.dumps(metadata))
    except Exception as e:
        logger.error("[ASG LifeCycle Hook Terminate. ROLLBACK]: {}".format(e))
        return False

    return True


def get_lc_name(stackname, elbtg):
    """

    :param stackname:
    :param elbtg:
    :return:
    """
    name = stackname[:10] + '_ASG_LC'
    return name[-63:len(name)]


def create_asg():
    """


    Method to create an Auto Scale Group with the configuration
    provided.

    .. note:: This method performs the following critical functions

       - reads in configuration from an S3 bucket
       - creates a launch configuration
       - creates an ASG
       - associates the policies with the ASG
       - registers to ASG life-cycle hook events and provides handlers for these events.

    :return:
    """
    lc_name = stackname[:10] + '_ASG_LC'
    asg_name = stackname[:10] + 'ASG'

    logger.info('Creating launch-config for a new ASG: ' + lc_name)
    userdata = 'vmseries-bootstrap-aws-s3bucket=' + s3master

    try:
        response = asg.create_launch_configuration(LaunchConfigurationName=lc_name,
                                                   ImageId=imageID, KeyName=keyname, SecurityGroups=[sg_untrust],
                                                   InstanceType=instanceType,
                                                   AssociatePublicIpAddress=False, EbsOptimized=True,
                                                   IamInstanceProfile=iamprofilebs,
                                                   BlockDeviceMappings=[
                                                       {'DeviceName': "/dev/xvda",
                                                        'Ebs':
                                                            {'DeleteOnTermination': True,
                                                             'VolumeType': 'gp2'
                                                             }
                                                        }
                                                   ],
                                                   UserData=userdata)
    except Exception as e:
        logger.error("[ASG LC error]: {}".format(e))
        return False

    logger.info('Creating Auto-Scaling Group with name: ' + asg_name)
    tags = {'ResourceId': asg_name, 'ResourceType': 'auto-scaling-group', 'Key': 'Name', 'Value': asg_name,
            'PropagateAtLaunch': True}
    logger.info(' Subnet Untrust List: ' + subnetuntrust)
    try:
        response = asg.create_auto_scaling_group(AutoScalingGroupName=asg_name, LaunchConfigurationName=lc_name,
                                                 MinSize=MinInstancesASG, MaxSize=MaximumInstancesASG,
                                                 DesiredCapacity=MinInstancesASG,
                                                 DefaultCooldown=ScalingPeriod,
                                                 VPCZoneIdentifier=subnetuntrust,
                                                 Tags=[tags],
                                                 HealthCheckGracePeriod=900)
    except Exception as e:
        logger.error("[ASG create error]: {}".format(e))
        return False

    # if create_asg_life_cycle(asg_name, AvailabilityZone) == False:
    if create_asg_life_cycle(asg_name) == False:
        return False

    scalein = asg_name + '-scalein'
    try:
        response = asg.put_scaling_policy(AutoScalingGroupName=asg_name, PolicyName=scalein,
                                          AdjustmentType='ChangeInCapacity',
                                          ScalingAdjustment=-1, Cooldown=600)
        arn_scalein = response['PolicyARN']
    except Exception as e:
        logger.error("[ASG ScaleIn Policy]: {}".format(e))
        return False

    scaleout = asg_name + '-scaleout'
    try:
        response = asg.put_scaling_policy(AutoScalingGroupName=asg_name, PolicyName=scaleout,
                                          AdjustmentType='ChangeInCapacity',
                                          ScalingAdjustment=1, Cooldown=600)
        arn_scaleout = response['PolicyARN']
    except Exception as e:
        logger.info("[ASG ScaleOut]: {}".format(e))
        return False

    logger.info('ARN of Scale In and Scale Out: ' + arn_scalein + ' ' + arn_scaleout)
    logger.info('Adding Cloud Watch Alarm : ' + ScalingParameter + ' for ASG: ' + asg_name)
    if cw_func_add_alarms[ScalingParameter](asg_name, arn_scalein, arn_scaleout) == False:
        return False

    return True


def get_azs(subnet_ids):
    """
    Region = 'eu-west-1'
    :param subnet_ids:
    :return:
    """
    fw_azs = []
    subnetids = subnet_ids.split(',')
    logger.info('Subnet id split type{}'.format(type(subnetids)))
    response1 = ec2_client.describe_subnets()
    logger.info(' subnets i See {}'.format(response1))

    for i in subnetids:
        subnet = ec2.Subnet(i)
        fw_azs.append(subnet.availability_zone)

    return fw_azs


def choose_subnet(subnet, AvailabilityZone):
    """
    Method to identify the subnet id based upon the
    availability zone.

    :param subnet:
    :param AvailabilityZone:
    :return:
    """
    logger.info('Choose Subnets: ')
    logger.info(subnet)
    list_subnets = subnet.split(",")
    response = ec2_client.describe_subnets(SubnetIds=list_subnets)
    ret_subnets = ""
    for i in response['Subnets']:
        if i['AvailabilityZone'] == AvailabilityZone:
            if ret_subnets == "":
                ret_subnets = i['SubnetId']
            else:
                ret_subnets = ret_subnets + "," + i['SubnetId']

    logger.info('Return Subnets for AZ: ' + AvailabilityZone + ' Subnets: ' + ret_subnets)
    return ret_subnets


def get_subnet_and_gw(ip_cidr):
    """
    Extract subnet and gateway from subnet cidr in AWS

    :param ip_cidr:
    :return:
    """
    addr_mask = ip_cidr.split('/')
    addr = addr_mask[0]
    try:
        mask = addr_mask[1]
    except IndexError:
        mask = '32'

    # convert to int
    addr = ip2int(addr)
    mask = int(mask)

    subnet = addr & ((0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF)
    if mask == 32:
        gw = addr
    else:
        gw = subnet | 1

    return (int2ip(subnet), int2ip(gw))


def ip2int(addr):
    """

    :param addr:
    :return:
    """
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    """

    :param addr:
    :return:
    """
    return socket.inet_ntoa(struct.pack("!I", addr))


def lambda_handler(event, context):
    """
    .. note:: This function is the entry point for the ```sched_event1``` Lambda function.

    This function performs the following actions:
    firewall_asg_update(event, context)
    firewall_init_config(event, context)
    network_load_balancer_update(event, context)

        | invokes ```check_and_send_message_to_queue()```
        |  desc: Checks the messages on the queue to ensure its up to date
        |        and for any changes as the case maybe.

        | invokes ```firewall_asg_update()```
        |  desc: monitor firewall asg and create asg if not exist

        | invokes ```firewall_init_config()```
        |  desc: monitor firewall in INIT state and move it to COMMIT if
        |        firewall auto commit is lifecycle_hook_success

        | invokes ```network_load_balancer_update()```
        |  desc: update firewall nat rules based on info in firewall table
        |        nlb table

    :param event: Encodes all the input variables to the lambda function, when
                  the function is invoked.
                  Essentially AWS Lambda uses this parameter to pass in event
                  data to the handler function.
    :type event: dict

    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :type context: LambdaContext

    :return: None
    """

    global stackname
    global region
    global sg_mgmt
    global sg_untrust
    global sg_trust
    global sg_vpc
    global keyname
    global iamprofilebs
    global s3master
    global subnetmgmt
    global subnetuntrust
    global subnettrust
    global routetableidtrust
    global vpcid
    global imageID
    global ScalingPeriod
    global ScaleUpThreshold
    global ScaleDownThreshold
    global ScalingParameter
    global instanceType
    global gcontext
    global MinInstancesASG
    global MaximumInstancesASG
    global LambdaExecutionRole
    global ASGNotifierRolePolicy
    global ASGNotifierRole
    global LambdaS3Bucket
    global SubnetIDNATGW
    global SubnetIDLambda
    global logger
    global fw_azs
    global trust_def_gw
    global apikey
    global LambdaENISNSTopic

    gcontext = context
    logger.info('got event{}'.format(event))
    eventresources = event['ResourceProperties']
    debug = eventresources['Debug']
    if debug == 'Yes':
        logger.setLevel(logging.INFO)

    logger.info('got eventresources{}'.format(eventresources))

    stackname = eventresources['StackName']
    region = eventresources['Region']
    vpcid = eventresources['VpcId']
    subnetmgmt = eventresources['SubnetIDMgmt']
    subnetuntrust = eventresources['SubnetIDUntrust']
    subnettrust = eventresources['SubnetIDTrust']
    routetableidtrust = eventresources['RouteTableIDTrust']
    sg_mgmt = eventresources['MgmtSecurityGroup']
    sg_trust = eventresources['TrustSecurityGroup']
    sg_untrust = eventresources['UntrustSecurityGroup']
    sg_vpc = eventresources['VPCSecurityGroup']
    keyname = eventresources['KeyName']
    instanceType = eventresources['FWInstanceType']
    MinInstancesASG = int(eventresources['MinInstancesASG'])
    MaximumInstancesASG = int(eventresources['MaximumInstancesASG'])
    ScaleUpThreshold = float(eventresources['ScaleUpThreshold'])
    ScaleDownThreshold = float(eventresources['ScaleDownThreshold'])
    ScalingParameter = eventresources['ScalingParameter']
    ScalingPeriod = int(eventresources['ScalingPeriod'])
    imageID = eventresources['ImageID']
    LambdaENISNSTopic = (eventresources['LambdaENISNSTopic'])
    iamprofilebs = str(eventresources['FirewallBootstrapRole'])
    LambdaExecutionRole = str(eventresources['LambdaExecutionRole'])
    ASGNotifierRole = str(eventresources['ASGNotifierRole'])
    ASGNotifierRolePolicy = str(eventresources['ASGNotifierRolePolicy'])
    s3master = eventresources['BootstrapS3BucketName']
    LambdaS3Bucket = eventresources['LambdaS3Bucket']
    SubnetIDNATGW = eventresources['SubnetIDNATGW']
    SubnetIDLambda = eventresources['SubnetIDLambda']
    apikey = eventresources['apikey']

    subnetuntrust = str((subnetuntrust))
    subnetuntrust = fix_subnets(subnetuntrust)

    subnetmgmt = str((subnetmgmt))
    subnetmgmt = fix_subnets(subnetmgmt)

    subnettrust = str((subnettrust))
    subnettrust = fix_subnets(subnettrust)

    SubnetIDNATGW = str((SubnetIDNATGW))
    SubnetIDNATGW = fix_subnets(SubnetIDNATGW)

    SubnetIDLambda = str((SubnetIDLambda))
    SubnetIDLambda = fix_subnets(SubnetIDLambda)

    routetableidtrust = str((routetableidtrust))
    routetableidtrust = fix_subnets(routetableidtrust)

    logger.info('StackName:' + stackname)
    logger.info('Mgmt Security Group ID : ' + sg_mgmt)
    logger.info('KeyName is :' + keyname)
    logger.info('S3 Master Bucket :' + s3master)
    logger.info('iamprofilebs: ' + iamprofilebs)
    logger.info('Subnet Mgmt List: ' + subnetmgmt)
    logger.info('Subnet Untrust List: ' + subnetuntrust)
    logger.info('Subnet Trust List: ' + subnettrust)
    logger.info('Trust Route Table IDlist: ' + routetableidtrust)
    logger.info('Deployed VpcId is :' + vpcid)

    try:
        logger.info("Calling get_azs with {} list".format(subnettrust))
        fw_azs = get_azs(subnettrust)
        # print("[{0}]".format(', '.join(map(str, fw_azs))))
        trust_def_gw = []
        for i in fw_azs:
            # logger.info("got inside of for loop")
            trust_subnet_id = choose_subnet(subnettrust, i)
            subnet = ec2.Subnet(trust_subnet_id)
            subnet_str, gw = get_subnet_and_gw(subnet.cidr_block)
            trust_def_gw.append(gw)
            # logger.info("Trust subnet default gw[{}]: {}".format(i, trust_def_gw[i]))
        logger.info("trust_def_gw:")
        print("[{0}]".format(', '.join(map(str, trust_def_gw))))
    except Exception as e:
        logger.exception("Get az and trust default gw error]: {}".format(e))
    responseData = {}
    # TODO fix cfnresponse info
    try:
        if event['RequestType'] == 'Delete':
            try:
                if remove_asg():
                    responseData['data'] = 'SUCCESS'
                    cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
                else:
                    responseData['data'] = 'FAILED'
                    cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
            except Exception as e:
                logger.error('Got ERROR in remove_asg .. check for left over resources {}'.format(e))
                cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        elif event['RequestType'] == 'Create':
            try:
                if create_asg():
                    responseData['data'] = 'SUCCESS'
                    cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
                else:
                    responseData['data'] = 'FAILED'
                    cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
            except Exception as e:
                logger.info("Got exception creating ASG: {}".format(e))
        elif event['RequestType'] == 'Update':
            pass

    except:
        logger.error('Got ERROR in create_asg Lamnda handler {}'.format(e))
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")


if __name__ == '__main__':
    event = {
        "RequestType": "Create",
        "ServiceToken": "arn:aws:lambda:us-east-1:106808901653:function:jh123-CreateAsgLambda-1BTO5XMNHI6JG",
        "ResponseURL": "https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/arn%3Aaws%3Acloudformation%3Aus-east-1%3A106808901653%3Astack/jh123/6c1372b0-8335-11e9-b128-127a71eef55e%7CLambdaCustomResource%7Cd6bc91c7-25e5-4619-abcd-5c42637ad464?AWSAccessKeyId\u003dAKIA6L7Q4OWT7XTLUBXY\u0026Expires\u003d1559267484\u0026Signature\u003dZMQi%2Bv4kSp90kIPhtNXU%2BWnzf2E%3D",
        "StackId": "arn:aws:cloudformation:us-east-1:106808901653:stack/jh123/6c1372b0-8335-11e9-b128-127a71eef55e",
        "RequestId": "d6bc91c7-25e5-4619-abcd-5c42637ad464",
        "LogicalResourceId": "LambdaCustomResource",
        "ResourceType": "AWS::CloudFormation::CustomResource",
        "ResourceProperties": {
            "ServiceToken": "arn:aws:lambda:us-east-1:106808901653:function:jh123-CreateAsgLambda-1BTO5XMNHI6JG",
            "ScaleDownThreshold": "20",
            "ScalingPeriod": "900",
            "MinInstancesASG": "2",
            "password": "password",
            "RouteTableIDTrust": "rtb-056ea4d6721ed6225,rtb-02b8e2c438554832e",
            "ScalingParameter": "DataPlaneCPUUtilizationPct",
            "InitLambda": "jh123-CreateAsgLambda-1BTO5XMNHI6JG",
            "TrustSecurityGroup": "sg-0bfd488bc117d5289",
            "LambdaS3Bucket": "us-east-1-autoscale",
            "MaximumInstancesASG": "5",
            "LambdaENISNSTopic": "arn:aws:sns:us-east-1:106808901653:jh123-LambdaENISNSTopic-GFEZHZZFJLSV",
            "SubnetIDLambda": "subnet-065e3d64065ce8f60,subnet-0ceaec717c5539d56",
            "BootstrapS3BucketName": "us-east-1-autoscale",
            "Debug": "No",
            "UntrustSecurityGroup": "sg-0e976cb0d04d375af",
            "FWInstanceType": "m4.xlarge",
            "LambdaExecutionRole": "TransitLambdaExecutionRole-jh123",
            "FirewallBootstrapRole": "jh123-FirewallBootstrapInstanceProfile-UNWLDADHBBW9",
            "VPCSecurityGroup": "sg-03bf8b00cf377b695",
            "ASGNotifierRolePolicy": "jh123-ASGN-3KVFZOEBUJDG",
            "KeyName": "us-east-1.key",
            "SubnetIDNATGW": "subnet-032ed2dc3f411b3ea,subnet-0adabb96c25416d9a",
            "VpcId": "vpc-084f4ff9836c3c130",
            "SubnetIDTrust": "subnet-08c1fbde977ca4b12,subnet-0bdc36ecd7436b12f",
            "SubnetIDUntrust": "subnet-07f9c3b50628f578b,subnet-0316f0292c60c819f",
            "ASGNotifierRole": "arn:aws:iam::106808901653:role/jh123-ASGNotifierRole-1U86ZKNFY2JWM",
            "ScaleUpThreshold": "80",
            "SubnetIDMgmt": "subnet-0d74424dcd2c52b9a,subnet-087f7c94d79ec251a",
            "MgmtSecurityGroup": "sg-0d4436544bfd28cd7",
            "ImageID": "ami-ce01c0b3",
            "Region": "us-east-1",
            "StackName": "jh123"
        }
    }
    context = ''

    lambda_handler(event, context)
