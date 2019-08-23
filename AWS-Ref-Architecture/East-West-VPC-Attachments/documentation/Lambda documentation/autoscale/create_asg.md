

NAME
    create_asg

DESCRIPTION

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
    
    
    # Author: Justin Harris <jharris@paloaltonetworks.com>sh
    
    Lambda Custom resource invoked during stack creation to configure autoscale.
    Performs the following tasks
    
    1) Configures the autoscale group sets the Lifecycle hook metadata that will be passed to the add_eni.py function during
    VM creation.  The metadata contains a dict of values that are required by the VM
    
    2) Creates the launch configuration for the VMs
    
    3) Configures the cloudwatch alarms

FUNCTIONS
    AddActiveSessions(asg_name, arn_scalein, arn_scaleout)
        Method to create the ActiveSessions Alarm. This alarm
        will trigger when the Active Sessions exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    
    AddDataPlaneBufferUtilization(asg_name, arn_scalein, arn_scaleout)
        Method to create the DataPlaneBufferUtilization Alarm. This alarm
        will trigger when the DataPlaneBufferUtilization exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    
    AddDataPlaneCPUUtilization(asg_name, arn_scalein, arn_scaleout)
        Method to create the DataPlaneCPUUtilization Alarm. This alarm
        will trigger when the Data Plane CPU Utilization exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    
    AddGPActiveTunnels(asg_name, arn_scalein, arn_scaleout)
        Method to create the GPActiveTunnels Alarm. This alarm
        will trigger when the GP Active Tunnels  exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    
    AddGPGatewayUtilization(asg_name, arn_scalein, arn_scaleout)
        Method to create the GPGatewayUtilization Alarm. This alarm
        will trigger when the GPGatewayUtilization exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    
    AddSessionSslProxyUtilization(asg_name, arn_scalein, arn_scaleout)
        Method to create the SessionSslProxyUtilization Alarm. This alarm
        will trigger when the SessionSslProxyUtilization exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    
    AddSessionUtilization(asg_name, arn_scalein, arn_scaleout)
        Method to create the SessionUtilization Alarm. This alarm
        will trigger when the SessionUtilization exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    
    DelActiveSessions(asg_name)
        Method to delete the Active Sessions alarm
        
        :param asg_name: Name of the ASG
        :return: None
    
    DelDataPlaneBufferUtilization(asg_name)
        Method to delete the DatePlaneBufferUtilization  alarm
        
        :param asg_name: Name of the ASG
        :return: None
    
    DelDataPlaneCPUUtilization(asg_name)
        Method to delete the DataPlaneCPUUtilization Alarm. This alarm
        will trigger when the Data Plane CPU Utilization exceeds the
        specified threshold.
        
        :param asg_name: Name of the ASG
        :return: None
    
    DelGPActiveTunnels(asg_name)
        Method to delete the GP GPActiveTunnels alarm
        
        :param asg_name: Name of the ASG
        :return: None
    
    DelGPGatewayUtilization(asg_name)
        Method to delete the GP Session Utilization alarm
        
        :param asg_name: Name of the ASG
        :return: None
    
    DelSessionSslProxyUtilization(asg_name)
        Method to delete the SessionSslProxyUtilization alarm
        
        :param asg_name: Name of the ASG
        :return: None
    
    DelSessionUtilization(asg_name)
        Method to delete the Session Utilization alarm
        
        :param asg_name: Name of the ASG
        :return: None
    
    choose_subnet(subnet, AvailabilityZone)
        Method to identify the subnet id based upon the
        availability zone.
        
        :param subnet:
        :param AvailabilityZone:
        :return:
    
    common_alarm_func_add(asg_name, metricname, namespace, arn_scalein, arn_scaleout, alarmname, desc, Unit)
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
    
    common_alarm_func_del(alarmname)
        Common interface to delete alarms
        :param alarmname: Name of the alarm to delete.
        :return: None
    
    create_asg()
        Method to create an Auto Scale Group with the configuration
        provided.
        
        .. note:: This method performs the following critical functions
        
           - reads in configuration from an S3 bucket
           - creates a launch configuration
           - creates an ASG
           - associates the policies with the ASG
           - registers to ASG life-cycle hook events and provides handlers for these events.
        
        :return:
    
    create_asg_life_cycle(asg_name)
        Method to register ASG life cycle hook actions.
        
        
        When and ASG lifecycle hook is triggered the targets as registered
        by this method get triggered with the appropriate data fields.
        
        :param asg_name: Name of the ASG.
        :return: bool
    
    fix_subnets(data1)
        :param data1:
        :return:
    
    fix_unicode(data)
        Method to convert opaque data from unicode to utf-8
        :param data: Opaque data
        :return: utf-8 encoded data
    
    get_azs(subnet_ids)
        Region = 'eu-west-1'
        :param subnet_ids:
        :return:
    
    get_cw_name_space(stackname, asg_name)
        :param stackname:
        :param asg_name:
        :return:
    
    get_lc_name(stackname, elbtg)
        :param stackname:
        :param elbtg:
        :return:
    
    get_subnet_and_gw(ip_cidr)
        Extract subnet and gateway from subnet cidr in AWS
        
        :param ip_cidr:
        :return:
    
    int2ip(addr)
        :param addr:
        :return:
    
    ip2int(addr)
        :param addr:
        :return:
    
    lambda_handler(event, context)
        Function to create the autoscale group during stack deployment.  The function is called as a lambda custom resource.
        We use a custom resource to setup cloudwatch alarms and configure LIFECYCLE HOOK notifications metadata to
        send to the VM.
        
        :param event: dict
        :param context: string
        :return: Cloudformation success or fail notification
    
    remove_alarm(asg_name)
        :param asg_name:
        :return:
    
    remove_asg(stackname, elbtg, az, ScalingParameter, KeyPANWPanorama, force, delete_stack)
        :param stackname:
        :param elbtg:
        :param az:
        :param ScalingParameter:
        :param KeyPANWPanorama:
        :param force:
        :param delete_stack:
        :return:
    
    remove_asg_life_cycle(asg_name)
        :param asg_name:
        :return:

