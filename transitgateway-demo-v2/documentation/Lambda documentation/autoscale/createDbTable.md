Help on module createDbTable:

NAME
    createDbTable

DESCRIPTION
    # /*****************************************************************************
    # * Copyright (c) 2019, Palo Alto Networks. All rights reserved.              *
    # *                                                                           *
    # * This Software is the property of Palo Alto Networks. The Software and all *
    # * accompanying documentation are copyrighted.                               *
    # *****************************************************************************/
    #
    # Copyright 2019 Palo Alto Networks
    #
    # Licensed under the Apache License, Version 2.0 (the "License");
    # you may not use this file except in compliance with the License.
    # You may obtain a copy of the License at
    #
    #   http://www.apache.org/licenses/LICENSE-2.0
    #
    # Unless required by applicable law or agreed to in writing, software
    # distributed under the License is distributed on an "AS IS" BASIS,
    # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    # See the License for the specific language governing permissions and
    # limitations under the License.
    
    
    # Author: Justin Harris <jharris@paloaltonetworks.com>

FUNCTIONS
    createBGPTunnelIpTable(tableName)
        Updates BgpTunnelIpPool table with  attributes IpSegment, N1T1, N1T2, N2T1, N2T2 and Available=YES
    
    createDbtable_lambda_handler(event, context)
        Creates the Dynamodb table used for VPN connection tracking and IP allocation
        :param event:
        :param context:
        :return:

DATA
    logger = <RootLogger root (INFO)>

FILE
    /Users/jharris/Documents/PycharmProjects/wwce/aws-cft/transitgateway-demo-v2/lambda-src/autoscale/createDbTable.py


