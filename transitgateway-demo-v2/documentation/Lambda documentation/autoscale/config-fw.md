Help on module config-fw:

NAME
    config-fw

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
    
    
    Config-fw is called by add_eni lambda once the firewall interfaces have been created.
    This function handles the VPN creation and deletion and the tracking of IP allocations in DynamoDb

CLASSES
    builtins.Exception(builtins.BaseException)
        FWNotUpException
    builtins.dict(builtins.object)
        XmlDictConfig
    builtins.list(builtins.object)
        XmlListConfig
    
    class FWNotUpException(builtins.Exception)
     |  Common base class for all non-exit exceptions.
     |  
     |  Method resolution order:
     |      FWNotUpException
     |      builtins.Exception
     |      builtins.BaseException
     |      builtins.object
     |  
     |  Data descriptors defined here:
     |  
     |  __weakref__
     |      list of weak references to the object (if defined)
     |  
     |  ----------------------------------------------------------------------
     |  Methods inherited from builtins.Exception:
     |  
     |  __init__(self, /, *args, **kwargs)
     |      Initialize self.  See help(type(self)) for accurate signature.
     |  
     |  __new__(*args, **kwargs) from builtins.type
     |      Create and return a new object.  See help(type) for accurate signature.
     |  
     |  ----------------------------------------------------------------------
     |  Methods inherited from builtins.BaseException:
     |  
     |  __delattr__(self, name, /)
     |      Implement delattr(self, name).
     |  
     |  __getattribute__(self, name, /)
     |      Return getattr(self, name).
     |  
     |  __reduce__(...)
     |      helper for pickle
     |  
     |  __repr__(self, /)
     |      Return repr(self).
     |  
     |  __setattr__(self, name, value, /)
     |      Implement setattr(self, name, value).
     |  
     |  __setstate__(...)
     |  
     |  __str__(self, /)
     |      Return str(self).
     |  
     |  with_traceback(...)
     |      Exception.with_traceback(tb) --
     |      set self.__traceback__ to tb and return self.
     |  
     |  ----------------------------------------------------------------------
     |  Data descriptors inherited from builtins.BaseException:
     |  
     |  __cause__
     |      exception cause
     |  
     |  __context__
     |      exception context
     |  
     |  __dict__
     |  
     |  __suppress_context__
     |  
     |  __traceback__
     |  
     |  args
    
    class XmlDictConfig(builtins.dict)
     |  Example usage:
     |  
     |  >>> tree = ElementTree.parse('your_file.xml')
     |  >>> root = tree.getroot()
     |  >>> xmldict = XmlDictConfig(root)
     |  
     |  Or, if you want to use an XML string:
     |  
     |  >>> root = ElementTree.XML(xml_string)
     |  >>> xmldict = XmlDictConfig(root)
     |  
     |  And then use xmldict for what it is... a dict.
     |  
     |  Method resolution order:
     |      XmlDictConfig
     |      builtins.dict
     |      builtins.object
     |  
     |  Methods defined here:
     |  
     |  __init__(self, parent_element)
     |      Initialize self.  See help(type(self)) for accurate signature.
     |  
     |  ----------------------------------------------------------------------
     |  Data descriptors defined here:
     |  
     |  __dict__
     |      dictionary for instance variables (if defined)
     |  
     |  __weakref__
     |      list of weak references to the object (if defined)
     |  
     |  ----------------------------------------------------------------------
     |  Methods inherited from builtins.dict:
     |  
     |  __contains__(self, key, /)
     |      True if D has a key k, else False.
     |  
     |  __delitem__(self, key, /)
     |      Delete self[key].
     |  
     |  __eq__(self, value, /)
     |      Return self==value.
     |  
     |  __ge__(self, value, /)
     |      Return self>=value.
     |  
     |  __getattribute__(self, name, /)
     |      Return getattr(self, name).
     |  
     |  __getitem__(...)
     |      x.__getitem__(y) <==> x[y]
     |  
     |  __gt__(self, value, /)
     |      Return self>value.
     |  
     |  __iter__(self, /)
     |      Implement iter(self).
     |  
     |  __le__(self, value, /)
     |      Return self<=value.
     |  
     |  __len__(self, /)
     |      Return len(self).
     |  
     |  __lt__(self, value, /)
     |      Return self<value.
     |  
     |  __ne__(self, value, /)
     |      Return self!=value.
     |  
     |  __new__(*args, **kwargs) from builtins.type
     |      Create and return a new object.  See help(type) for accurate signature.
     |  
     |  __repr__(self, /)
     |      Return repr(self).
     |  
     |  __setitem__(self, key, value, /)
     |      Set self[key] to value.
     |  
     |  __sizeof__(...)
     |      D.__sizeof__() -> size of D in memory, in bytes
     |  
     |  clear(...)
     |      D.clear() -> None.  Remove all items from D.
     |  
     |  copy(...)
     |      D.copy() -> a shallow copy of D
     |  
     |  fromkeys(iterable, value=None, /) from builtins.type
     |      Returns a new dict with keys from iterable and values equal to value.
     |  
     |  get(...)
     |      D.get(k[,d]) -> D[k] if k in D, else d.  d defaults to None.
     |  
     |  items(...)
     |      D.items() -> a set-like object providing a view on D's items
     |  
     |  keys(...)
     |      D.keys() -> a set-like object providing a view on D's keys
     |  
     |  pop(...)
     |      D.pop(k[,d]) -> v, remove specified key and return the corresponding value.
     |      If key is not found, d is returned if given, otherwise KeyError is raised
     |  
     |  popitem(...)
     |      D.popitem() -> (k, v), remove and return some (key, value) pair as a
     |      2-tuple; but raise KeyError if D is empty.
     |  
     |  setdefault(...)
     |      D.setdefault(k[,d]) -> D.get(k,d), also set D[k]=d if k not in D
     |  
     |  update(...)
     |      D.update([E, ]**F) -> None.  Update D from dict/iterable E and F.
     |      If E is present and has a .keys() method, then does:  for k in E: D[k] = E[k]
     |      If E is present and lacks a .keys() method, then does:  for k, v in E: D[k] = v
     |      In either case, this is followed by: for k in F:  D[k] = F[k]
     |  
     |  values(...)
     |      D.values() -> an object providing a view on D's values
     |  
     |  ----------------------------------------------------------------------
     |  Data and other attributes inherited from builtins.dict:
     |  
     |  __hash__ = None
    
    class XmlListConfig(builtins.list)
     |  list() -> new empty list
     |  list(iterable) -> new list initialized from iterable's items
     |  
     |  Method resolution order:
     |      XmlListConfig
     |      builtins.list
     |      builtins.object
     |  
     |  Methods defined here:
     |  
     |  __init__(self, aList)
     |      Initialize self.  See help(type(self)) for accurate signature.
     |  
     |  ----------------------------------------------------------------------
     |  Data descriptors defined here:
     |  
     |  __dict__
     |      dictionary for instance variables (if defined)
     |  
     |  __weakref__
     |      list of weak references to the object (if defined)
     |  
     |  ----------------------------------------------------------------------
     |  Methods inherited from builtins.list:
     |  
     |  __add__(self, value, /)
     |      Return self+value.
     |  
     |  __contains__(self, key, /)
     |      Return key in self.
     |  
     |  __delitem__(self, key, /)
     |      Delete self[key].
     |  
     |  __eq__(self, value, /)
     |      Return self==value.
     |  
     |  __ge__(self, value, /)
     |      Return self>=value.
     |  
     |  __getattribute__(self, name, /)
     |      Return getattr(self, name).
     |  
     |  __getitem__(...)
     |      x.__getitem__(y) <==> x[y]
     |  
     |  __gt__(self, value, /)
     |      Return self>value.
     |  
     |  __iadd__(self, value, /)
     |      Implement self+=value.
     |  
     |  __imul__(self, value, /)
     |      Implement self*=value.
     |  
     |  __iter__(self, /)
     |      Implement iter(self).
     |  
     |  __le__(self, value, /)
     |      Return self<=value.
     |  
     |  __len__(self, /)
     |      Return len(self).
     |  
     |  __lt__(self, value, /)
     |      Return self<value.
     |  
     |  __mul__(self, value, /)
     |      Return self*value.n
     |  
     |  __ne__(self, value, /)
     |      Return self!=value.
     |  
     |  __new__(*args, **kwargs) from builtins.type
     |      Create and return a new object.  See help(type) for accurate signature.
     |  
     |  __repr__(self, /)
     |      Return repr(self).
     |  
     |  __reversed__(...)
     |      L.__reversed__() -- return a reverse iterator over the list
     |  
     |  __rmul__(self, value, /)
     |      Return self*value.
     |  
     |  __setitem__(self, key, value, /)
     |      Set self[key] to value.
     |  
     |  __sizeof__(...)
     |      L.__sizeof__() -- size of L in memory, in bytes
     |  
     |  append(...)
     |      L.append(object) -> None -- append object to end
     |  
     |  clear(...)
     |      L.clear() -> None -- remove all items from L
     |  
     |  copy(...)
     |      L.copy() -> list -- a shallow copy of L
     |  
     |  count(...)
     |      L.count(value) -> integer -- return number of occurrences of value
     |  
     |  extend(...)
     |      L.extend(iterable) -> None -- extend list by appending elements from the iterable
     |  
     |  index(...)
     |      L.index(value, [start, [stop]]) -> integer -- return first index of value.
     |      Raises ValueError if the value is not present.
     |  
     |  insert(...)
     |      L.insert(index, object) -- insert object before index
     |  
     |  pop(...)
     |      L.pop([index]) -> item -- remove and return item at index (default last).
     |      Raises IndexError if list is empty or index is out of range.
     |  
     |  remove(...)
     |      L.remove(value) -> None -- remove first occurrence of value.
     |      Raises ValueError if the value is not present.
     |  
     |  reverse(...)
     |      L.reverse() -- reverse *IN PLACE*
     |  
     |  sort(...)
     |      L.sort(key=None, reverse=False) -> None -- stable sort *IN PLACE*
     |  
     |  ----------------------------------------------------------------------
     |  Data and other attributes inherited from builtins.list:
     |  
     |  __hash__ = None

FUNCTIONS
    add_inf_to_router(hostname, api_key, tunnelInfId, virtualRouter='default')
        Function to add an interface to a Virtual-Router
    
    add_inf_to_zone(hostname, api_key, zone, tunnelInfId)
        Function to add an interface to a Zone
    
    add_to_peer_group(hostname, api_key, virtualRouter, peerGroup, peerName, tunnel_int_ip, tunnelInfId, tunnel_int_peer_ip, peerAsn)
        Add IPSec tunnel interface to a BGP Peer group
    
    check_cgw(awsRegion, fwUntrustPubIP, n2Eip)
    
    config_deactivate_license_apikey(hostname, api_key, license_api_key)
        Function to configure DeactivateLicense API Key
        This function is used during initialization of a PA Node and requires internet connectivity
    
    config_fw_lambda_handler(event, context)
        Called after add_eni lambda handler.
        Called directly via a lambda_client.invoke action
        :param event:
            event = {
                'lambda_bucket_name': lambda_bucket_name,
                'event-name': 'gw-terminate/gw-launch',
                'instance-id': ec2_instanceid,
                'asg_name': asg_name,
                'asg_hookname': lifecycle_hook_name
            }
        :param context:
        
        Handles the configuration of the VPN connection between the firewall and AWS CGW.
        
        :return:
    
    config_gw(fwUntrustPubIP, gwMgmtPubIp, fwUntrustPrivIP, fwUntrustSubnet, pa_asn, Region, cgw1Tag, table_name, tgwId, username, password, bucketName, tag, instanceId)
        Called during a Lifecycle hook CREATE event.
        Handles the allocation of IPs, creation of cgw and VPN config and configuration of the firewall to connect to the
        CGW
        :param fwUntrustPubIP:
        :param gwMgmtPubIp:
        :param fwUntrustPrivIP:
        :param fwUntrustSubnet:
        :param pa_asn:
        :param Region:
        :param cgw1Tag:
        :param table_name:
        :param tgwId:
        :param username:
        :param password:
        :param bucketName:
        :param tag:
        :param instanceId:
        :return:
        Main function that will configure the firewall and VPN connections.
    
    create_cgw(cgwIp, cgwAsn, Region, tag)
    
    create_ike_gateway(hostname, api_key, name, psk, ikeProfile, pa_dmz_inf, peerIp)
        Function to create IKE Gateway
    
    create_ipsec_tunnel(hostname, api_key, tunnelName, ikeName, ipsecProfile, tunnelInfId)
        Function to create IPSec tunnel
    
    create_ipsec_tunnel_Inf(hostname, api_key, tunnelInfId, tunnelInfIp='ip/30', mtu=1427)
        Function to create tunnel interface to use with IPsec
    
    create_vpn_connection_upload_to_s3(Region, tgwId, cgwId, tunnelOneCidr, tunnelTwoCidr, tag, bucketName, assumeRoleArn=None)
        Creates VPN connection and upload the VPN configuration to the S3 bucket
    
    deactivate_license(hostname, api_key)
        Function to Deactivate / remove license associated with a PA node
        This function is used during decommision of a server and requires internet connectivity
    
    delete_cgw(cgwId, DryRun=False)
    
    delete_vpn_connection(VpnConnectionId, DryRun=False)
    
    done(success, context, asg_message)
        Method to send a successful response to an
        ASG lifecycle action.
        
        :param success:
        :param context:
        :param asg_message:
        :return:
    
    editIpObject(hostname, api_key, name, value)
        Function to edit/update an existing IP Address object on a PA Node
    
    find_classic_subnet(kwargs)
        call describe_subnets passing kwargs.  Returns the first subnet in the list of subnets.
    
    find_subnet_by_block(cidr)
        find a subnet by CIDR block. Sets a Filter based on the subnet CIDR and calls find_classic_subnet()
    
    find_subnet_by_id(subnet_id)
        find a subnet by subnet ID. Sets a Filter based on the subnet_id and calls find_classic_subnet()
        :param subnet_id:
    
    getApiKey(hostname, username, password)
        Generate the API key from username / password
    
    getFirewallStatus(fwIP, api_key)
    
    get_available_bgp_tunnel_ip_pool(tableName, instanceId, paGroupName)
    
    get_cidr(subnetId)
        :param subnetId:
        :return: returns subnet cidr as string x.x.x.x/x
        Get the cidr block from a subnetId
    
    get_free_tunnel_inf_ids(tunnelNames, no_of_ids=2)
        Function to return two unused tunnel ids within range 1-9999 and not already used by names in the list 'tunnelNames'
    
    get_gw_ip(cidr)
    
    get_tunnel_units(hostname, api_key)
        Function to fet all tunnel interfaces and return it as a list. This is used to find unused tunnel interface id while creating a new one.
    
    loadVpnConfigFromS3(bucketName, vpnId)
        Function to read AWS-IPSec configuration (xml format) from an S3 bucket, parse it return important data as a dictionary
        Returns Dict
        <class 'dict'>:
        {'id': 'vpn-05574d274b6385444',
        'pa_dmz_ip': '99.80.124.137',
        'pa_asn': '65000',
        'vgw_asn': '64512',
        't1_ike_peer': '63.35.84.61',
        't1_int_ip': '169.254.0.118',
        't1_int_peer_ip': '169.254.0.117',
        't1_ike_psk': 'Da7SFsg6mNSH5uKCoA_ShWjRUBzjDqLh',
        't2_ike_peer': '63.35.142.140',
        't2_int_ip': '169.254.0.114',
        't2_int_peer_ip': '169.254.0.113',
        't2_ike_psk': 'EpdPi5Qrqdt8ENE.8oB3q4AdaFshjOMT'}
    
    make_api_call(hostname, data)
        Function to make API call
    
    pa_configure_vpn(hostname, api_key, vpnConfDict, peerGroup, ikeProfile='default', ipsecProfile='default', pa_dmz_inf='ethernet1/1', virtualRouter='default', zone='UNTRUST')
        Function to configure IPSec vpn on a PA Node
    
    pa_group_configure_vpn(api_key, paGroup, vpnConfigBucket, N1VpnId, N2VpnId, ikeProfile='default', ipsecProfile='default', pa_dmz_inf='eth1', virtualRouter='default', zone='UNTRUST')
        Function to configure VPN with a PAGroup and a VPC. Each node in the PAGroup will establish a VPN with the VPC.
    
    pa_initialize(hostname, api_key, pa_dmz_priv_ip, pa_dmz_pub_ip, pa_asn, pa_dmz_subnet_gw, SubnetCidr, license_api_key='')
        Handles the majority of the firewall configuration once the dataplane is available
        Updates the following
        Static route for the trust interface route tables
        Sets the BGP ASN
        Sets the VPN tunnel parameters
        Sets the tunnel interface IP addresses
        :param hostname:
        :param api_key:
        :param pa_dmz_priv_ip:
        :param pa_dmz_pub_ip:
        :param pa_asn:
        :param pa_dmz_subnet_gw:
        :param SubnetCidr:
        :param license_api_key:
        :return:
    
    pan_commit(hostname, api_key, message='')
        Function to commit configuration changes
    
    pan_edit_config(hostname, api_key, xpath, element)
        Function to make API call to "edit" (or modify) a specific configuration
        Note: Some properties need "set" method instead of "edit" to work
    
    pan_get_config(hostname, api_key, xpath)
        Function to make API call to "get" (or read or list) a specific configuration
    
    pan_op_cmd(hostname, api_key, cmd)
        Function to make an 'op' call to execute a command
    
    pan_rollback(hostname, api_key, username='admin')
        Function to rollback uncommited changes
    
    pan_set_config(hostname, api_key, xpath, element)
        Function to make API call to "set" a specific configuration
    
    release_ips(tablename, instanceId)
        When the Firewall is terminated we release the IP addresses from the IP pool and release them in the
        Dynamodb table.
        :param tablename:
        :param instanceId:
        :return:
    
    retrieve_fw_ip(instance_id)
        Retrieve the IP of the Instance
        
        @param instance_id The id of the instance
        @type ```str```
    
    send_request(call)
        Handles sending requests to API
        :param call: url
        :return: Retruns result of call. Will return response for codes between 200 and 400.
                 If 200 response code is required check value in response
    
    terminate(value)
    
    terminate_gw(message, tablename)
        Called in response to a Lifecycle hook TERMINATE action.
        
        :param message:
        message = {
                'lambda_bucket_name': lambda_bucket_name,
                'event-name': 'gw-terminate',
                'instance-id': ec2_instanceid,
                'asg_name': asg_name,
                'asg_hookname': lifecycle_hook_name
            }
        :param tablename: BGP Tunnel info
        :return:
        
        Handles the deletion of the VPN connection and the CGW. Releases the Tunnel IPs back to the pool in dynamodb
    
    updateVpcTable(tableName, data, status)
        Updates the Transit VpcTable with VpcId, Node1VpnId, Node2VpnId, Region, IpSegment and CurrentStatus
    
    update_bgp_table(tableName, vpnId, cgwId, instanceId)
        When the resources are allocated to the VPN connection we track them in the DynamoDb table.
        
        :param tableName:
        :param vpnId:
        :param cgwId:
        :param instanceId:
        :return:
    
    update_bgp_tunnel_ip_pool(ipSegment, tableConn, instanceId, paGroupName, Dryrun=False)
    
    update_default_route_nexthop(hostname, api_key, subnetGateway, virtualRouter='default')
        Function to update default route virtual router
    
    update_routerId_asn(hostname, api_key, routerId, routerAsn, virtualRouter='default')
        Function to edit/update BGP RourterID(Public IP) and ASN on a PA Node
    
    update_tgw_firewall(vpc_summary_route, fw_trust_ip, fw_untrust_ip, api_key, trustAZ_subnet_cidr, fw_untrust_int)
        Parse the repsonse from makeApiCall()
        :param vpc_summary_route:
        :param fw_trust_ip:
        :param fw_untrust_ip:
        :param api_key:
        :param trustAZ_subnet_cidr:
        :param fw_untrust_int:
        :return:
        If we see the string 'yes' in the repsonse we will assume that the firewall is up and continue with the firewall
        configuration
    
    uploadObjectToS3(vpnConfiguration, bucketName, assumeRoleArn=None)
        Uploads an object(VPN Conf file) to S3 bucket

DATA
    PortalMgmtIp = ''
    Region = 'eu-west-1'
    api_key = ''
    asg = <botocore.client.AutoScaling object>
    asg_hookname = ''
    asg_name = ''
    dynamodb = dynamodb.ServiceResource()
    ec2 = ec2.ServiceResource()
    ec2_client = <botocore.client.EC2 object>
    events_client = <botocore.client.CloudWatchEvents object>
    fqdn = ''
    fwUntrustPubIP = ''
    gcontext = ''
    gwDpInterfaceId = ''
    gwMgmtPubIp = ''
    hostname = ''
    iam_client = <botocore.client.IAM object>
    instanceId = ''
    job_id = ''
    lambda_client = <botocore.client.Lambda object>
    lambda_function_arn = ''
    logger = <RootLogger root (INFO)>
    this_func_name = ''

FILE
    /Users/jharris/Documents/PycharmProjects/wwce/aws-cft/transitgateway-demo-v2/lambda-src/autoscale/config-fw.py


