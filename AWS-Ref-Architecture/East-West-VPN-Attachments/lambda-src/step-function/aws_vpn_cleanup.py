import boto3
import logging
import requests
import json
logger = logging.getLogger()
logger.setLevel(logging.INFO)
import xml.etree.ElementTree as ET
import urllib
import ssl
import time
ec2_client = boto3.client('ec2', region_name = 'eu-west-1')
from pprint import pprint

def delete_cgw(cgwId, DryRun=False):
    try:
        response = ec2_client.delete_customer_gateway(
            CustomerGatewayId=cgwId,
            DryRun=DryRun
        )
        logger.info('Deleted cgw connection {}'.format(cgwId))
        return True
    except Exception as e:
        logger.info('Got error {} deleting cgw'.format(e))
        return False

def get_cgws():
    gateways = []
    cgws = ec2_client.describe_customer_gateways(Filters = [{'Name': 'bgp-asn','Values': ['65003']}],DryRun=False)
    if len(cgws.get('CustomerGateways')) > 0:
        gateways =  cgws.get('CustomerGateways')
        return gateways
    return gateways

def get_vpn_connections():

    vpn_ids = []
    attachments = ec2_client.describe_transit_gateway_attachments(Filters=
                                                                  [{'Name': 'resource-type', 'Values': ['vpn']},
                                                                   {'Name': 'state', 'Values': ['available','pending']}])
    attachment_list = attachments.get('TransitGatewayAttachments')
    if len(attachment_list) > 0:
        for vpn_attachment in attachment_list:
            if vpn_attachment.get('ResourceId'):
                vpn_ids.append(vpn_attachment)
        return vpn_ids
    else:
        logger.info('Found no vpn attachments to delete')
        return vpn_ids

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

def panEditConfig(hostname, api_key, xpath, element):
    """
    Builds a request object and then Calls makeApiCall with request object.
    :param hostname: IP address of the firewall
    :param api_key:
    :param xpath: xpath of the configuration we wish to modify
    :param element: element that we wish to modify
    :return:  Returns the firewall response
    """
    logger.info("Updating edit config with xpath \n{} and element \n{} ".format(xpath, element))

    data = {
        'type': 'config',
        'action': 'edit',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    response = makeApiCall(hostname, data)

    return response


def makeApiCall(hostname, data):
    """
    Makes the API call to the firewall interface.  We turn off certificate checking before making the API call.
    Returns the API response from the firewall.
    :param hostname:
    :param data:
    :return: Expected response
    <response status="success">
        <result>
            <![CDATA[yes\n]]>
        </result>
    </response>
    """

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # No certificate check
    ctx.verify_mode = ssl.CERT_NONE
    url = "https://" + hostname + "/api"
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')
    return urllib.request.urlopen(url, data=encoded_data, context=ctx).read()

def get_tgw_vpn_attachment_data(resource_id):
    Region = 'eu-west-1'
    attachment_id = ''
    response = 0
    attachment_count = 0
    while (attachment_count == 0):
        try:
            ec2_client = boto3.client('ec2', region_name=Region)
            response = ec2_client.describe_transit_gateway_attachments(
                TransitGatewayAttachmentIds=[],
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [
                            str(resource_id),
                        ]
                    },
                ],
                MaxResults=123,
                DryRun=False
            )
            logger.info(
                'Got response {} looking for vpn attachmentid from resourceid {}'.format(response, resource_id))
            attachment_count = len(response['TransitGatewayAttachments'])
            if attachment_count > 0:
                state = response['TransitGatewayAttachments'][0].get('State')
                logger.info('Attachment state is {}'.format(state))
                break
            else:
                logger.info('Attachment count is zero')
        except Exception as e:
            time.sleep(5)
            print('{}'.format(e))
    return response['TransitGatewayAttachments'][0]

def create_vpn_association(attachment_id, tgw_route_table_id):
    try:
        response = ec2_client.associate_transit_gateway_route_table(
            TransitGatewayRouteTableId=tgw_route_table_id,
            TransitGatewayAttachmentId=attachment_id,
            DryRun=False
        )
        return True
    except Exception as e:
        logger.info('Got vpn association error'.format(e))
        return False


def create_vpn_propagation(attachment_id, tgw_route_table_id):
    try:
        response1 = ec2_client.enable_transit_gateway_route_table_propagation(
            TransitGatewayRouteTableId=tgw_route_table_id,
            TransitGatewayAttachmentId=attachment_id,
            DryRun=False
        )
        return True
    except Exception as e:
        logger.info('Got vpn propagation error'.format(e))
        return False



if __name__ == '__main__':
    import boto3
    import requests
    tgws = []
    table_list = ec2_client.describe_transit_gateway_route_tables(Filters = [
           {'Name':'tag:Propagate', 'Values':['EW']}
          ])
    tables = table_list.get('TransitGatewayRouteTables')
    for table in tables:
        tgws.append(table.get('TransitGatewayRouteTableId'))
    attachments = get_vpn_connections()
    for attachment in attachments:
        logger.info('Setting propagation for attachment {}'.format(attachment.get('TransitGatewayAttachmentId')))
        [create_vpn_propagation(attachment.get('TransitGatewayAttachmentId'), tgwrt) for tgwrt in tgws]


    tgw_route_table_id = 'tgw-rtb-0ffaaa359d2b369f1'

    #
    #
    attachments = get_vpn_connections()
    for attachment in attachments:
        logger.info('Setting propagation for attachment {}'.format(attachment.get('TransitGatewayAttachmentId')))
        [create_vpn_propagation(attachment.get('TransitGatewayAttachmentId'), tgwrt) for tgwrt in tgws]

    cgws = get_cgws()
    [delete_cgw(cgw.get('CustomerGatewayId')) for cgw in cgws]
    vpns = get_vpn_connections()
    [delete_vpn_connection(vpn.get('ResourceId')) for vpn in vpns]