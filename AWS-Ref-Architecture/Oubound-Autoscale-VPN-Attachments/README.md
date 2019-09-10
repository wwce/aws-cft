# AWS Transit Gateway Outbound Autoscale

Deploys Firewalls into an Autoscale group for securing connections to the internet

Prerequisites
1) Existing Transit Gateway 
2) Existing Transit Gateway Route table that the VPNs will be associated with
3) At least one spoke VPC route table that the VPN routes will be propagated to.  The route table must be tagged with the key value pair
Key = Propagation Value = NS

![alt_text](https://github.com/wwce/aws-cft/blob/master/transitgateway-demo-v2/documentation/images/TGW-Direct-Attach.png)

The bootstrap init.cfg file has "interface swap" enabled so the management interface is bound to eth1 and the untrust interface is bound to eth0

Nat 

The default account for the firewalls is

panadmin/Pal0Alt0123!


# Support Policy: Community-Supported
The code and templates in this repository are released under an as-is, best effort, support policy. These scripts should viewed as community supported and Palo Alto Networks will contribute our expertise as and when possible. We do not provide technical support or help in using or troubleshooting the components of the project through our normal support options such as Palo Alto Networks support teams, or ASC (Authorized Support Centers) partners and backline support options. The underlying product used (the VM-Series firewall) by the scripts or templates are still supported, but the support is only for the product functionality and not for help in deploying or using the template or script itself. Unless explicitly tagged, all projects or work posted in our GitHub repository (at https://github.com/PaloAltoNetworks) or sites other than our official Downloads page on https://support.paloaltonetworks.com are provided under the best effort policy.

