## VPC Attached VM-Series Attached to Existing Transit Gateway
This build is an adaptation of the [East-West-VPC-Attachments](https://github.com/wwce/aws-cft/tree/master/AWS-Ref-Architecture/East-West-VPC-Attachments) to work function with AWS Transit Gateway without creating spoke VPCs.

### Overview
<p align="center">
<img src="https://raw.githubusercontent.com/wwce/aws-cft/master/Direct-Attach-FW-Existing-TGW/images/vpc-attached-fw.png">
</p>

### Requirements
* An existing Transit Gateway
* An existing Transit Gateway route table for the Security-VPC attachment
* S3 Bucket for VM-Series bootstrap
* S3 Bucket for Lambda code


### How to Deploy
1.  Follow the guide for the direct attach firewalls substituing the lambda files and CFT template file)
(https://github.com/wwce/aws-cft/blob/master/AWS-Ref-Architecture/East-West-VPC-Attachments/documentation/AWS_TGW_Direct_Attach_deployment_guide-v2.pdf)
2.  Follow the **guide.pdf** for additional instructions.  


## Support Policy
The guide in this directory and accompanied files are released under an as-is, best effort, support policy. These scripts should be seen as community supported and Palo Alto Networks will contribute our expertise as and when possible. We do not provide technical support or help in using or troubleshooting the components of the project through our normal support options such as Palo Alto Networks support teams, or ASC (Authorized Support Centers) partners and backline support options. The underlying product used (the VM-Series firewall) by the scripts or templates are still supported, but the support is only for the product functionality and not for help in deploying or using the template or script itself.
Unless explicitly tagged, all projects or work posted in our GitHub repository (at https://github.com/PaloAltoNetworks) or sites other than our official Downloads page on https://support.paloaltonetworks.com are provided under the best effort policy.
