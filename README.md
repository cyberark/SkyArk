![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/SkyArkLogo2.png "SkyArk")  
SkyArk is a cloud security project with two helpful sub-modules - AWStealth and AWStrace.

# The Main Goal:
To help the cloud community in the effort of making cloud environments more secure.  
SkyArk currently focuses on mitigating the new threat of Cloud Shadow Admins, and helps organizations to discover, validate and protect cloud privileged entities.  
Stealthy and undercover cloud admins may reside in every public cloud platform and the tool at this time helps mitigating the risk in AWS.  
**In defensive/pentest/risk assessment procedures - make sure to address the threat and validate that those privileged entities are indeed well secured.**  


# Background:
SkyArk tool is published as part of our presented research at RSA USA 2018 - on Cloud Shadow Admins:  
https://www.rsaconference.com/videos/quick-look-sneak-your-way-to-cloud-persistenceshadow-admins-are-here-to-stay
  
The research focuses on the new uprising threat of Cloud Shadow Admins - how attackers can find and abuse non-trivial and so called “limited” permissions to still make it through and escalate their privileges and become full cloud admins.  
  
Furthermore, attackers can easily use those tricky specific permissions to hide stealthy admin entities that will wait for them as an undercover persistence technique. We started researching this threat in AWS following its great popularity and later on, we will continue to other cloud vendors as well.

More details are available in the "Cloud Shadow Admins" blog post:  
https://www.cyberark.com/threat-research-blog/cloud-shadow-admin-threat-10-permissions-protect/  

# Tool Description
SkyArk currently contains two modules:
-	**AWSteatlh**:  
**Discovers the most privileged entities in the scanned AWS environments - including AWS Shadow Admins.**  
With the AWStealth’s scanning results - organizations will know what users, groups and roles have sensitive and risky permissions.  
We also encourage organizations to scan their environments from time to time and search for suspicious deviations in their privileged entities list.  
**Potential attackers are hunting those kind of entities. The defensive teams must make sure these privileged entities are well secured - have strong, rotated and safety stored credentials, have MFA enabled and monitored carefully.**   
Remember that we cannot protect the things we don’t know, and AWStealth will help to discover the most privileged entities - the straight-forward admins and the unique stealthy shadow entities that could also easily escalate privileges and become full admins.  
-	**AWStrace**:  
**Analyzes AWS CloudTrail Logs - the module provides new valuable insights from CloudTrail logs.**  
It especially prioritizes risky sensitive IAM actions that potential attackers might use as part of their malicious actions as AWS Shadow Admins.  
The module analyzes the log files and produces informative csv result file with important details on each executed action in the evaluated environment.  
Security teams can use the results files to investigate sensitive actions, discover the entities that took those actions and reveal additional valuable details on each executed and logged action.  
  
# Quick Start  
SkyArk runs in PowerShell - and uses the free **AWS's PowerShell Module**:  
https://aws.amazon.com/powershell/  
If you have PS version 5+, the tool will prompt you and could automatically install the AWS PowerShell module for you. Otherwise, you can download "AWS Tools for Windows PowerShell" in advance:  
[Direct download link](http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi)  
   
Open PowerShell in SkyArk folder with running scripts permission:  
"powershell -ExecutionPolicy Bypass -NoProfile"
  
**Start and import SkyArk:**
```
1. Import-Module .\SkyArk.ps1 -force
```
**Perform AWStealth scan:**
```
2. Scan-AWShadowAdmins -accesskeyid [AccessKeyID] -secretkey [SecretAccessKey] -defaultregion [AWS-region]
Example:
Scan-AWShadowAdmins -accesskeyid AKIAIKYBE12345HDS -secretkey pdcWZR6Mdsffsdf9ub3j/dnhxRh1d -defaultregion us-east-1
```
**Perform AWStrace analysis:**
```
3. Download-CloudTrailLogFiles -AccessKeyID [AccessKeyID]  -SecretKey [SecretAccessKey] -DefaultRegion [AWS-region] -TrailBucketName [CloutTrail-S3bucket] -BucketKeyPrefix [A-Folder-Prefix-To-The-Trail's-Logs]
Example:
Download-CloudTrailLogFiles -AccessKeyID AKIAIKYBE12345HDS -SecretKey pdcWZR6Mdsffsdf9ub3j/dnhxRh1d -DefaultRegion "us-east-1" -TrailBucketName "cloudtrail-bucketname" -BucketKeyPrefix "AWSLogs/412345678910/CloudTrail/us-east-1/2018/03/08"

4. Analyze-CloudTrailLogFiles
```
  
# Permissions for SkyArk - ReadOnly

**Permissions policy for AWStealth**:  
The built in "SecurityAudit" Job function.  
Or Read-Only permissions over the IAM:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*"
            ],
            "Resource": "*"
        }
    ]
}
```
  
**Permissions policy for AWStrace**:  
Read-Only for the CloudTrail's S3 bucket - to download and analyze the log files
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Resource": "arn:aws:s3:::*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::cloudtrail-bucketname"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:Get*",
                "s3:List*",
                "s3:Copy*"
            ],
            "Resource": "arn:aws:s3:::cloudtrail-bucketname/*"
        }
    ]
}
```

# Share Your Thoughts And Feedback  
Asaf Hecht ([@Hechtov](https://twitter.com/Hechtov)) and CyberArk Labs
