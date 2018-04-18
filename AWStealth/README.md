![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/AWStealthLogo.png "AWStealth")  
  
**Discovers the most privileged entities in the scanned AWS environments - including AWS Shadow Admins.**  
With the AWStealth’s scanning results - organizations will know what users, groups and roles have sensitive and risky permissions.  
Potential attackers are hunting those kind of entities. The defensive teams must make sure these privileged entities are well secured - have strong, rotated and safety stored credentials, have MFA enabled, are monitored carefully and so on.  
Remember that we cannot protect the things we don’t know, and AWStealth will help to discover the most privileged entities - the straight-forward admins and the unique stealthy shadow entities that could also easily escalate privileges and become full admins.

# Quick Start to AWStealth
SkyArk runs in PowerShell - and uses the free **AWS's PowerShell Module**, you can download "AWS Tools for Windows PowerShell" in advance:  
https://aws.amazon.com/powershell/  
[Direct download link](http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi)  
The tool could also prompt you and automatically install the AWS PowerShell module for you.
  
Open PowerShell in SkyArk folder with running scripts permission:  
"powershell -ExecutionPolicy Bypass -NoProfile"
  
**If you want to use only AWStealth from SkyArk tool:**
```
1. Import-Module .\AWStealth.ps1 -force
```
**Perform AWStealth scan:**
```
2. Scan-AWShadowAdmins -accesskeyid [AccessKeyID] -secretkey [SecretAccessKey] -defaultregion [AWS-region]
Example:
Scan-AWShadowAdmins -accesskeyid AKIAIKYBE12345HDS -secretkey pdcWZR6Mdsffsdf9ub3j/dnhxRh1d -defaultregion us-east-1
```

# Permissions for AWStealth - ReadOnly 
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
  
