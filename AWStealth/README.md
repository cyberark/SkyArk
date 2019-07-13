![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/AWStealthLogo.png "AWStealth")  
  
**Discover the most privileged entities in the target AWS environments - including the stealthy AWS Shadow Admins.**  
  
With the AWStealth’s scanning results - blue and red teamers can discover who are the users with the most sensitive and risky permissions.  
Potential attackers are hunting for those users and the defensive teams must make sure these privileged users are well secured - have strong, rotated and safety stored credentials, have MFA enabled, being monitored carefully, etc.  
  
Remember that we cannot protect the things we don’t aware of, and AzureStealth helps in the complex mission of discovering the most privileged AWS entities - including the straight-forward admins and also the stealthy shadow admins that could easily escalate their privileges and become full admins as well.
  
# Quick Start to AWStealth
SkyArk runs in PowerShell - and uses the free **AWS's PowerShell Module**, you can download "AWS Tools for Windows PowerShell" in advance:  
https://aws.amazon.com/powershell/  
[Direct download link](http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi)  
If you use PowerShell version 5 or above - The tool would prompt you and could automatically install the AWS PowerShell module for you.
  
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
  
**AWStealth DEMO:**  
![Demo](https://github.com/Hechtov/Photos/blob/master/SkyArk/SkyArk-shortVideo.gif)  
  
