![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/AzureStealth.png?raw=true "AzureStealth")  
  
**Discover the most privileged users in the target Azure environments - including the stealthy Azure Shadow Admins.**  
With the AzureStealth’s scanning results - blue and red teamers will discover who are the users with the most sensitive and risky permissions.  
Potential attackers are hunting for those users and the defensive teams must make sure these privileged users are well secured - have strong, rotated and safety stored credentials, have MFA enabled, being monitored carefully, etc.  
  
Remember that we cannot protect the things we don’t aware of, and AzureStealth will help in the complex mission of discovereing the most privileged Azure users - including the straight-forward admins and the stealthy shadow admins that could easily escalate their privileges and become full admins as well.

# Quick Start to AzureStealth
AzureStealth is PowerShell script that uses the free **Azure's PowerShell Module**, you can download in advance:  
### How To Install Azure PowerShell Modules:  
Guide for installing Azure "AZ" PowerShell Module:  
https://docs.microsoft.com/en-us/powershell/azure/install-az-ps  
Guide for installing Azure "AzureAD" PowerShell Module (you need this in addtion to the az module):  
https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2  
  
If you local admin use the following PowerShell command:  
      Install-Module -Name Az -AllowClobber  
      Install-Module AzureAD -AllowClobber  
Else:  
    Install-Module -Name Az -AllowClobber -Scope CurrentUser  
    Install-Module AzureAD -AllowClobber -Scope CurrentUser  
  
### How To Run AzureStealth:  
First, download/sync locally the script file AzureStealth.ps1  
Go to the script folder.  
Run the following commands:  
```
    (1) Import-Module .\AzureStealth.ps1 -Force     (load the scan)  
    (2) Scan-AzureAdmins                            (start the AzureStealth scan)  
Optional:  
    (-) Scan-AzureAdmins -UseCurrentCred            (if you used Azure PowerShell in the past, it uses the current cached Azure credentials)  
    (-) Scan-AzureAdmins -GetPrivilegedUserPhotos   (if you want to focus only on the privileged Azure users, you can also get their photo (if they have profile photos))  
```  
### Run AzyreStealth Directly From The Azure Built-In CloudShell:  
You can load and run the scan directly from GitHub use(PowerShell command):  
```
    (1) IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AzureStealth/AzureStealth.ps1')  
    (2) Scan-AzureAdmins  
```
   
   
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
  






*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*##*#*#
  
# AzureStealth - Discover the most privileged users in Azure and secure\target them  
  
Written by: Asaf Hecht ([@Hechtov](https://twitter.com/Hechtov))   
More Updates on Twitter   
  
*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*##*#*#
  
#### HOW TO INSTALL AZURE POWERSHELL MODULE:

Guide for installing Azure AZ PowerShell Module:  
https://docs.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-1.4.0
  
If local admin (PowerShell command):  
    Install-Module -Name Az -AllowClobber
Else:  
    Install-Module -Name Az -AllowClobber -Scope CurrentUser  
  
*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*##*#*#

#### HOW TO RUN AZURESTEALTH SCAN:
  
First, download/sync locally the script file AzureStealth.ps1  
Go to the script folder.  
Run the following commands:  
    (1) Import-Module .\AzureStealth.ps1 -Force     (load the scan)  
    (2) Scan-AzureAdmins                            (start the AzureStealth scan)  
Optional:  
    (-) Scan-AzureAdmins -UseCurrentCred            (if you used Azure PowerShell in the past, it uses the current cached Azure credentials)  
    (-) Scan-AzureAdmins -GetPrivilegedUserPhotos   (if you want to focus only on the privileged Azure users, you can also get their photo (if they have profile photos))  


#### RUN AZURESTEALTH DIRECTLY FROM GITHUB:
Option for direct loading the scan from GitHub (PowerShell command):  
    (1) IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AzureStealth/AzureStealth.ps1')  
    (2) Scan-AzureAdmins  

*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*##*#*#
