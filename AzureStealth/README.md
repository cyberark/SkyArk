![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/AzureStealth.png?raw=true "AzureStealth")  
  
**Discover the most privileged users in the target Azure environments - including the stealthy Azure Shadow Admins.**  
  
With the AzureStealth’s scanning results - blue and red teamers can discover who are the users with the most sensitive and risky permissions.  
Potential attackers are hunting for those users and the defensive teams must make sure these privileged users are well secured - have strong, rotated and safety stored credentials, have MFA enabled, being monitored carefully, etc.  
  
Remember that we cannot protect the things we aren't aware of, and AzureStealth helps in the complex mission of discovering the most privileged Azure users - including the straight-forward admins and also the stealthy shadow admins that could easily escalate their privileges and become full admins as well.
  
### AzureStealth DEMO: 
  
![Demo](https://github.com/Hechtov/Photos/blob/master/SkyArk/AzureStealth%20-%20short%20demo1.gif?raw=true)  
  
# Quick Start to AzureStealth
AzureStealth is a PowerShell script that uses the free **Azure's PowerShell Modules**, it requires PowerShell version 5.1+ (that comes by default in Windows 10 and for the other OSs there is an available update).  
  
### How To Install Azure PowerShell Modules:  
Guide for installing Azure "AZ" PowerShell Module:  
https://docs.microsoft.com/en-us/powershell/azure/install-az-ps  
Guide for installing Azure "AzureAD" PowerShell Module (you need this in addtion to the az module):  
https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2  
In short, for installing the modules just use the following PowerShell commands: 
```
If you are local admin on the machine:  
    Install-Module -Name Az -AllowClobber  
    Install-Module AzureAD -AllowClobber  
Else:  
    Install-Module -Name Az -AllowClobber -Scope CurrentUser  
    Install-Module AzureAD -AllowClobber -Scope CurrentUser  
```
  
### How To Run AzureStealth:  
1) Download/sync locally the script file AzureStealth.ps1    
2) Open PowerShell in the AzureStealth folder with the permission to run scripts:  
   "powershell -ExecutionPolicy Bypass -NoProfile"  
3) Run the following commands:  
```
    (1) Import-Module .\AzureStealth.ps1 -Force     (load the scan)  
    (2) Scan-AzureAdmins                            (start the AzureStealth scan)  
```
4) Optional commands:
```
    (-) Scan-AzureAdmins -UseCurrentCred            (if you used Azure PowerShell in the past, it uses the current cached Azure credentials)  
    (-) Scan-AzureAdmins -GetPrivilegedUserPhotos   (if you want to focus only on the privileged Azure users, you can also get their photos (if they have profile photos))  
``` 
5) If you encounter with Azure connection errors, you can manualy connect to Azure and then run the scan:
```
    (1) Import-Module .\AzureStealth.ps1 -Force  
    (2) Connect-AzAccount
    (2) Connect-AzureAD
    (4) Scan-AzureAdmins -UseCurrentCred 
```
  
### How To Run AzureStealth Easily From The Azure Built-In CloudShell:  
Guide for PowerShell in Azure CloudShell:  
https://docs.microsoft.com/en-us/azure/cloud-shell/quickstart-powershell  
In short, here is a useful screenshot from the guide:  
  
![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/Azure%20CloudShell%20Guide%20-%203.jpg?raw=true "Azure Cloud Shell")  
  
**Using PowerShell \ CloudShell - you can load and run the scan directly from GitHub, simply use the following commands:**  
```
    (1) IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AzureStealth/AzureStealth.ps1')  
    (2) Scan-AzureAdmins  
```
  
### Permissions for running the AzureStealth scan:
AzureStealth only needs Read-Only permissions over the Azure Directory and Subscriptions that you wish to scan.  
To note:  
By default, all the Azure users have read permissions over the Azure Directory (Azure Tenant) they are part of.  
You can also run the scan with users who don't have Azure Subscription permissions at all, in this case, the scan will still detect the Azure Directory's Admins, but not the Subscription's Admins that cannot be queried.  
  
  
## Share Your Thoughts And Feedback  
Asaf Hecht ([@Hechtov](https://twitter.com/Hechtov)) and CyberArk Labs 
  
