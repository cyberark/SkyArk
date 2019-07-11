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
