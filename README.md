
![alt text](https://github.com/Hechtov/Photos/blob/master/SkyArk/SkyArkLogo2.png "SkyArk")  

### SkyArk is a cloud security project with two main scanning modules:  
 1.  **AzureStealth**  - Scans Azure environments   
 2.  **AWStealth**  - Scan AWS environments   
  
### These two scanning modules will discover the most privileged entities in the target AWS and Azure.  

# The Main Goal - Discover The Most Privileged Cloud Users
SkyArk currently focuses on mitigating the new threat of Cloud Shadow Admins, and helps organizations to discover, assess and protect cloud privileged entities.  
Stealthy and undercover cloud admins may reside in every public cloud platform and SkyArk helps mitigating the risk in AWS and Azure.  
**In defensive/pentest/risk assessment procedures - make sure to address the threat and validate that those privileged entities are indeed well secured.**  


# Background:
SkyArk deals with the new uprising threat of Cloud Shadow Admins - how attackers can find and abuse non-trivial and so-called “limited” permissions to still make it through and escalate their privileges and become full cloud admins.  
Furthermore, attackers can easily use those tricky specific permissions to hide stealthy admin entities that will wait for them as an undercover persistence technique.  
  
SkyArk was initially published as part of our research on the threat of AWS Shadow Admins, this research was presented at RSA USA 2018 conference.  
The AWS Shadow Admins blog post:  
https://www.cyberark.com/threat-research-blog/cloud-shadow-admin-threat-10-permissions-protect/  
The recording of the RSA talk:  
https://www.rsaconference.com/videos/sneak-your-way-to-cloud-persistenceshadow-admins-are-here-to-stay  
  
About a year later, we added the AzureStealth scan to SkyArk for mitigating the Shadow Admins threat in Azure!  
  
# Tool Description
SkyArk currently contains two main scanning modules **AWStealth** and **AzureStealth**.  
With the scanning results - organizations can discover the entities (users, groups and roles) who have the most sensitive and risky permissions.  
In addition, we also encourage organizations to scan their environments from time to time and search for suspicious deviations in their privileged entities list.  
**Potential attackers are hunting for those users and the defensive teams should make sure these privileged users are well secured - have strong, rotated and safety stored credentials, have MFA enabled, being monitored carefully, etc.**   
Remember that we cannot protect the things we don’t aware of, and SkyArk helps in the complex mission of discovering the most privileged cloud entities - including the straight-forward admins and also the stealthy shadow admins that could easily escalate their privileges and become full admins as well.  
  
### 1. AzureStealth Scan
**Discover the most privileged users in the scanned Azure environment - including the Azure Shadow Admins.**
  
**How To Run AzureStealth**  
The full details are in the AzureStealth's Readme file:  
[https://github.com/cyberark/SkyArk/blob/master/AzureStealth/README.md](https://github.com/cyberark/SkyArk/blob/master/AzureStealth/README.md)  
In short:
1.  Download/sync locally the SkyArk project
2.  Open PowerShell in the SkyArk folder with the permission to run scripts:  
    "powershell -ExecutionPolicy Bypass -NoProfile"
3.  Run the following commands:
```
(1) Import-Module .\SkyArk.ps1 -force
(2) Start-AzureStealth
```
 AzureStealth needs only Read-Only permissions over the scanned Azure Directory (Tenant) and Subscription.  
 *You can also run the scan easily from within the Azure Portal by using the built-in CloudShell:  
 ```
    (1) IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AzureStealth/AzureStealth.ps1')  
    (2) Scan-AzureAdmins  
```  
 **AzureStealth DEMO:**  
 ![Demo](https://github.com/Hechtov/Photos/blob/master/SkyArk/AzureStealth%20-%20short%20demo1.gif?raw=true)  
   
  ### 2. AWStealth Scan
**Discover the most privileged entities in the scanned AWS environment - including the Azure Shadow Admins.**
  
**How To Run AWStealth**  
The full details are in the AWStealth's Readme file:  
[https://github.com/cyberark/SkyArk/tree/master/AWStealth](https://github.com/cyberark/SkyArk/tree/master/AWStealth)  
In short:  
1.  Download/sync locally the SkyArk project
2.  Open PowerShell in the SkyArk folder with the permission to run scripts:  
    "powershell -ExecutionPolicy Bypass -NoProfile"
3.  Run the following commands:
```
(1) Import-Module .\SkyArk.ps1 -force
(2) Start-AWStealth
```
 AWStealth needs only Read-Only permissions over the IAM service of the scanned AWS environment.
    
**AWStealth DEMO:**  
![Demo](https://github.com/Hechtov/Photos/blob/master/SkyArk/SkyArk-shortVideo.gif)  
  
  ### 3. SkyArk includes more small sub-modules for playing around in the cloud security field
An example for such a sub-module is **AWStrace** module.  
**AWStrace - analyzes AWS CloudTrail Logs and can provide new valuable insights from CloudTrail logs.**  
It especially prioritizes risky sensitive IAM actions that potential attackers might use as part of their malicious actions as AWS Shadow Admins.  
The module analyzes the log files and produces informative csv result file with important details on each executed action in the tested environment.  
Security teams can use the results files to investigate sensitive actions, discover the entities that took those actions and reveal additional valuable details on each executed and logged action.  
  
# Quick Start  
Take a look at the Readme files of the scanning modules:  
AzureStealth - [https://github.com/cyberark/SkyArk/blob/master/AzureStealth/README.md](https://github.com/cyberark/SkyArk/blob/master/AzureStealth/README.md)  
AWStealth - [https://github.com/cyberark/SkyArk/blob/master/AWStealth/README.md](https://github.com/cyberark/SkyArk/blob/master/AWStealth/README.md)

# Share Your Thoughts And Feedback  
Asaf Hecht ([@Hechtov](https://twitter.com/Hechtov)) and CyberArk Labs 
  
**More coverage on the uprising Cloud Shadow Admins threat:**  
  
ThreatPost: https://threatpost.com/cloud-credentials-new-attack-surface-for-old-problem/131304/  
TechTarget\SearchCloudSecurity: https://searchcloudsecurity.techtarget.com/news/252439753/CyberArk-warns-of-shadow-admins-in-cloud-environments  
SecurityBoulevard: https://securityboulevard.com/2018/05/cyberark-shows-how-shadow-admins-can-be-created-in-cloud-environments/  
LastWatchDog: https://www.lastwatchdog.com/cyberark-shows-how-shadow-admins-can-be-created-in-cloud-environments/  
Byron Acohido's Podcast: https://soundcloud.com/byron-acohido/cloud-privileged-accounts-flaws-exposed  
