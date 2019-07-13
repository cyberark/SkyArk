<#

######################################################################################################
#                                                                                                    #
#                                                                                                    #
#   SkyArk - help you to discover, assess and secure the most privileged entities in Azure and AWS   #
#                                                                                                    #
#                                                                                                    #
######################################################################################################
#                                                                                                    #
#                                                                                                    #
#                                  Written by: Asaf Hecht (@Hechtov)                                 #
#                                             CyberArk Labs                                          #
#                                      Future updates via Twitter                                    #
#                                                                                                    #
#                                                                                                    #
######################################################################################################

Currently it has two modules: AWStealth & AWStrace - check them out.

New modules to come - you are welcome to share feedback and suggest ideas.

################################################

Versions Notes:

Version 0.1 - 15.3.18
Version 0.2 - 10.4.18 - added the new AWStealth scan - discover the most privileged entities in AWS
Version 1.0 - RSA USA conference publication (19.4.18)
Version 1.1 - New version for AWStealth, with new summary report in a simple txt file 
version 2.0 - 13.7.19 added the new AzureStealth scan - discover the most privileged users in Azure

#>


$SkyArkVersion = "v2.0"

$AWStealth = @"
------------------------------------------------------------------------- 
   
        .d8888b.  888                      d8888         888      
       d88P  Y88b 888                     d88888         888      
       Y88b.      888                    d88P888         888      
        "Y888b.   888  888 888  888     d88P 888 888d888 888  888 
           "Y88b. 888 .88P 888  888    d88P  888 888P"   888 .88P 
             "888 888888K  888  888   d88P   888 888     888888K  
       Y88b  d88P 888 "88b Y88b 888  d8888888888 888     888 "88b 
        "Y8888P"  888  888  "Y88888 d88P     888 888     888  888 
                              888                               
                        Y8b d88P                               
                         "Y88P"                                   
"@                                   

$Author = @"
------------------------------------------------------------------------- 

                    Author: Asaf Hecht - @Hechtov
                            CyberArk Labs
                     Future updates via Twitter

-------------------------------------------------------------------------

"@


Write-Host $AWStealth
Write-Host "`n                  ***   Welcome to SkyArk $SkyArkVersion   ***`n"
Write-Host "          Cool cloud security project to help you around :)`n"
Write-Host "`nThe two main scanning modules are: AWStealth & AzureStealth"
Write-Host "Check them out and discover the most privileged entities in the target AWS and Azure`n"
Write-Host "New modules to come - you are welcome to share feedback and suggest ideas`n"
Write-Host $Author


Write-Host "`nChoose the scanning module you want to run with the following commands:"
Write-Host "  (1) Start-AWStealth"
Write-Host "  (2) Start-AzureStealth`n"


# Check for the AWS module
function Check-AWSmodule {
    # Search for AWS powerShell module
    try {
        $AWSModule = Get-AWSPowerShellVersion
    }
    catch {
        try {
            Write-Host "[+] Trying to import the AWS PowerShell module"
            Import-Module "AWSPowerShell"
            $testAWSModule = Get-AWSPowerShellVersion
        }
        catch {
            Write-Host "The AWS's PowerShell module is not available on your machine - the tool can install it for you:" -ForegroundColor Yellow
            $PowerShellVersion = $PSVersionTable.PSVersion.Major
            if ($PowerShellVersion -ge 5) {
                Write-Host "Installing AWSPowerShell module for the current user..."
                Install-Module AWSPowerShell -Scope CurrentUser -Force
                Import-Module "AWSPowerShell"
            }
            else {
                Write-Warning "You use PowerShell version $testAWSModule. PS could not automatically install the AWS module. Consider upgrade to PS version 5+ or download AWSPowerShell module from the official site:"
                Write-Warning "https://aws.amazon.com/powershell/"
                Return
            }
        }
        try {
            $testAWSModule = Get-AWSPowerShellVersion
            if ($testAWSModule) {
                Write-Host "[+] Good, AWS PowerShell module was loaded successfully"
            }
        }
        catch {
            Write-Host "Encountered an error with AWS's PowerShell module - please make sure it's indeed installed on your machine - and try again." -ForegroundColor red
            Write-Host "Check the official download page:`n    https://aws.amazon.com/powershell/`nOr use the direct download link:`n    http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi" -ForegroundColor Yellow
            Return
        }
    }
}


# Function to start the AWStealth scan
function Start-AWStealth {
    # Check the AWS module
    Write-Host "Checking for the AWS PowerShell module"
    Check-AWSmodule
    # Import AWStealth and AWStrace
    Write-Host "Importing the scanning module with: `"Import-Module `".\AWStealth\AWStealth.ps1`" -force`" command" -ForegroundColor Green
    Import-Module ".\AWStealth\AWStealth.ps1" -force > $null
    Write-Host "Starting the scan with: `"Scan-AWShadowAdmins`" command`n" -ForegroundColor Green
    Scan-AWShadowAdmins
}


# Function to start the AzureStealth scan
function Start-AzureStealth {
    Write-Host "Importing the scanning module with: `"Import-Module `".\AzureStealth\AzureStealth.ps1`" -force `" command" -ForegroundColor Green
    Import-Module ".\AzureStealth\AzureStealth.ps1" -force
    Write-Host "Starting the scan with: `"Scan-AzureAdmins`" command`n" -ForegroundColor Green
    Scan-AzureAdmins
}
