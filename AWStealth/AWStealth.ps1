<#

#################################################################
#                                                               #  
#  AWStealth -  Detect Shadow Admins in AWS cloud environments  #
#                                                               #
#################################################################
#                                                               #
#                                                               #
#               Written by: Asaf Hecht (@Hechtov)               #
#                    More Updates on Twitter                    #
#                                                               #
#                                                               #
#################################################################


Welcome to SkyArk's AWStealth module.

It's time to discover the most privileged AWS entities

#################################################################

Versions Notes:
 
Version 0.1: 26.2.18
version 0.2: 4.3.18
version 0.3: 8.3.18
version 0.4: 13.3.18
Version 1.0: RSA USA conference publication (19.4.18)
Version 1.1: 23.5.19 - Added the final summary report in a txt format
version 1.2: 13.7.19 - Modified as part of SkyArk and the new AzureStealth scan
version 1.3: 26.8.19 - Added a few more filtering rules
version 1.4: 20.1.20 - Added the ability to run the scan with Session Tokens (thanks @stefankober for the help)
version 1.5: 16.8.20 - Fixed an error in the AWS PowerShell module validation
version 1.6: 18.8.20 - Minor fixes
#>


$AWStealthVersion = "v1.6"

$AWStealth = @"
------------------------------------------------------
      __          _______ _             _ _   _     
     /\ \        / / ____| |           | | | | |    
    /  \ \  /\  / / (___ | |_ ___  __ _| | |_| |__  
   / /\ \ \/  \/ / \___ \| __/ _ \/ _`` | | __| '_ \ 
  / ____ \  /\  /  ____) | ||  __/ (_| | | |_| | | |
 /_/    \_\/  \/  |_____/ \__\___|\__,_|_|\__|_| |_|
                                                    
------------------------------------------------------
"@                                   

$Author = @"
          Author:  Asaf Hecht - @Hechtov
                  CyberArk Labs
            Future updates via Twitter

------------------------------------------------------
"@


Write-Output $AWStealth
Write-Output "***   Welcome to SkyArk's AWStealth module $AWStealthVersion   ***`n"
Write-Output "It's time to discover the most privileged AWS entities`n"
Write-Output $Author

try {
    $isAwsPowerShellModuleLoaded = (Get-Module) | Where-Object {$_.Name -eq "AWSPowerShell"} 
    if (-not $isAwsPowerShellModuleLoaded){
        Write-Host "[+] Searching for the AWS PowerShell module..."
    }
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
            Write-Warning "You use PowerShell version $testAWSModule. PS could not automatically install the AWS module. Consider upgrade to PS version 5+ or download AWSPowerShell module from the officןal site:"
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


# Function to load the AWS credentials and create a temporary profile
function Load-AWScred {
    Param (
        # The secret Key ID to use
        [string]
        $AccessKeyID,
        # The secret Key to use
        [string]
        $SecretKey,
        # The session token to use (optional)
        [string]
        $sessionToken,
        # The default AWS region of the scanned environment
        [string]
        $DefaultRegion,
        # A name of an existing profile to use
        [string]
        $ProfileName,
        # The name for the temporary AWS profile
        [string]
        $tempProfile
    )

    # Load the AWS credentials
    if ($ProfileName) {
        Set-AWSCredential -ProfileName $ProfileName
    }
    else {
        if (-not $AccessKeyID) {
            $AccessKeyID = read-host "What is the AWS AccessKeyID?"
        }
        if (-not $SecretKey) {
            $SecretKey = read-host "What is the AWS SecretKey?"
        }
        if (-not $SessionToken) {
            $SessionToken = read-host "Optional: What is the AWS SessionToken (hit Enter if none)?"
        }
        if ($SessionToken) {
            Write-Host "SessionToken was set"
            Set-AWSCredential -AccessKey $AccessKeyID -SecretKey $SecretKey -SessionToken $SessionToken -StoreAs $tempProfile
        }
        else {
            Write-Host "SessionToken wasn't set"
            Set-AWSCredential -AccessKey $AccessKeyID -SecretKey $SecretKey -StoreAs $tempProfile
        }
        Set-AWSCredential -ProfileName $tempProfile
    }
    if (-not $DefaultRegion) {
    # Removed the following because IAM is cross region service, and currently the tool only query the IAM [18/8/20]
    #   $DefaultRegion = read-host "What is your AWS default region (e.g. `"us-east-1`")?"
    	$DefaultRegion = "us-east-1"
    }
    Set-DefaultAWSRegion -Region $DefaultRegion
    
    if ($SessionToken) {
        $currentUser = Get-STSCallerIdentity
        $currentUserName = $currentUser.Arn
    }
    else {
        $currentUser = Get-IAMUser
        $currentUserName = $currentUser.UserName
    }
    Write-Host "`n[+] Loaded AWS credentials - $tempProfile [EntityName=$currentUserName]"
}


function Mark-privilegedPolicy {
    Param (
        [string]
        $privilegeType,
        [string]
        $newPrivilegeType
    )   
    $isPrivileged = $true
    
    if ($privilegeType -eq "") {
        $privilegeType = $newPrivilegeType
    }
    else {
        $privilegeType += ",$newPrivilegeType"
    }

    return $isPrivileged, $privilegeType
}

# Function for detecting privileged permission policies
function Check-PrivilegedPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [PSCustomObject]
        $policy,
        [string]
        $policyName
    )
    $privilegeType = ""
    $isPrivileged = $false
    $policyCondition = "noCondition"

    # First, checking for the built-in privileged job functions policies:
    #   Privileged built-in job functions:
    #   AdministratorAccess - Provides full access to AWS services and resources - FullAWSAdmin
    #   Billing - Grants permissions for billing and cost management. This includes viewing account ussage and viewing and modifying budgets and payment methods.
    #   NetworkAdministrator - Grants full access permissions to AWS services and actions required to set up and configure AWS network resources.
    #   DatabaseAdministrator - Grants full access permissions to AWS services and actions required to set up and configure AWS database services.
    #   PowerUserAccess - Provides full access to AWS services and resources, but does not allow management of Users and groups.
    #   SystemAdministrator - Grants full access permissions necessary for resources required for application and development operations.
    
    if ($policyName -eq "AdministratorAccess") {
        $isPrivileged = $true
        $privilegeType = "FullAWSAdmin"
    }
    elseif ($policyName -eq "Billing") {
        $isPrivileged = $true
        $privilegeType = "BillingAdministrator"
    }
    elseif ($policyName -eq "NetworkAdministrator") {
        $isPrivileged = $true
        $privilegeType = "NetworkAdministrator"
    }
    elseif ($policyName -eq "PowerUserAccess") {
        $isPrivileged = $true
        $privilegeType = "PowerUserAccess"
    }
    elseif ($policyName -eq "SystemAdministrator") {
        $isPrivileged = $true
        $privilegeType = "SystemAdministrator"
    }
    elseif ($policyName -eq "DatabaseAdministrator") {
        $isPrivileged = $true
        $privilegeType = "DatabaseAdministrator"
    }
    else {
        # to add the privilege checking logic function
        $policy.statement | foreach {
            if ($_.effect -eq "Allow") {
                # check if the policy contains a condition
                if ($_.Condition) {
                    $conditionExists = $true
                    $conditionObject = $_.Condition
                    $conditionValue = ""
                    $conditionObject.PSObject.Properties | foreach-object {
                        $conditionValue += [string]$_.value
                    }
                    if ($policyCondition -eq "noCondition") {
                        $policyCondition = $conditionValue
                    }
                    else {
                        $policyCondition += $conditionValue
                    }
                }
                else {
                    $policyCondition = "noCondition"
                }
                $broadResource = $false
                if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*") -or ($_ -eq "arn:aws:iam::*:group/*") `
                    -or ($_ -eq "arn:aws:iam::*:role/*") -or ($_ -eq "arn:aws:iam::*:user/*") -or ($_ -eq "arn:aws:iam::*:policy/*") `
                    -or ($_ -eq "arn:aws:iam::*:instance-profile/*") -or ($_ -eq "arn:aws:ec2:*:*:instance/*") `
                    -or ($_ -eq "arn:aws:lambda:*:*:function:*") -or ($_ -eq "arn:aws:glue:*:*:catalog/*") -or ($_ -eq "arn:aws:cloudformation:*:*:stack/*/*") `
                    -or ($_ -eq "arn:aws:codestar:*:*:project/*") -or ($_ -eq "arn:aws:codestar:*:*:notebook-instance/*")}) {
                    # check for Shadow Admins' policies and search for other privileged entities
                    #############################################################################################################################################################(1)
                    # */* full cloud admin senario
                    if ($_.Action | ? {($_ -eq "*")}) {
                        if ($_.Resource | ? {($_ -eq "*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullAWSAdmin"
                        }
                    }
                    #############################################################################################################################################################(2)
                    # check for the sensitive "CreateAccessKey" permission to other entities
                    # example for a dangerous usage with AWS CLI: "aws iam create-access-key --user-name administrator"
                    if ($_.Action | ? {($_ -eq "iam:CreateAccessKey")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")}) {
                            #$isPrivileged = $true
                            #$privilegeType += ",ShadowCreateAccessKeys"
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCreateAccessKeys"
                        }
                    }
                    #############################################################################################################################################################(3)
                    # check for the sensitive "Attach*Policy" permissions to other entities
                    # example for a dangerous usage with AWS CLI: "aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --user-name userAttachPolicy"
                    if ($_.Action | ? {($_ -eq "iam:AttachUserPolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowAttachUserPolicy"
                        }
                    }
                    if ($_.Action | ? {($_ -eq "iam:AttachGroupPolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:group/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowAttachGroupPolicy"
                        }
                    }
                    if ($_.Action | ? {($_ -eq "iam:AttachRolePolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:role/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowAttachRolePolicy"
                        }
                    }
                    #############################################################################################################################################################(4)
                    # check for the sensitive "Put*Policy" permissions to other entities
                    # example for a dangerous usage with AWS CLI: aws iam put-user-policy --user-name shadowPutPolicy --policy-name AdminPolicy --policy-document "file:///Work/AWS/AWShadowAdmins/Demo/AdminPermissionPolicy.json"
                    if ($_.Action | ? {($_ -eq "iam:PutUserPolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowPutUserPolicy"
                        }
                    }
                    if ($_.Action | ? {($_ -eq "iam:PutGroupPolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:group/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowPutGroupPolicy"
                        }
                    }
                    if ($_.Action | ? {($_ -eq "iam:PutRolePolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:role/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowPutRolePolicy"
                        }
                    }
                    #############################################################################################################################################################(5)
                    # check for the sensitive "CreatePolicy" permissions to other entities
                    # example for a dangerous usage with AWS CLI: aws iam create-policy --policy-name my-read-only-policy --policy-document "file:///Work/AWS/AWShadowAdmins/Demo/AdminPermissionPolicy.json"
                    if ($_.Action | ? {($_ -eq "iam:CreatePolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:policy/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCreatePolicy"
                        }
                    }
                    #############################################################################################################################################################(6)
                    # check for the sensitive "UpdateLoginProfile" permissions to other entities
                    # example for a dangerous usage with AWS CLI: "aws iam update-login-profile --user-name ShadowTest --password Password123!"
                    if ($_.Action | ? {($_ -eq "iam:UpdateLoginProfile")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowUpdateLoginProfiles"
                        }
                    }
                    #############################################################################################################################################################(7)
                    # check for the sensitive "CreateLoginProfile" permissions to other entities
                    # example for a dangerous usage with AWS CLI: "aws iam create-login-profile --cli-input-json file:///Work/AWS/AWShadowAdmins/Demo/LoginProfile.json"
                    if ($_.Action | ? {($_ -eq "iam:CreateLoginProfile")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCreateLoginProfiles"
                        }
                    }
                    #############################################################################################################################################################(8)
                    # check for the sensitive "AddUserToGroup" permissions to other entities
                    # example for a dangerous usage with AWS CLI: "aws iam add-user-to-group --user-name Bob --group-name demoAdminsGroup"
                    if ($_.Action | ? {($_ -eq "iam:AddUserToGroup")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:group/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowAddUserToGroups"
                        }
                    }
                    #############################################################################################################################################################(9)
                    # check for the sensitive "CreatePolicyVersion" permissions to other entities
                    # example for a dangerous usage with AWS CLI: "aws iam create-policy-version --policy-arn arn:aws:iam::419890133200:policy/IAM-Read-Only --policy-document file:///Work/AWS/AWShadowAdmins/Demo/AdminPermissionPolicy.json --set-as-default"
                    if ($_.Action | ? {($_ -eq "iam:CreatePolicyVersion") -or ($_ -eq "iam:SetDefaultPolicyVersion")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:policy/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowSetPolicyVersions"
                        }
                    }
                    #############################################################################################################################################################(10)
                    # check for the sensitive "modifyInstanceProfile" permissions to other entities
                    # example for a dangerous usage with AWS CLI: 
                    # aws iam create-instance-profile --instance-profile-name shadowProfile
                    # aws iam add-role-to-instance-profile --role-name AdminRole --instance-profile-name shadowProfile (need the PassRole permission)
                    # aws ec2 associate-iam-instance-profile --instance-id i-003116a190790073d --iam-instance-profile Name=shadowProfile 
                    $permissionActions = $_.Action | ? {($_ -eq "iam:CreateInstanceProfile") -or ($_ -eq "iam:AddRoleToInstanceProfile") -or ($_ -eq "iam:PassRole") -or ($_ -eq "ec2:AssociateIamInstanceProfile")}
                    $permissionResources = $_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:role/*") -or ($_ -eq "arn:aws:iam::*:instance-profile/*") -or ($_ -eq "arn:aws:ec2:*:*:instance/*")}
                    if (($($permissionResources | Measure-Object).count -ge 1) -and ($permissionActions.count -ge 3)) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowModifyInstanceProfiles"
                    }
                    #############################################################################################################################################################(11)
                    # check for the sensitive "UpdateAssumeRolePolicy" permission 
                    # example for a dangerous usage with AWS CLI: "aws iam update-assume-role-policy --role-name shadowRole --policy-document file:///Work/AWS/AWShadowAdmins/Demo/RoleTrustPolicy.json"
                    if ($_.Action | ? {($_ -eq "iam:UpdateAssumeRolePolicy")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:role/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowUpdateAssumeRolePolicy"
                        }
                    }
                    #############################################################################################################################################################(12)
                    if ($_.Action | ? {($_ -eq "iam:*")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")-or ($_ -eq "arn:aws:iam::*:group/*")-or ($_ -eq "arn:aws:iam::*:role/*") -or ($_ -eq "arn:aws:iam::*:policy/*") -or ($_ -eq "arn:aws:iam::*:instance-profile/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullIAMadmin"
                        }
                    }
                    #############################################################################################################################################################(13)
                    if ($_.Action | ? {($_ -eq "s3:*")}) {
                        if ($_.Resource | ? {($_ -eq "*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullS3admin"
                        }
                    }
                    #############################################################################################################################################################(14)
                    if ($_.Action | ? {($_ -eq "ec2:*")}) {
                        if ($_.Resource | ? {($_ -eq "*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullEC2admin"
                        }
                    }
                    #############################################################################################################################################################(15)
                    if ($_.Action | ? {($_ -eq "kms:*")}) {
                        if ($_.Resource | ? {($_ -eq "*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullKMSadmin"
                        }
                    }
                    #############################################################################################################################################################(16)
                    if ($_.Action | ? {($_ -eq "sts:*")}) {
                        if ($_.Resource | ? {($_ -eq "*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullSTSadmin"
                        }
                    }
                    #############################################################################################################################################################(17)
                    if ($_.Action | ? {($_ -eq "Cloudformation:*")}) {
                        if ($_.Resource | ? {($_ -eq "*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullCloudformationAdmin"
                        }
                    }
                    #############################################################################################################################################################(18)
                    if ($_.Action | ? {($_ -eq "lambda:*")}) {
                        if ($_.Resource | ? {($_ -eq "*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullLambdaAdmin"
                        }
                    }
                    #############################################################################################################################################################(19)
                    if ($_.Action | ? {($_ -eq "iam:attach*")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")-or ($_ -eq "arn:aws:iam::*:group/*")-or ($_ -eq "arn:aws:iam::*:role/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMattachAdmin"
                        }
                    }
                    #############################################################################################################################################################(20)
                    if ($_.Action | ? {($_ -eq "iam:put*")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")-or ($_ -eq "arn:aws:iam::*:group/*")-or ($_ -eq "arn:aws:iam::*:role/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMputAdmin"
                        }
                    }
                    #############################################################################################################################################################(21)
                    if ($_.Action | ? {($_ -eq "iam:add*")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:group/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMaddAdmin"
                        }
                    }
                    #############################################################################################################################################################(22)
                    if ($_.Action | ? {($_ -eq "iam:create*")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:policy/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMcreateAdmin"
                        }
                    }
                    #############################################################################################################################################################(23)
                    if ($_.Action | ? {($_ -eq "iam:CreatePolicyVersion")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:policy/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCreatePolicyVersions"
                        }
                    }
                    #############################################################################################################################################################(24)
                    $permissionActions = $_.Action | ? {($_ -eq "iam:PassRole") -or ($_ -eq "ec2:RunInstances")}
                    if ($permissionActions.count -eq 2) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:ec2:*:*:instance/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowRunNewInstancesWithRoles"
                        }
                    }          
                    #############################################################################################################################################################(25)
                    # The following permissions scenarios were described by Rhino Security Labs:
                    # https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
                    # https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
                    # Thanks to the researcher Spencer Gietzen on those additional privilege esclation techniques.
                    #############################################################################################################################################################(26)
                    if ($_.Action | ? {($_ -eq "iam:PassRole")}){
                        # Passing a role to a new Lambda function, and invoke it
                        if ($_.Action | ? {($_ -eq "lambda:CreateFunction")}){
                            if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:lambda:*:*:function:*")}) {
                                if ($_.Action | ? {($_ -eq "iam:ambda:InvokeFunction") -or ($_ -eq "lambda:AddPermission") -or ($_ -eq "lambda:CreateEventSourceMapping")}) {
                                    $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowRunLambda"
                                }
                            }
                        }
                        # Passing a role to a Glue Development Endpoint
                        if ($_.Action | ? {($_ -eq "glue:CreateDevEndpoint")}){
                            if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:glue:*:*:catalog/*")}) {
                                $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowGlueDevEndpoint"
                            }
                        } 
                        # Passing a role to CloudFormation
                        if ($_.Action | ? {($_ -eq "cloudformation:CreateStack")}){
                            if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:cloudformation:*:*:stack/*/*")}) {
                                $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCloudFormation"
                            }
                        }
                        # Passing a role to Data Pipeline
                        $permissionActions = $_.Action | ? {($_ -eq "datapipeline:CreatePipeline") -or ($_ -eq "datapipeline:PutPipelineDefinition")}
                        if ($permissionActions.count -eq 2) {
                            if ($_.Resource | ? {($_ -eq "*")}) {
                                $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowDataPipeline"
                            }
                        }
                        # Passing a role to a new CodeStar project
                        if ($_.Action | ? {($_ -eq "codestar:CreateProject")}){
                            if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:codestar:*:*:project/*")}) {
                                $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCodeStar"
                            }
                        }
                        # Passing a role to a new SageMaker Jupyter notebook
                        $permissionActions = $_.Action | ? {($_ -eq "sagemaker:CreateNotebookInstance") -or ($_ -eq "sagemaker:CreatePresignedNotebookInstanceUrl")}
                        if ($permissionActions.count -eq 2) {
                            if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:codestar:*:*:notebook-instance/*")}) {
                                $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowSageMaker"
                            }
                        }
                    }

                    #############################################################################################################################################################(27)
                    # Updating the code of an existing Lambda function
                    if ($_.Action | ? {($_ -eq "lambda:UpdateFunctionCode")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:lambda:*:*:function:*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowUpdateLambda"
                        }
                    }
                    #############################################################################################################################################################(28)
                    # Updating an existing Glue Dev Endpoint
                    if ($_.Action | ? {($_ -eq "glue:UpdateDevEndpoint")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:glue:*:*:catalog/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowGlueUpdate"
                        }
                    }
                    #############################################################################################################################################################(29)
                    # Creating a CodeStar project from a template
                    if ($_.Action | ? {($_ -eq "codestar:CreateProjectFromTemplate")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:codestar:*:*:project/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCodeStar"
                        }
                    }
                    #############################################################################################################################################################(30)
                    # Creating a new CodeStar project and associating a team member
                    $permissionActions = $_.Action | ? {($_ -eq "codestar:CreateProject") -or ($_ -eq "codestar:AssociateTeamMember")}
                    if ($permissionActions.count -eq 2) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:codestar:*:*:project/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowCodeStar"
                        }
                    }
                    #############################################################################################################################################################(31)
                    # Adding a malicious Lambda layer to an existing Lambda function
                    if ($_.Action | ? {($_ -eq "lambda:UpdateFunctionConfiguration")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:codestar:*:*:function/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowAddLambda"
                        }
                    }
                    #############################################################################################################################################################(32)
                    # Gaining access to an existing SageMaker Jupyter notebook
                    if ($_.Action | ? {($_ -eq "sagemaker:CreatePresignedNotebookInstanceUrl")}) {
                        if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:codestar:*:*:notebook-instance/*")}) {
                            $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "ShadowSageMaker"
                        }
                    }
                    #############################################################################################################################################################
                }
            }
        }
    }

    return $isPrivileged, $privilegeType, $policyCondition
}


# Function for building the entities' information data-line, this is the structure of privilegedEntitiesDB 
function Build-EntityInfoLine {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [string]
        $entityType,
        [string]
        $policyType,
        [PSCustomObject]
        $entityObject,
        [string]
        $managedPolicyJsonStr,
        [string]
        $policyName,
        [string]
        $privilegeType,
        [string]
        $policyCondition
    )

    if ($entityType -eq "User") {
        $EntityName = $entityObject.UserName
        $entityArn = $entityObject.Arn
        $passwordLastUsed = [string]$entityObject.PasswordLastUsed
        if ($passwordLastUsed -eq "01/01/0001 00:00:00") {
            $passwordLastUsed = "Never"
        }
    }
    elseif ($entityType -eq "Group") {
        $EntityName = $entityObject.Group.GroupName
        $entityArn = $entityObject.Group.Arn
        if ($entityObject.Users) {
            $ofs = ','
            $groupMembers = [string]$entityObject.Users.UserName
        }
        else {
            $groupMembers = "EmptyGroup"
        }
    }
    elseif ($entityType -eq "Role") {
        $EntityName = $entityObject.RoleName
        $entityArn = $entityObject.Arn
        $AssumeRolePolicyDocumentStr = [System.Web.HttpUtility]::UrlDecode($entityObject.AssumeRolePolicyDocument)
    }
    if ($entityType -eq "User") {
        $MFAdetails = Get-IAMMFADevice -username $EntityName
        if ($MFAdetails) {
            $isMFAenable = $true
        }
        else {
            $isMFAenable = "NoMFA"
        }
    }
    else {
        $isMFAenable = "-"
    }

    $entityInfoLine = [PSCustomObject][ordered] @{
        EntityName        = [string]$EntityName
        EntityType        = [string]$entityType
        PrivilegeType     = [string]$privilegeType
        PolicyName        = [string]$policyName
        PolicyType        = [string]$policyType
        MFAenable         = [string]$isMFAenable
        policyCondition   = [string]$policyCondition
        GroupMembers      = [string]$groupMembers
        AssumeRolePolicyDocument = [string]$AssumeRolePolicyDocumentStr
        Arn               = [string]$entityArn
        PrivilegedPermissionPolicy  = [string]$managedPolicyJsonStr
    }

    return $entityInfoLine
}


# Function for detecting privileged managed permission policies
function Check-ManagedPolicies {

    # Lists all the managed policies that are available in your AWS account, including your own customer-defined managed policies and all AWS managed policies
    $managedPolicies = Get-IAMPolicyList -OnlyAttached $true
    $numManagedPolicies = $managedPolicies.Count
    Write-host "[+] Scanning managed policies"
    Write-host "Discovered", $numManagedPolicies, "managed policies, analysis in progress"
    $countEntities.add("ManagedPolicies", $numManagedPolicies)
    $managedPolicyCounter = 0

    # check every managed policy in the environment
    $managedPolicies | foreach {
        $managedPolicyCounter++
        $managedPolicyData = Get-IAMPolicyVersion -PolicyArn $_.Arn -VersionId $_.DefaultVersionId
        $managedPolicyStr = [System.Web.HttpUtility]::UrlDecode($managedPolicyData.Document)
        $managedPolicyJson = $managedPolicyStr | ConvertFrom-Json
        $isPolicyPrivileged, $privilegeType, $policyCondition = Check-PrivilegedPolicy -policy $managedPolicyJson -policyName $_.PolicyName
        if ($isPolicyPrivileged) {
            # Lists all IAM users, groups, and roles that the specified managed policy is attached to
            $versionAwsPowerShellModule = (Get-Module) | Where-Object {$_.Name -eq "AWSPowerShell"} | select Version
            # Use the new filter parameter of PolicyUsageFilter for elimnating the Permissions Boundaries from the API answer:
            if ($updatedAwsPowerShellModule) {
                $policyEntities = Get-IAMEntitiesForPolicy -PolicyArn $_.Arn -PolicyUsageFilter "PermissionsPolicy"
            }
            else {
                $policyEntities = Get-IAMEntitiesForPolicy -PolicyArn $_.Arn
            }
            $policyName = $_.PolicyName
            # analyze users
            $policyEntities.PolicyUsers | foreach {
                $userInfo = Get-IAMUser -UserName $_.UserName
                if ($privilegedEntitiesDB.contains($userInfo.Arn)) {
                    # add only the permission policy
                    $entityLine = $privilegedEntitiesDB[$userInfo.Arn]
                    $entityLine.PrivilegedPermissionPolicy += "`n+`n$managedPolicyStr"
                    $entityLine.PolicyName += ",$policyName"
                    $entityLine.PrivilegeType += ",$privilegeType"
                    $entityLine.policyCondition += ",$policyCondition"
                    $privilegedEntitiesDB[$userInfo.Arn] = $entityLine
                }
                else {
                    $entityLine = Build-EntityInfoLine -entityType "User" -policyType "ManagedPolicy" -entityObject $userInfo -managedPolicyJsonStr $managedPolicyStr -policyName $policyName -privilegeType $privilegeType -policyCondition $policyCondition              
                    $privilegedEntitiesDB.add($userInfo.Arn, $entityLine)                
                }
            }
            # analyze groups
            $policyEntities.PolicyGroups | foreach {
                # to do: add a cached db
                $groupInfo = Get-IAMGroup -GroupName $_.GroupName
                if ($privilegedEntitiesDB.contains($groupInfo.Group.Arn)) {
                    # add only the permission policy
                    $entityLine = $privilegedEntitiesDB[$groupInfo.Group.Arn]
                    $entityLine.PrivilegedPermissionPolicy += "`n+`n$managedPolicyStr"
                    $entityLine.PolicyName += ",$policyName"
                    $entityLine.PrivilegeType += ",$privilegeType"
                    $entityLine.policyCondition += ",$policyCondition"
                    $privilegedEntitiesDB[$groupInfo.Group.Arn] = $entityLine
                }
                else {
                    $entityLine = Build-EntityInfoLine -entityType "Group" -policyType "ManagedPolicy" -entityObject $groupInfo -managedPolicyJsonStr $managedPolicyStr -policyName $policyName -privilegeType $privilegeType -policyCondition $policyCondition                
                    $privilegedEntitiesDB.add($groupInfo.Group.Arn, $entityLine)
                    # insert the privileged users that are members of the privilege group
                    if ($($groupInfo.Users.UserName | Measure-Object).count -gt 0) {
                        $groupInfo.Users.UserName | foreach {
                            $userInfo = Get-IAMUser -UserName $_
                            $groupName = $groupInfo.Group.GroupName
                            if ($privilegedEntitiesDB.contains($userInfo.Arn)) {
                                # add only the permission policy
                                $entityLine = $privilegedEntitiesDB[$userInfo.Arn]
                                $entityLine.PrivilegedPermissionPolicy += "`n+`n$managedPolicyStr"
                                $entityLine.PolicyName += ",$policyName-Through`"$groupName`"Group"
                                $entityLine.PrivilegeType += ",$privilegeType"
                                $entityLine.policyCondition += ",$policyCondition"
                                $privilegedEntitiesDB[$userInfo.Arn] = $entityLine
                            }
                            else {
                                $entityLine = Build-EntityInfoLine -entityType "User" -policyType "ManagedPolicy" -entityObject $userInfo -managedPolicyJsonStr $managedPolicyStr -policyName $policyName -privilegeType $privilegeType -policyCondition $policyCondition
                                $entityLine.PolicyName += "-Through`"$groupName`"Group"                
                                $privilegedEntitiesDB.add($userInfo.Arn, $entityLine)                
                            }
                        }
                    }                
                }
            }
            # analyze roles
            $policyEntities.PolicyRoles | foreach {
                $roleInfo = Get-IAMRole -RoleName $_.RoleName
                if ($privilegedEntitiesDB.contains($roleInfo.Arn)) {
                    # add only the permission policy
                    $entityLine = $privilegedEntitiesDB[$roleInfo.Arn]
                    $entityLine.PrivilegedPermissionPolicy += "`n+`n$managedPolicyStr"
                    $entityLine.PolicyName += ",$policyName"
                    $entityLine.PrivilegeType += ",$privilegeType"
                    $entityLine.policyCondition += ",$policyCondition"
                    $privilegedEntitiesDB[$roleInfo.Arn] = $entityLine
                }
                else {
                    $entityLine = Build-EntityInfoLine -entityType "Role" -policyType "ManagedPolicy" -entityObject $roleInfo -managedPolicyJsonStr $managedPolicyStr -policyName $policyName -privilegeType $privilegeType -policyCondition $policyCondition               
                    $privilegedEntitiesDB.add($roleInfo.Arn, $entityLine)            
                }
            } 
        }
        try {
            $tenPrcs = [math]::round(($numManagedPolicies/10),0)
            if (($managedPolicyCounter % $tenPrcs) -eq 0){
                $prc = ([math]::round(($managedPolicyCounter/$numManagedPolicies),2)*100)
                Write-host "Status: finished $managedPolicyCounter managed policies, $prc% done"
            }
        }
        catch {
            Write-Verbose "Progress status is not available right now"
        }
    }
    Write-host "Status: finished with all the managed policies"

}

# Function for detecting privileged inline permission policies
function Check-InlinePolicies {

    Write-host "`n[+] Scanning inline policies"

    # analyze inline policies in users
    $inlineUserPoliciesCounter = 0
    $userCounter = 0
    $AWSusers = Get-IAMUserList
    Write-host "Analyzing" $AWSusers.count "users"
    $countEntities.add("Users", $AWSusers.count)
    $AWSusers | foreach {
        $userCounter++
        $userName = $_.UserName
        $inlineUserPolicy = Get-IAMUserPolicyList -UserName $userName
        if ($inlineUserPolicy) {
            $inlineUserPoliciesCounter += $($inlineUserPolicy| Measure-Object).count
            $inlineUserPolicy | foreach {
                $inlineUserPolicyData = Get-IAMUserPolicy -UserName $userName -PolicyName $_
                $inlineUserPolicyStr = [System.Web.HttpUtility]::UrlDecode($inlineUserPolicyData.PolicyDocument)
                #$inlineGroupPolicyJson = [System.Web.HttpUtility]::UrlDecode($inlineGroupPolicyData.Document)
                $inlineUserPolicyJson = $inlineUserPolicyStr | ConvertFrom-Json
                $isPolicyPrivileged, $privilegeType, $policyCondition = Check-PrivilegedPolicy -policy $inlineUserPolicyJson
                if ($isPolicyPrivileged) {
                    # to do: add a cached db
                    $userInfo = Get-IAMUser -UserName $UserName
                    if ($privilegedEntitiesDB.contains($userInfo.Arn)) {
                        # add only the permission policy
                        $entityLine = $privilegedEntitiesDB[$userInfo.Arn]
                        $entityLine.PrivilegedPermissionPolicy += "`n+`n$inlineUserPolicyStr"
                        $entityLine.PolicyType += "+InlinePolicy"
                        $entityLine.PolicyName += ",$_"
                        $entityLine.PrivilegeType += ",$privilegeType"
                        $entityLine.policyCondition += ",$policyCondition"
                        $privilegedEntitiesDB[$userInfo.Arn] = $entityLine
                    }
                    else {
                        $entityLine = Build-EntityInfoLine -entityType "User" -policyType "InlinePolicy" -entityObject $userInfo -managedPolicyJsonStr $inlineUserPolicyStr -policyName $_ -privilegeType $privilegeType -policyCondition $policyCondition               
                        $privilegedEntitiesDB.add($userInfo.Arn, $entityLine)                
                    }
                }
            }
        }
        try {
            $tenPrcs = [math]::round(($AWSusers.count/10),0)
            if (($userCounter % $tenPrcs) -eq 0){
                $prc = ([math]::round(($userCounter/$AWSusers.count),2)*100)
                Write-host "Status: finished $userCounter users, $prc% done"
            }
        }
        catch {
            Write-Verbose "Progress status is not available right now"
        }
    }

    # analyze inline policies in groups
    $inlineGroupPoliciesCounter = 0
    $groupCounter = 0
    $AWSgroups = Get-IAMGroupList
    Write-host "Analyzing" $AWSgroups.count "groups"
    $countEntities.add("Groups", $AWSgroups.count)
    $AWSgroups | foreach {
    $groupCounter++
        $GroupName = $_.GroupName
        # Get a list of the inline policies that are embedded in the specified group.
        $inlineGroupPolicy = Get-IAMGroupPolicyList -GroupName $GroupName 
        if ($inlineGroupPolicy) {
            $inlineGroupPoliciesCounter += $($inlineGroupPolicy | Measure-Object).count
            $inlineGroupPolicy | foreach {
                $inlineGroupPolicyData = Get-IAMGroupPolicy -GroupName $GroupName -PolicyName $_ 
                $inlineGroupPolicyStr = [System.Web.HttpUtility]::UrlDecode($inlineGroupPolicyData.PolicyDocument)
                $inlineGroupPolicyJson = $inlineGroupPolicyStr | ConvertFrom-Json
                $isPolicyPrivileged, $privilegeType, $policyCondition = Check-PrivilegedPolicy -policy $inlineGroupPolicyJson
                if ($isPolicyPrivileged) {
                    $groupInfo = Get-IAMGroup -GroupName $GroupName
                    $policyName = $_
                    if ($privilegedEntitiesDB.contains($groupInfo.Group.Arn)) {
                        # add only the permission policy
                        $entityLine = $privilegedEntitiesDB[$groupInfo.Group.Arn]
                        $entityLine.PrivilegedPermissionPolicy += "`n+`n$inlineGroupPolicyStr"
                        $entityLine.PolicyType += "+InlinePolicy"
                        $entityLine.PolicyName += ",$policyName"
                        $entityLine.PrivilegeType += ",$privilegeType"
                        $entityLine.policyCondition += ",$policyCondition"
                        $privilegedEntitiesDB[$groupInfo.Group.Arn] = $entityLine
                    }
                    else {
                        $entityLine = Build-EntityInfoLine -entityType "Group" -policyType "InlinePolicy"-entityObject $groupInfo -managedPolicyJsonStr $inlineGroupPolicyStr -policyName $policyName -privilegeType $privilegeType -policyCondition $policyCondition               
                        $privilegedEntitiesDB.add($groupInfo.Group.Arn, $entityLine)
                        $groupName = $groupInfo.Group.GroupName
                        # insert the privileged users that are members of the privilege group
                        $groupInfo.Users.UserName | foreach {
                            $userInfo = Get-IAMUser -UserName $_
                            if ($privilegedEntitiesDB.contains($userInfo.Arn)) {
                                # add only the permission policy
                                $entityLine = $privilegedEntitiesDB[$userInfo.Arn]
                                $entityLine.PrivilegedPermissionPolicy += "`n+`n$inlineGroupPolicyStr"
                                $entityLine.PolicyType += "+InlinePolicy"
                                $entityLine.PolicyName += ",$policyName-Through`"$groupName`"Group"
                                $entityLine.PrivilegeType += ",$privilegeType"
                                $entityLine.policyCondition += ",$policyCondition"
                                $privilegedEntitiesDB[$userInfo.Arn] = $entityLine
                            }
                            else {
                                $entityLine = Build-EntityInfoLine -entityType "User" -policyType "InlinePolicy" -entityObject $userInfo -managedPolicyJsonStr $inlineGroupPolicyStr -policyName $policyName -privilegeType $privilegeType -policyCondition $policyCondition              
                                $entityLine.PolicyName += "-Through`"$groupName`"Group" 
                                $privilegedEntitiesDB.add($userInfo.Arn, $entityLine)                
                            }
                        }                
                    }

                }
            }
        }
        try {
            $tenPrcs = [math]::round(($AWSgroups.count/10),0)
            if (($groupCounter % $tenPrcs) -eq 0){
                $prc = ([math]::round(($groupCounter/$AWSgroups.count),2)*100)
                Write-host "Status: finished $groupCounter groups, $prc% done"
            }
        }
        catch {
            Write-Verbose "Progress status is not available right now"
        }
    }

    # analyze inline policies in roles
    $inlineRolePoliciesCounter = 0
    $roleCounter = 0
    $AWSroles = Get-IAMRoleList
    Write-host "Analyzing" $AWSroles.count "roles"
    $countEntities.add("Roles", $AWSroles.count)
    $AWSroles | foreach {
        $roleCounter++
        $roleName = $_.RoleName
        $inlineRolePolicy = Get-IAMRolePolicyList -RoleName $roleName
        if ($inlineRolePolicy) {
            $inlineRolePoliciesCounter += $($inlineRolePoliciesCounter | Measure-Object).count
            $inlineRolePolicy | foreach {
                $inlineRolePolicyData = Get-IAMRolePolicy  -RoleName $roleName -PolicyName $_ 
                $inlineRolePolicyStr = [System.Web.HttpUtility]::UrlDecode($inlineRolePolicyData.PolicyDocument)
                $inlineRolePolicyJson = $inlineRolePolicyStr | ConvertFrom-Json
                $isPolicyPrivileged, $privilegeType, $policyCondition = Check-PrivilegedPolicy -policy $inlineRolePolicyJson
                if ($isPolicyPrivileged) {
                    $roleInfo = Get-IAMRole -RoleName $roleName
                    if ($privilegedEntitiesDB.contains($roleInfo.Arn)) {
                        # add only the permission policy
                        $entityLine = $privilegedEntitiesDB[$roleInfo.Arn]
                        $entityLine.PrivilegedPermissionPolicy += "`n+`n$inlineRolePolicyStr"
                        $entityLine.PolicyType += "+InlinePolicy"
                        $entityLine.PolicyName += ",$_"
                        $entityLine.PrivilegeType += ",$privilegeType"
                        $entityLine.policyCondition += ",$policyCondition"
                        $privilegedEntitiesDB[$roleInfo.Arn] = $entityLine
                    }
                    else {
                        $entityLine = Build-EntityInfoLine -entityType "Role" -policyType "InlinePolicy" -entityObject $roleInfo -managedPolicyJsonStr $inlineRolePolicyStr -policyName $_ -privilegeType $privilegeType -policyCondition $policyCondition              
                        $privilegedEntitiesDB.add($roleInfo.Arn, $entityLine)
                        # to add all the entites that can assume the privileged role                
                    }
                }
            }
        }
        try {
            $tenPrcs = [math]::round(($AWSroles.count/10),0)
            if (($roleCounter % $tenPrcs) -eq 0){
                $prc = ([math]::round(($roleCounter/$AWSroles.count),2)*100)
                Write-host "Status: finished $roleCounter roles, $prc% done"
            }
        }
        catch {
            Write-Verbose "Progress status is not available right now"
        }
    }

    $inlinePoliciesCounter = $inlineUserPoliciesCounter + $inlineGroupPoliciesCounter + $inlineRolePoliciesCounter
    $countEntities.add("InlinePolicies", $inlinePoliciesCounter)
    if ($inlinePoliciesCounter -eq 1) {
        Write-Host "[+] Finished analyzing" $inlinePoliciesCounter "inline policy"
    }
    else {
        Write-Host "[+] Finished analyzing" $inlinePoliciesCounter "inline policies"
    }
}


# write the final scan report - as a simple and summarized txt file
function Write-Report {
    [CmdletBinding()]
    Param (
        $privilegedEntitiesDB,
        [string]
        $finalReportPath,
        [string]
        $resultCSVpath
    )

    $reportOutputArray = New-Object System.Collections.Generic.List[System.String]

    $allPrivivlgedEntities = $privilegedEntitiesDB | select "Arn" -Unique
    $numAllPrivivlgedEntities = $($allPrivivlgedEntities | Measure-Object).count
    Write-host "-> AWStealth discovered $numAllPrivivlgedEntities privileged entities" -BackgroundColor DarkRed
    $awsAccount = (([string]$allPrivivlgedEntities[0]).Split(":"))[4]
    $shadowAdmins = $privilegedEntitiesDB | Where-Object {$_.PrivilegeType -like "*shadow*"} 
    $numShadowAdmins = $($shadowAdmins | Measure-Object).count
    if ($numShadowAdmins -ge 1) {
         Write-host "-> Discovered $numShadowAdmins AWS Shadow Admins" -BackgroundColor DarkRed
    }
    $privilegedUsers = $privilegedEntitiesDB | Where-Object {$_.EntityType -eq "User"}
    $numPrivilegedUsers = $($privilegedUsers | Measure-Object).count
    $privilegedGroups = $privilegedEntitiesDB | Where-Object {$_.EntityType -eq "Group"}
    $numPrivilegedGroups = $($privilegedGroups | Measure-Object).count
    $privilegedRoles = $privilegedEntitiesDB | Where-Object {$_.EntityType -eq "Role"}
    $numPivilegedRoles = $($privilegedRoles | Measure-Object).count
    $privilegedUserNoMFA = $privilegedEntitiesDB | Where-Object {$_.MFAenable -eq "NoMFA"} 
    $numPrivilegedUserNoMFA = $($privilegedUserNoMFA | Measure-Object).count
    $privilegedUsersNoCondition = $privilegedEntitiesDB | Where-Object {$_.policyCondition -like "*noCon*"} 
    $numPrivilegedUsersNoCondition = $($privilegedUsersNoCondition | Measure-Object).count
    $privielgedUsersNotSecured = $privilegedEntitiesDB | Where-Object {($_.policyCondition -like "*noCon*") -and ($_.MFAenable -eq "NoMFA")} 
    $numPivielgedUsersNotSecured = $($privielgedUsersNotSecured| Measure-Object).count
    $scanTime = Get-Date -Format g

    $reportOutputArray.Add("")
    $reportOutputArray.Add("######################################################")
    $reportOutputArray.Add($AWStealth)
    $reportOutputArray.Add("              AWStealth version: $AWStealthVersion")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("       The scanned AWS Account: $awsAccount")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("        Date of the scan: $scanTime")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("######################################################")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("                     SCAN SUMMARY")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("#######################################################")

    try {
        $reportOutputArray.Add("")
        $reportOutputArray.Add("AWStealth scanned:")
        $number = $countEntities["Users"]
        $reportOutputArray.Add("$number Users")
        $number = $countEntities["Groups"]
        $reportOutputArray.Add("$number Groups")
        $number = $countEntities["Roles"]
        $reportOutputArray.Add("$number Roles")
        $number = $countEntities["ManagedPolicies"]
        $reportOutputArray.Add("$number Managed Policies")
        $number = $countEntities["InlinePolicies"]
        $reportOutputArray.Add("$number Inline Policies")
    }
    catch {
        Write-verbose "Couldn't calculate the entities' numbers"
    }
    $reportOutputArray.Add("")
    $reportOutputArray.Add("* The AWStealth scan focuses on the highest level of the privileges in AWS.")
    $reportOutputArray.Add("  Make sure to secure also the less-sensitive entities in the environment.")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("Total number of the most privileged AWS entities: $numAllPrivivlgedEntities")
    $reportOutputArray.Add("Total number of AWS Shadow Admins: $numShadowAdmins")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("Number of privileged Users: $numPrivilegedUsers")
    $reportOutputArray.Add("Number of privileged Groups: $numPrivilegedGroups")
    $reportOutputArray.Add("Number of privileged Roles: $numPivilegedRoles")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("#######################################################")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("-> Number of privileged users without MFA protection: $numPrivilegedUserNoMFA")
    $reportOutputArray.Add("-> Number of privileged entities without constrained conditions: $numPrivilegedUsersNoCondition")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("-> Number of unsecured users = no MFA and no constrained permission condition: $numPivielgedUsersNotSecured")
    if ($numPivielgedUsersNotSecured -gt 1) {
        Write-host "-> Number of unsecured users = no MFA and no constrained permission condition: $numPivielgedUsersNotSecured Users!`n" -BackgroundColor DarkRed
    }
    $reportOutputArray.Add("")        
    $reportOutputArray.Add("List of unsecured privileged users:")
    $counter = 0
    $privielgedUsersNotSecured | foreach {
        $counter += 1
        $reportOutputArray.Add([string]$counter + ". " + $_.EntityName)
    }

    $reportOutputArray.Add("")
    $reportOutputArray.Add("######################################################")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("Full scan results are available in the scan csv file:")
    $reportOutputArray.Add($resultCSVpath)
    $reportOutputArray.Add("")
    $reportOutputArray.Add("#######################################################")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("List of users with direct privileges:")
    $counter = 0
    $usersFromGroups = @()
    $privilegedUsers | foreach {
        $countPolicyNames = ($_.PolicyName | Where-Object {$_ -eq ','} | Measure-Object).Count
        $countPoliciesFromGroups = ($_.PolicyName | Where-Object {$_ -like '*-Thr*'} | Measure-Object).Count
        if (($countPolicyNames + 1) -eq $countPoliciesFromGroups) {
            $usersFromGroups += $_.EntityName
        }
        else {
            $counter += 1
            $reportOutputArray.Add([string]$counter + ". " + $_.EntityName)
        }
    }

    $reportOutputArray.Add("")
    $reportOutputArray.Add("List of the privileged Groups:")
    $counter = 0
    $privilegedGroups | foreach {
        $counter += 1
        $reportOutputArray.Add([string]$counter + ". " + $_.EntityName + " - group members: " + $_.GroupMembers)
    }
    $reportOutputArray.Add("")
    $reportOutputArray.Add("List of the privileged Roles:")
    $counter = 0
    $privilegedRoles | foreach {
        $counter += 1
        $reportOutputArray.Add([string]$counter + ". " + $_.EntityName)
    }

    $reportOutputArray.Add("")
    $reportOutputArray.Add("######################################################")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("The discoverd entites with their full privileged permission policies:")
    $reportOutputArray.Add("")
    $reportOutputArray.Add("#######################################################")
    $reportOutputArray.Add("")

    $counter = 0
    $privilegedEntitiesDB | foreach {
        $mfa = "no MFA"
        if ($_.MFAenable -eq $true) {
            $mfa = "MFA is enabled"
        }
        if ($_.policyCondition -like "*noCon*") {
            $policyCond = "no constrained permission condition"
        }
        else {
            $policyCond = "the permission has a condition"
        }
        $counter += 1
        $reportOutputArray.Add([string]$counter + ". " + $_.EntityName + " - " + $mfa + ", " + $policyCond)
        $reportOutputArray.Add("PrivilegedType: " + $_.PrivilegeType)
        $permissionPolicy = ([string]$_.PrivilegedPermissionPolicy).Split("`n")
        $permissionPolicy | foreach {
            $reportOutputArray.Add($_)
        }
    }

    $reportOutputArray.Add("")
    $reportOutputArray.Add("#######################################################")

    $reportOutputArray | Out-File $finalReportPath 
}


# The main function of AWStealth - it will discover privileged entity in the target AWS environment
function Scan-AWShadowAdmins {
    Param (
        # The access key ID to use
        [string]
        $AccessKeyID,
        # The secret Key to use
        [string]
        $SecretKey,
		      # The session token to use (optional)
        [string]
		      $sessionToken,
        # The default AWS region of the scanned environment
        [string]
        $DefaultRegion,
        [string]
        $ProfileName
    )    
     
    $privilegedEntitiesDB = @{}
    $countEntities = @{}
    [string]$resultsTime = Get-Date -Format "yyyyMMdd"
    $resultCSVpath = $PSScriptRoot + "\AWStealth - Results " + $resultsTime + ".csv"
    $finalReportPath = $PSScriptRoot + "\AWStealth - Final Report " + $resultsTime + ".txt"

    # Load the AWS credentials
    $tempProfile = "AWStealthProfile"
    Load-AWScred -AccessKeyID $AccessKeyID -SecretKey $SecretKey -sessionToken $sessionToken -DefaultRegion $DefaultRegion -ProfileName $ProfileName -tempProfile $tempProfile
    if ($ProfileName) {
        Set-AWSCredential -ProfileName $ProfileName
    }
    else {
        Set-AWSCredential -ProfileName $tempProfile
    }

    try {
        [System.Reflection.Assembly]::LoadWithPartialName("System.Web.HttpUtility")
        Add-Type -AssemblyName System.Web
        # try using [System.Web.HttpUtility]
        $libraryCheck = [System.Web.HttpUtility]::UrlDecode("test")
    }
    catch {
        Write-host "Error in loading `"System.Web.HttpUtility`" .NET library - trying another attempt" -ForegroundColor red
        [System.Reflection.Assembly]::LoadWithPartialName("System.Web.HttpUtility")
    }

    Write-host "[+] Start scanning for privileged AWS entities - including AWS Shadow Admins`n"

    # check the AWS PowerShell Module version, because only from xxxx AWS annouced the concept of "Permissions Boundaries"
    $updatedAwsPowerShellModule = $false
    $versionAwsPowerShellModule = (Get-Module) | Where-Object {$_.Name -eq "AWSPowerShell"} | select Version
    if ($versionAwsPowerShellModule.Version.Major -ge 4) {
    	$updatedAwsPowerShellModule = $true
    }
    else {
        if ($versionAwsPowerShellModule.Version.Major -eq 3){
            if ($versionAwsPowerShellModule.Version.Minor -ge 3) {
                if ($versionAwsPowerShellModule.Version.Build -ge 330) {
                    $updatedAwsPowerShellModule = $true
                }
	    }
        }
    }
    if (-not $updatedAwsPowerShellModule) {
        Write-Host "`nThe current AWS PowerShell Module that is loaded - isn't up to date, its version: "$versionAwsPowerShellModule.Version -BackgroundColor Red
        Write-Host "Please upgrade your AWS Powershell Module." 
        Write-Host "If you have PowerShell v5+ -> Use the commands: `"Update-Module -Name AWSPowerShell`" and restart the PowerShell session""" 
        Write-Host "You can also uninstall and install the updated module with:" 
        Write-Host "`"Uninstall-Module -Name AWSPowerShell`" and `"Install-Module -Name AWSPowerShell`"" 
        Write-Host "OR download manualy the last version from:`nhttps://aws.amazon.com/powershell/" 
        Write-Host "`nThe AWStealth scan will continue!" -BackgroundColor DarkGreen
        Write-Host "But there might be false-postive in the results if the entities in the envrionment have `"Permissions Boundries`"`n" -BackgroundColor DarkGreen
    }
    
    $totaltime = New-Object system.Diagnostics.Stopwatch  
    $totaltime.Start()

    # analyze managed policies
    Check-ManagedPolicies

    # analyze inline policies
    Check-InlinePolicies
        
    $totaltime.Stop()
    $runtime = $totaltime.Elapsed.TotalMilliseconds
    $runtime = ($runtime/1000)
    $runtimeMin = ($runtime/60)
    $runtimeHours = ($runtime/3600)
    $runtime = [math]::round($runtime , 2)
    $runtimeMin = [math]::round($runtimeMin , 2)
    $runtimeHours = [math]::round($runtimeHours , 3)
    Write-Host "`nFinished the AWStealth scan in: $runtimeMin Minutes, $runtimeHours Hours"

    Write-host "`n[+] Discovered" $privilegedEntitiesDB.Count "privileged entities in the scanned AWS environment" -ForegroundColor green

    if ($($privilegedEntitiesDB | Measure-Object).count -eq 0) {
        Write-host "Sorry, the scan didn't find any AWS Shadow Admin.`nPlease try again.`nCheck the prerequisites - including the credentials you are using in the scan and your internet connection" -ForegroundColor red
    }
    else {
        $privilegedEntitiesDB.Values | sort-object -Descending EntityType, PrivilegeType, PolicyName | Export-Csv -path $resultCSVpath -NoTypeInformation
        Write-host "[+] Exported the results to: `n`"$resultCSVpath`"`n" -ForegroundColor green
        $privilegedEntitiesDB = $privilegedEntitiesDB.Values | sort-object -Descending EntityType, PrivilegeType, PolicyName
        Write-Report -privilegedEntitiesDB $privilegedEntitiesDB -finalReportPath $finalReportPath -resultCSVpath $resultCSVpath
        Write-host "[+] Check the final report: `n`"$finalReportPath`"`n" -ForegroundColor green
    }
    Remove-AWSCredentialProfile -ProfileName $tempProfile -force
}


# Alias function for starting the AWStealth scan
function Scan-AWSAdmins {
    Scan-AWShadowAdmins
}


# Initiating global DBs
$privilegedEntitiesDB = @{}
$countEntities = @{}
