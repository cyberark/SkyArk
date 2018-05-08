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

#>


$version = "v1.0"

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
            Future updates via Twitter

------------------------------------------------------
"@


Write-Output $AWStealth
Write-Output "***   Welcome to SkyArk's AWStealth module $version   ***`n"
Write-Output "It's time to discover the most privileged AWS entities`n"
Write-Output $Author

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
        Set-AWSCredential -AccessKey $AccessKeyID -SecretKey $SecretKey -StoreAs $tempProfile
        Set-AWSCredential -ProfileName $tempProfile
    }
    if (-not $DefaultRegion) {
        $DefaultRegion = read-host "What is your AWS default region (e.g. `"us-east-1`")?"
    }
    Set-DefaultAWSRegion -Region $DefaultRegion
    $currentUser = Get-IAMUser
    $currentUserName = $currentUser.UserName
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
                # example for a dangerous usage with AWS CLI: "aws iam update-login-profile --user-name ShadowTest --password Cyber123"
                if ($_.Action | ? {($_ -eq "iam:UpdateLoginProfile")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "shadowUpdateLoginProfiles"
                    }
                }
                #############################################################################################################################################################(7)
                # check for the sensitive "CreateLoginProfile" permissions to other entities
                # example for a dangerous usage with AWS CLI: "aws iam create-login-profile --cli-input-json file:///Work/AWS/AWShadowAdmins/Demo/LoginProfile.json"
                if ($_.Action | ? {($_ -eq "iam:CreateLoginProfile")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "shadowCreateLoginProfiles"
                    }
                }
                #############################################################################################################################################################(8)
                # check for the sensitive "AddUserToGroup" permissions to other entities
                # example for a dangerous usage with AWS CLI: "aws iam add-user-to-group --user-name Bob --group-name demoAdminsGroup"
                if ($_.Action | ? {($_ -eq "iam:AddUserToGroup")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:group/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "shadowAddUserToGroups"
                    }
                }
                #############################################################################################################################################################(9)
                # check for the sensitive "CreatePolicyVersion" permissions to other entities
                # example for a dangerous usage with AWS CLI: "aws iam create-policy-version --policy-arn arn:aws:iam::419890133200:policy/IAM-Read-Only --policy-document file:///Work/AWS/AWShadowAdmins/Demo/AdminPermissionPolicy.json --set-as-default"
                if ($_.Action | ? {($_ -eq "iam:CreatePolicyVersion") -or ($_ -eq "iam:SetDefaultPolicyVersion")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:policy/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "shadowSetPolicyVersions"
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
                if (($permissionResources.count -ge 1) -and ($permissionActions.count -ge 3)) {
                    $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "shadowModifyInstanceProfiles"
                }
                #############################################################################################################################################################(11)
                # check for the sensitive "UpdateAssumeRolePolicy" permission 
                # example for a dangerous usage with AWS CLI: "aws iam update-assume-role-policy --role-name shadowRole --policy-document file:///Work/AWS/AWShadowAdmins/Demo/RoleTrustPolicy.json"
                if ($_.Action | ? {($_ -eq "iam:UpdateAssumeRolePolicy")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:role/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "shadowUpdateAssumeRolePolicy"
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
                #############################################################################################################################################################(14)
                if ($_.Action | ? {($_ -eq "kms:*")}) {
                    if ($_.Resource | ? {($_ -eq "*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullKMSadmin"
                    }
                }
                #############################################################################################################################################################(14)
                if ($_.Action | ? {($_ -eq "sts:*")}) {
                    if ($_.Resource | ? {($_ -eq "*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullSTSadmin"
                    }
                }
                #############################################################################################################################################################(14)
                if ($_.Action | ? {($_ -eq "Cloudformation:*")}) {
                    if ($_.Resource | ? {($_ -eq "*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullCloudformationAdmin"
                    }
                }
                #############################################################################################################################################################(14)
                if ($_.Action | ? {($_ -eq "lambda:*")}) {
                    if ($_.Resource | ? {($_ -eq "*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "FullLambdaAdmin"
                    }
                }
                #############################################################################################################################################################(15)
                if ($_.Action | ? {($_ -eq "iam:attach*")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")-or ($_ -eq "arn:aws:iam::*:group/*")-or ($_ -eq "arn:aws:iam::*:role/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMattacAdmin"
                    }
                }
                #############################################################################################################################################################(16)
                if ($_.Action | ? {($_ -eq "iam:put*")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:user/*")-or ($_ -eq "arn:aws:iam::*:group/*")-or ($_ -eq "arn:aws:iam::*:role/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMputAdmin"
                    }
                }
                #############################################################################################################################################################(17)
                if ($_.Action | ? {($_ -eq "iam:add*")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:group/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMaddAdmin"
                    }
                }
                #############################################################################################################################################################(18)
                if ($_.Action | ? {($_ -eq "iam:create*")}) {
                    if ($_.Resource | ? {($_ -eq "*") -or ($_ -eq "arn:aws:iam::*:policy/*")}) {
                        $isPrivileged, $privilegeType = Mark-privilegedPolicy -privilegeType $privilegeType -newPrivilegeType "IAMcreatAdmin"
                    }
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
            $policyEntities = Get-IAMEntitiesForPolicy -PolicyArn $_.Arn
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
                    if ($groupInfo.Users.UserName.count -gt 0) {
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
    $AWSusers | foreach {
        $userCounter++
        $userName = $_.UserName
        $inlineUserPolicy = Get-IAMUserPolicyList -UserName $userName
        if ($inlineUserPolicy) {
            $inlineUserPoliciesCounter += $inlineUserPolicy.count
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
    $AWSgroups | foreach {
    $groupCounter++
        $GroupName = $_.GroupName
        # Get a list of the inline policies that are embedded in the specified group.
        $inlineGroupPolicy = Get-IAMGroupPolicyList -GroupName $GroupName 
        if ($inlineGroupPolicy) {
            $inlineGroupPoliciesCounter += $inlineGroupPolicy.count
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
    $AWSroles | foreach {
        $roleCounter++
        $roleName = $_.RoleName
        $inlineRolePolicy = Get-IAMRolePolicyList -RoleName $roleName
        if ($inlineRolePolicy) {
            $inlineRolePoliciesCounter += $inlineRolePoliciesCounter.count
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
    if ($inlinePoliciesCounter -eq 1) {
        Write-Host "[+] Finished analyzing" $inlinePoliciesCounter "inline policy"
    }
    else {
        Write-Host "[+] Finished analyzing" $inlinePoliciesCounter "inline policies"
    }
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
        # The default AWS region of the scanned environment
        [string]
        $DefaultRegion,
        [string]
        $ProfileName
    )    
     
    $privilegedEntitiesDB = @{}
    $resultCSVpath = $PSScriptRoot + "\AWSteatlh - Results.csv"

    # Load the AWS credentials
    $tempProfile = "AWStealthProfile"
    Load-AWScred -AccessKeyID $AccessKeyID -SecretKey $SecretKey -DefaultRegion $DefaultRegion -ProfileName $ProfileName -tempProfile $tempProfile
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

    if ($privilegedEntitiesDB.count -eq 0) {
        Write-host "Sorry, the scan didn't find any AWS Shadow Admin.`nPlease try again.`nCheck the prerequisites - including the credentials you are using in the scan and your internet connection" -ForegroundColor red
    }
    else {
        $privilegedEntitiesDB.Values | sort -Descending EntityType, PrivilegeType, PolicyName | Export-Csv -path $resultCSVpath -NoTypeInformation
        Write-host "[+] Exported the results to `"$resultCSVpath`"`n" -ForegroundColor green
    }
    
    Remove-AWSCredentialProfile -ProfileName $tempProfile -force
}

# Initiating global DBs
$privilegedEntitiesDB = @{}
