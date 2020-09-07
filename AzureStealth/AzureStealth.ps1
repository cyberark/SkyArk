#Requires -Version 5.1
<#

###########################################################################################
#                                                                                         #
#    AzureStealth - Discover the most privileged users in Azure and secure\target them    #
#                                                                                         #
###########################################################################################
#                                                                                         #
#                                                                                         #
#                             Written by: Asaf Hecht (@Hechtov)                           #
#                                      CyberArk Labs                                      #
#                                Future updates via Twitter                               #
#                                                                                         #
###########################################################################################


Versions Notes:
Version 0.1 - 03.03.19
Version 0.2 - 21.03.19
Version 0.3 - 08.07.19
Version 0.4 - 11.07.19
Version 1.0 - 12.07.19 - published on GitHub as part of SkyArk tool:
https://github.com/cyberark/SkyArk
https://github.com/cyberark/SkyArk/tree/master/AzureStealth
Version 1.1 - 01.09.19 - added two sensitive directory roles
Version 1.2 - 07.09.20 - add support for CSP suscriptions

###########################################################################################

HOW TO INSTALL AZURE POWERSHELL MODULE:

Guide for installing Azure "AZ" PowerShell Module:
https://docs.microsoft.com/en-us/powershell/azure/install-az-ps

Guide for installing Azure "AzureAD" PowerShell Module (you need this in addtion to the az module):
https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2

If local admin (PowerShell command):
    Install-Module -Name Az -AllowClobber
    Install-Module AzureAD -AllowClobber
Else:
    Install-Module -Name Az -AllowClobber -Scope CurrentUser
    Install-Module AzureAD -AllowClobber -Scope CurrentUser
    
###########################################################################################

HOW TO RUN AZURESTEALTH:

1) Download/sync locally the script file AzureStealth.ps1
2) Open PowerShell in the AzureStealth folder with the permission to run scripts:
   "powershell -ExecutionPolicy Bypass -NoProfile"
3) Run the following commands
    (1) Import-Module .\AzureStealth.ps1 -Force     (load the scan)
    (2) Scan-AzureAdmins                            (start the AzureStealth scan)
Optional commands:
    (-) Scan-AzureAdmins -UseCurrentCred            (if you used Azure PowerShell in the past, it uses the current cached Azure credentials)
    (-) Scan-AzureAdmins -GetPrivilegedUserPhotos   (if you want to focus only on the privileged Azure users, you can also get their photos (if they have profile photos))

###########################################################################################

HOW TO RUN AZURESTEALTH DIRECTLY FROM AZURE'S CLOUDSHELL:

You can load and run the scan directly from GitHub, simply use the following PowerShell commands:
    (1) IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AzureStealth/AzureStealth.ps1')
    (2) Scan-AzureAdmins

###########################################################################################
#>

$AzureStealthVersion = "v1.2"

$AzureStealth = @"

-------------------------------------------------------------------------------

                                      _____ _             _ _   _     
           /\                        / ____| |           | | | | |    
          /  \    _____   _ _ __ ___| (___ | |_ ___  __ _| | |_| |__  
         / /\ \  |_  / | | | `'__/ _ \\___ \| __/ _ \/ _`` | | __| `'_ \ 
        / ____ \  / /| |_| | | |  __/____) | ||  __/ (_| | | |_| | | |
       /_/    \_\/___|\__,_|_|  \___|_____/ \__\___|\__,_|_|\__|_| |_|
                                                                
"@                                   

$Author = @"
-------------------------------------------------------------------------------

                        Author: Asaf Hecht - @Hechtov
                                CyberArk Labs
                         Future updates via Twitter

-------------------------------------------------------------------------------

"@


Write-Output $AzureStealth
Write-Output "`n                  ***   Welcome to AzureStealth $AzureStealthVersion   ***`n"
Write-Output " Discover the most privileged users in Azure and secure\target them :)`n"
Write-Output $Author


# Check if the PowerShell Azure Module exists on the machine
function Check-AzureModule {
    $oneAzureModuleExist = $true
    # Try loading the AZ PowerShell Module
    try {
        $azModule = Get-InstalledModule -Name Az -ErrorAction Stop
    }
    Catch {
        Write-Host "`nCouldn't find the Azure `"AZ`" PowerShell Module" -ForegroundColor Yellow
        Write-Host "The tool will prompt you and install it using the `"Install-Module -Name Az`" command" -ForegroundColor Yellow
        if ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
            Install-Module -Name Az -AllowClobber
        }
        else {
            Install-Module -Name Az -AllowClobber -Scope CurrentUser
        }
    }
    try {
        $azModule = Get-InstalledModule -Name Az -ErrorAction Stop
        if ($azModule){
            Write-Host "`n  [+] Great, Azure `"AZ`" PowerShell Module exists`n"   
        }
    }
    catch {
        Write-Host "`nEncountered an error - couldn't find the Azure `"AZ`" PowerShell Module" -BackgroundColor Red
        Write-Host "Please install Azure Az PowerShell Module (requires PowerShell version 5.1+)" -BackgroundColor Red
        Write-Host "Installation guideline:" -BackgroundColor Red
        Write-Host "https://docs.microsoft.com/en-us/powershell/azure/install-az-ps" -BackgroundColor Red
        $oneAzureModuleExist = $false
        #Return $false
    }

    # Try loading the AzureAD PowerShell Module
    try {
        $azModule = Get-InstalledModule -Name AzureAD -ErrorAction Stop
    }
    Catch {
        Write-Host "`nCouldn't find the Azure `"AzureAD`" PowerShell Module" -ForegroundColor Yellow
        Write-Host "The tool will prompt you and install it using the `"Install-Module -Name AzureAD`" command" -ForegroundColor Yellow
        if ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
            Install-Module -Name AzureAD -AllowClobber
        }
        else {
            Install-Module -Name AzureAD -AllowClobber -Scope CurrentUser
        }
    }
    try {
        $azModule = Get-InstalledModule -Name AzureAD -ErrorAction Stop
        if ($azModule){
            Write-Host "  [+] Great, Azure `"AzureAD`" PowerShell Module exists`n"
            $oneAzureModuleExist = $true  
        }
    }
    catch {
        Write-Host "`nEncountered an error - couldn't find the Azure `"AzureAD`" PowerShell Module" -BackgroundColor Red
        Write-Host "Please install Azure Az PowerShell Module (requires PowerShell version 5.1+)" -BackgroundColor Red
        Write-Host "Installation guideline:" -BackgroundColor Red
        Write-Host "https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2" -BackgroundColor Red
        if ($oneAzureModuleExist -eq $false) {
            $oneAzureModuleExist = $false
        }
    }

    Return $oneAzureModuleExist
}


# Connect to the target Azure environment
function Connect-AzureEnvironment {
    
    try {
        $answer = "n"
        $AzContext = Get-AzContext  | Where-Object {($_.tenant) -or ($_.TenantId)}
        if ($AzContext.Account) {
            Write-Host "The current Azure account context is set for:"
            Write-Host ($AzContext | select  Name, Account, Environment | Format-List | Out-String)  -NoNewline
            $answer = Read-Host "Do you want to use this Azure Account context? Press (y/Y or n/N)"
        }
        if ($answer.ToLower() -notmatch "y") {
            $AzAllCachedContext = Get-AzContext -ListAvailable
            $AzCachedContext = $AzAllCachedContext | Where-Object {($_.Tenant) -or ($_.TenantId)}
            if ($AzCachedContext) {
                Write-Host "The follwoing Azure user/s are available through the cache:`n"
                $counter = 0
                $AzCachedContext | foreach {
                    $counter++
                    $contextAccount = $_.Account.id 
                    $contextName = $_.Name
                    $contextNameEx = "*" + $contextAccount + "*"
                    if ($contextName -like $contextNameEx){
                        Write-Host "$counter) Name: $contextName"
                    }
                    else {
                        Write-Host "$counter) Name: $contextName - $contextAccount"
                    }
                
                }
                $contextAnswer = Read-Host "`nDo you want to use one of the above cached users?`nPress the user's number from above (or n/N for chosing a new user)"
                if ($contextAnswer.ToString() -le $counter) {
                    $contextNum = [int]$contextAnswer
                    $contextNum--
                    $chosenAccount = $AzCachedContext[$contextNum].Account.id
                    Write-Host "`nYou chose to proceed with $chosenAccount"
                    Set-AzContext -Context $AzCachedContext[$contextNum] -ErrorAction Stop  > $null
                    return $true
                }
            }
            Write-Host "Please connect to your desired Azure environment"
            Write-Host "These are the available Azure environments:"
            $AzEnvironment = Get-AzEnvironment | select Name, ResourceManagerUrl
            Write-Host ($AzEnvironment | Format-Table | Out-String)  -NoNewline
            $answer = read-host "Do you use the US-based `"AzureCloud`" environment? Press (y/Y or n/N)"
            $rand = Get-Random -Maximum 10000
            if ($answer.ToLower() -match "y") {
                Connect-AzAccount -ContextName "Azure$rand" -ErrorAction Stop > $null
            }
            else {
                $AzEnvironment = Read-Host "Ok, please write your Azure environment Name from the list above.`nAzure environment Name"
                Connect-AzAccount -ContextName "Azure$rand" -Environment $AzEnvironment -ErrorAction Stop > $null
            }    
        }
    }
    catch {
        Write-Host "Encountered an error - check again the inserted Azure Credentials" -BackgroundColor red
        Write-Host "There was a problem when trying to access the target Azure Tenant\Subscription" -BackgroundColor Red
        Write-Host "Please try again... and use a valid Azure user" 
        Write-Host "You can also try different Azure user credentials or test the scan on a different environment"
        return $false
    }
    Write-Host "`n  [+] Got valid Azure credentials"

    return $true
}


# Connect to the target Azure Directory
function Connect-AzureActiveDirectory {
    [CmdletBinding()]
    param(
    $AzContext
    )
    try {
        $tenantId = $AzContext.Tenant.Id
        $accountId = $AzContext.Account.Id
        if ($tenantId){
            $AzAD = Connect-AzureAD -TenantId $tenantId -AccountId $accountId -ErrorAction Stop
        }
        else {
            $AzAD = Connect-AzureAD -AccountId $accountId -ErrorAction Stop
        }
        $directoryName = $AzAD.TenantDomain
        Write-Host "`n  [+] Connected to the Azure Active Directory: "$directoryName
    }
    catch {
         Write-Host "`nCouldn't connect to the Azure Active Directory using the chosen user" -BackgroundColor red
         Write-Host "Please try again... and use a valid Azure AD user" -BackgroundColor red
         Write-Host "The tool will continue but it won't scan the Tenant Directory level (only subscriptions will be scanned)" -BackgroundColor red
         Write-Host "You can also try different Azure user credentials or test the scan on a different environment"
         return $false
    }   
    
    return $true
}


# Add the detected privileged entity to the Results Dictionary 
function Add-PrivilegeAzureEntity {
    [CmdletBinding()]
    param(
    [string]
    $entityId,
    [string]
    $DirectoryTenantID,
    [string]
    $SubscriptionID,
    [string]
    $RoleId,
    [string]
    $PrivilegeReason,
    [string]
    $ClassicSubscriptionAdminRole,
    [string]
    $scope,
    [switch]
    $ClassicAdmin
    )

    $fullDirectoryAdmins = @("Application Administrator", "Authentication Administrator",`
        "Password Administrator", "Privileged Authentication Administrator",`
        "Cloud Application Administrator", "Helpdesk Administrator", "Privileged Role Administrator", "User Account Administrator")
    $sensitiveDirectoryAdmins = @("SharePoint Service Administrator", "Exchange Service Administrator",`
        "Conditional Access Administrator", "Security Administrator")
    $subscriptionAdmins =  @("Owner","Contributor", "User Access Administrator")
    
    $RBACRoleAdminName = $roleDict[$RoleId].Name
    if ($ClassicAdmin) {
        $ClassicAdministrator = $PrivilegeReason
        $PrivilegeType = "Azure Subscription Full Admin"
        $RoleId = "Classic Subscription Admin"
    }
    else {
        if ($PrivilegeReason -eq "Company Administrator") {
            $roleDict[$RoleId].DisplayName = "Global Administrator"
            $PrivilegeType = "Azure Directory Full Admin"
        }
        elseif ($fullDirectoryAdmins -contains $PrivilegeReason) {
            $PrivilegeType = "Azure Directory Shadow Admin"
        }
        elseif ($sensitiveDirectoryAdmins -contains $PrivilegeReason) {
            $PrivilegeType = "Azure Directory Sensitive Admin"
        }
        elseif ($subscriptionAdmins -contains $PrivilegeReason) {
            $PrivilegeType = "Azure Subscription Full Admin"
        }
        elseif ($PrivilegeReason -eq "Privileged Group Owner") {
            $PrivilegeType = "Azure Subscription Shadow Admin"
            $RBACRoleAdminName = "Privileged Group Owner"
        }
    } 
    if ($entityDict[$entityId].ExtensionProperty.createdDateTime) {
        $EntityCreationDate = Get-Date ($entityDict[$entityId].ExtensionProperty.createdDateTime) -Format "yyyMMdd"
    }
    $customRole = ""
    if ($roleDict[$RoleId].IsCustom) {
        $PrivilegeType = "Azure Subscription Shadow Admin"
        $customRole = $True
    }

    $entityLine = [PSCustomObject][ordered] @{
        PrivilegeType        = [string]$PrivilegeType
        EntityDisplayName    = [string]$entityDict[$entityId].DisplayName
        EntityPrincipalName  = [string]$entityDict[$entityId].UserPrincipalName
        EntityType           = [string]$entityDict[$entityId].ObjectType 
        DirectoryRoleAdminName   = [string]$roleDict[$RoleId].DisplayName  
        ClassicSubscriptionAdmin = [string]$ClassicAdministrator
        RBACRoleAdminName        = [string]$RBACRoleAdminName
        SubscriptionName     = [string]$subscriptionDict[$SubscriptionID].Name
        SubscriptionID       = [string]$SubscriptionID
        SubscriptionStatus   = [string]$subscriptionDict[$SubscriptionID].State
        TenantDisplayName    = [string]$tenantDict[$TenantId].DisplayName
        TenantInitialName    = [string]$tenantDict[$TenantId].InitialDomainName
        DirectoryTenantID    = [string]$DirectoryTenantID
        EntityCreationDate   = [string]$EntityCreationDate
        EntityId             = [string]$entityDict[$entityId].ObjectId
        EntityHasPhoto       = [string]$entityDict[$entityId].EntityHasPhoto
        UserEnabled          = [string]$entityDict[$entityId].AccountEnabled
        OnPremisesSID        = [string]$entityDict[$entityId].OnPremisesSecurityIdentifier
        RoleIsCustom         = [string]$customRole
        RoleId               = [string]$RoleId        
    }
    if ($RoleId) {
        $entityRand = [string]($entityDict[$entityId].ObjectId) + "-" + [string]$RoleId
    }
    else {
        $rand  = $SubscriptionID + $PrivilegeReason
        $entityRand = [string]($entityDict[$entityId].ObjectId) + "-" + [string]$rand
    }
    if (-not $privilegedAzEntitiesDict.contains($entityRand)) {
        $privilegedAzEntitiesDict.add($entityRand,$entityLine)
    }
}


# Add the detected Entity to the Dictionary
function Add-EntityToDict {
    [CmdletBinding()]
    param(
        $AzEntityObject,
        [switch]
        $externalUser
    )

    if ($externalUser){
        $externalUserObject = [PSCustomObject][ordered] @{
            DisplayName        = $AzEntityObject
            UserPrincipalName  = $AzEntityObject
            ObjectType         = "User"
            ObjectId           = "ExternalUser-" + $AzEntityObject
        }
        $entityDict.add($AzEntityObject, $externalUserObject)
    }
    else {
        $EntityId = $AzEntityObject.ObjectId
        if (-not $entityDict.contains($EntityId)) { 
            $resultsFolder = $PSScriptRoot + "\Results-" + $resultsTime
            $usersPhotoFolder = $resultsFolder + "\PrivilegedUserPhotos"
            $entityHasPhoto = ""
	        if ((-not $CloudShellMode) -and (-not $fullUserReconList)) {
		        if ($AzEntityObject.ExtensionProperty."thumbnailPhoto@odata.mediaEditLink") {
			        $entityHasPhoto = $true
		            $resultsFolderExists = Test-Path -Path $resultsFolder
		            if (-not $resultsFolderExists) {
			            New-Item -ItemType directory -Path $resultsFolder > $null
		            }
                    $usersPhotoFolderExists = Test-Path -Path $usersPhotoFolder
		            if (-not $usersPhotoFolderExists) {
			            New-Item -ItemType directory -Path $usersPhotoFolder > $null
		            }
			        try {
			            Get-AzureADUserThumbnailPhoto -ObjectId $EntityId -FilePath $usersPhotoFolder -ErrorAction SilentlyContinue > $null
			            $entityHasPhoto = $true
			        }
			        catch {}
		        }
                else {
                    $entityHasPhoto = $false
                }
	        }      
            $AzEntityObject | Add-Member EntityHasPhoto $entityHasPhoto
            $entityDict.add($EntityId, $AzEntityObject)
        }
    }
}


# Add the detected Role to the Dictionary
function Add-RoleToDict {
    [CmdletBinding()]
    param(
        $RoleObject,
        [switch]
        $RbacRole
    )
    
    if ($RbacRole) {
        $RoleId = $RoleObject.Id
    }
    else {
        $RoleId = $RoleObject.ObjectId
    }

    if (-not $roleDict.contains($RoleId)) {  
        $roleDict.add($RoleId, $RoleObject)
    }
}


# Check for directory roles and add to the Dictionary
function Check-DirectoryRolesEntities {
    [CmdletBinding()]
    param(
    [string]
    $direcotryRoleName
    )    
    $role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq $direcotryRoleName}
    if ($role) {
        Add-RoleToDict -RoleObject $role
        $globalAdminDB = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Get-AzureADUser
        $globalAdminDB | foreach {
            Add-EntityToDict -AzEntityObject $_
            Add-PrivilegeAzureEntity -entityId $_.ObjectId -DirectoryTenantID $TenantId -PrivilegeReason $direcotryRoleName -RoleId $role.ObjectId
        }
    }
}


# Scan each tenant for its Azure Admins
function Run-TenantScan {
    [CmdletBinding()]
    param(
        [string]
        $TenantId,
        [string]
        $UsedUserPrincipalName,
        [string]
        $UsedUserId
    )

    $tenantObject = Get-AzureADTenantDetail
    if (-not $tenantDict.contains($TenantId)) {      
        $initialDomainName = $tenantObject.VerifiedDomains | Where-Object {$_.Initial} | select Name
        $tenantObject | Add-Member "InitialDomainName" $initialDomainName.Name
        $tenantDict.add($TenantId, $tenantObject)
    }
    if ($fullUserReconList){
        $usersLimit = 200000
        $allUsers = Get-AzureADUser -Top $usersLimit
        $allUsersNumber = $allUsers.count
        Write-Host "      Retrieving information on $allUsersNumber Azure AD users, great reconnaissance, check the results file in the end"  
        $allUsers | foreach {
            Add-EntityToDict -AzEntityObject $_
        }
    }
    <#
    1.  Global Administrator / Company Administrator - Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities.
    2.	Application Administrator - Users in this role can create and manage all aspects of enterprise applications.
    3.	Authentication Administrator - Users with this role can set or reset non-password credentials. 
    4.	Cloud Application Administrator - Users in this role have the same permissions as the Application Administrator role, excluding the ability to manage application proxy.
    5.	Password Administrator / Helpdesk Administrator - Users with this role can change passwords, invalidate refresh tokens, manage service requests.
    6.	Privileged Role Administrator - Users with this role can manage role assignments in Azure Active Directory.
    7.	User Account Administrator - Can manage all aspects of users and groups, including resetting passwords for limited admins.
    #>
    $privilegedDirectoryRoles = @("Company Administrator","Application Administrator", "Authentication Administrator",`
        "Password Administrator", "Privileged Authentication Administrator", "Cloud Application Administrator",`
        "Helpdesk Administrator", "Privileged Role Administrator", "User Account Administrator")
    $sensitiveDirectoryRoles = @("SharePoint Service Administrator", "Exchange Service Administrator","Conditional Access Administrator", "Security Administrator")

    $privilegedDirectoryRoles | foreach {
        Check-DirectoryRolesEntities -direcotryRoleName $_
    }
    $sensitiveDirectoryRoles | foreach {
        Check-DirectoryRolesEntities -direcotryRoleName $_
    }
}


# Scan each subscription for its Azure Admins
function Run-SubscriptionScan {
    [CmdletBinding()]
    param(
    [string]
    $subscriptionId
    )

    if (-not $subscriptionDict.contains($subscriptionId)) {      
        $subscriptionObject = Get-AzSubscription -SubscriptionId $subscriptionId
        $subscriptionDict.add($subscriptionId, $subscriptionObject)
    }
    $tenantId = $subscriptionDict[$subscriptionId].TenantId
    <#
    RABC privileged roles names:
	1. Owner
	2. Contributor
	3. User Access Administrator
    #>
    $privilegedSubscriptionRoles = @("Owner","Contributor", "User Access Administrator")
    $privilegedRBACPermissions = @("Microsoft.Authorization/*","Microsoft.Authorization/*/Write",`
    "Microsoft.Authorization/roleAssignments/*", "Microsoft.Authorization/roleDefinition/*",`
    "Microsoft.Authorization/roleDefinitions/*", "Microsoft.Authorization/elevateAccess/Action",`
    "Microsoft.Authorization/roleDefinition/write", "Microsoft.Authorization/roleDefinitions/write",`
    "Microsoft.Authorization/roleAssignments/write","Microsoft.Authorization/classicAdministrators/write")

    $privilegedRbacRoles = @()
    $allRbacRoles = Get-AzRoleDefinition
    $allRbacRoles | foreach {
        # If this is a built-in RBAC role
        if (-not $_.IsCustom) {
            if ($privilegedSubscriptionRoles -contains $_.Name) {
                Add-RoleToDict -RoleObject $_ -RbacRole
                $privilegedRbacRoles += $_
            }
        }
        # If this RBAC role is custom made
        else {
            $customRole = $_
            $_.Actions | foreach {
                if ($privilegedRBACPermissions -contains $_) {
                    Add-RoleToDict -RoleObject $customRole -RbacRole
                    $privilegedRbacRoles += $customRole
                }
            }
        }
    }
    # Get the entities with the privileged RBAC roles
    # handle the error case of "no classic admin could be queried" (if the subscription isn't legacy)
    try {
        $subscriptionRoleAssignments = Get-AzRoleAssignment -IncludeClassicAdministrators -ErrorAction Stop
    }
    catch {
        $subscriptionRoleAssignments = Get-AzRoleAssignment
    }
    # Check classic administrators:
    $subscriptionRoleAssignments | Where-Object {-not $_.RoleAssignmentId} | foreach {
        $PrivilegeReason = $_.RoleDefinitionName
        $userPrincipalName = $_.SignInName
        $AzEntityObject = Get-AzureADUser -Filter "userPrincipalName eq '$userPrincipalName'"
        # Check if the user is an external user
        if (-not $AzEntityObject) {
            Add-EntityToDict -AzEntityObject $userPrincipalName -externalUser
            Add-PrivilegeAzureEntity -entityId $userPrincipalName -SubscriptionID $subscriptionId -PrivilegeReason $PrivilegeReason -DirectoryTenantID $TenantId -ClassicAdmin #-RoleId $role.ObjectId 
        }
        else {
            if (-not $entityDict.contains($AzEntityObject.ObjectId)){
                Add-EntityToDict -AzEntityObject $AzEntityObject
            }
            Add-PrivilegeAzureEntity -entityId $AzEntityObject.ObjectId -SubscriptionID $subscriptionId -PrivilegeReason $PrivilegeReason -DirectoryTenantID $TenantId -ClassicAdmin #-RoleId $role.ObjectId 
        }
    }
    # Check for privileged RBAC roles
    $subscriptionRoleAssignments | Where-Object {$privilegedRbacRoles.Id -contains $_.RoleDefinitionId} | foreach {
        $rbacPrivilegedEntities = @()
        $PrivilegeReason = $_.RoleDefinitionName
        $roleId = $_.RoleDefinitionId
        [string]$scope = "/subscriptions/" + $subscriptionId
        if ([string]$_.scope -eq $scope) {
            if ($_.ObjectType -eq "User") {
                $rbacPrivilegedEntities += $_.ObjectId
            }
            elseif ($_.ObjectType -eq "Group") {
                $newGroupCount = 1
                $firstGroup = $true
                $groupFromGroups = @()
                Do {
                    if ($firstGroup) {
                        try {
			    $usersFromGroup = Get-AzureADGroupMember -ObjectId $_.ObjectId
			}
			catch {
			    Write-Verbose "Error with a specific group, maybe the Group is a foreign group and can't be queried"
			}
                    }
                    else {
                        $usersFromGroup = $groupFromGroups | Get-AzureADGroupMember -ObjectId $_.ObjectId
                    }
                    $firstGroup = $false
                    $usersFromGroup = $usersFromGroup | where {$_.ObjectType -eq "User"}
		    $usersFromGroup | foreach {
                        $rbacPrivilegedEntities += $_.ObjectId
                    }
                    $groupFromGroups = $usersFromGroup | where {$_.ObjectType -eq "Group"}
                    $newGroupCount = $groupFromGroups.count
                    $ownersOfGroup = @()
		    try {
		        $ownersOfGroup = Get-AzureADGroupOwner -ObjectId $_.ObjectId
                        $ownersOfGroup | foreach {
                            if (-not $entityDict.contains($_.ObjectId)){
                                $AzEntityObject = Get-AzureADUser -ObjectId $_.ObjectId
                                Add-EntityToDict -AzEntityObject $AzEntityObject
                            }
                            Add-PrivilegeAzureEntity -entityId $_.ObjectId -SubscriptionID $subscriptionId -PrivilegeReason "Privileged Group Owner" -RoleId $roleId -DirectoryTenantID $TenantId
                        }
		    }
		    catch {
		        Write-Verbose "Error with a specific group, maybe the Group is a foreign group and can't be queried"
		    }
                } While ($newGroupCount -ne 0)
            }
        }
    
        $rbacPrivilegedEntities | foreach {
            if (-not $entityDict.contains($_)){
                $AzEntityObject = Get-AzureADUser -ObjectId $_
                Add-EntityToDict -AzEntityObject $AzEntityObject
            }
            Add-PrivilegeAzureEntity -entityId $_ -SubscriptionID $subscriptionId -PrivilegeReason $PrivilegeReason -RoleId $roleId -DirectoryTenantID $TenantId
        }
    }
}


# Building the results file
function Write-AzureReconInfo {
    param(
    [string]
    $ResultsFolder,
    [switch]
    $CloudShellMode
    )
    if ($CloudShellMode) {
        $usersInfoPath = $resultsFolder + "/AzureUsers-Info.csv"
        $directoryInfoPath = $resultsFolder + "/AzureDirectory-Info.csv"
    }
    else {
        $usersInfoPath = $resultsFolder + "\AzureUsers-Info.csv"
        $directoryInfoPath = $resultsFolder + "\AzureDirectory-Info.csv"
    }
    $ofs = ','

    $entityReconOutput = @()

    $entityDict.Values | foreach {
        $entityReconLine = [PSCustomObject][ordered] @{
                UserPrincipalName          = [string]$_.UserPrincipalName
                DisplayName                = [string]$_.DisplayName
                ObjectType                 = [string]$_.ObjectType
                UserType                   = [string]$_.UserType
                AccountEnabled             = [string]$_.AccountEnabled
                JobTitle                   = [string]$_.JobTitle
                Department                 = [string]$_.Department
                Mail                       = [string]$_.Mail
                Mobile                     = [string]$_.Mobile
                TelephoneNumber            = [string]$_.TelephoneNumber
                PreferredLanguage          = [string]$_.PreferredLanguage
                MailNickName               = [string]$_.MailNickName
                GivenName                  = [string]$_.GivenName
                Surname                    = [string]$_.Surname
                EntityHasMailPhoto         = [string]$_.EntityHasPhoto
                CreatedDateTime            = [string]$_.ExtensionProperty.createdDateTime
                OnPremisesSecurityIdentifier = [string]$_.OnPremisesSecurityIdentifier
                DirSyncEnabled             = [string]$_.DirSyncEnabled
                LastDirSyncTime            = [string]$_.LastDirSyncTime
                RefreshTokensValidFromDateTime = [string]$_.RefreshTokensValidFromDateTime
                UsageLocation              = [string]$_.UsageLocation
                CompanyName                = [string]$_.CompanyName
                Country                    = [string]$_.Country
                State                      = [string]$_.State
                City                       = [string]$_.City
                StreetAddress              = [string]$_.StreetAddress
                PostalCode                 = [string]$_.PostalCode
                PhysicalDeliveryOfficeName = [string]$_.PhysicalDeliveryOfficeName
                FacsimileTelephoneNumber   = [string]$_.FacsimileTelephoneNumber
                IsCompromised              = [string]$_.IsCompromised
                ImmutableId                = [string]$_.ImmutableId
                CreationType               = [string]$_.CreationType
                PasswordPolicies           = [string]$_.PasswordPolicies
                PasswordProfile            = [string]$_.PasswordProfile
                ShowInAddressList          = [string]$_.ShowInAddressList
                SipProxyAddress            = [string]$_.SipProxyAddress
                DeletionTimestamp          = [string]$_.DeletionTimestamp
                ObjectId                   = [string]$_.ObjectId
        }       
        $entityReconOutput += $entityReconLine
    }
    $entityReconOutput | Sort-Object UserPrincipalName | Export-Csv -path $usersInfoPath -NoTypeInformation

    $tenantReconOutput = @()
    $tenantDict.Values | foreach {
        $tenantReconLine = [PSCustomObject][ordered] @{
                InitialDomainName      = [string]$_.InitialDomainName
                DisplayName            = [string]$_.DisplayName
                ObjectType             = [string]$_.ObjectType
                DirSyncEnabled         = [string]$_.DirSyncEnabled
                CompanyLastDirSyncTime = [string]$_.CompanyLastDirSyncTime
                Country                = [string]$_.Country
                CountryLetterCode      = [string]$_.CountryLetterCode
                PreferredLanguage      = [string]$_.PreferredLanguage
                State                  = [string]$_.State
                City                   = [string]$_.City
                PostalCode             = [string]$_.PostalCode
                Street                 = [string]$_.Street
                TelephoneNumber        = [string]$_.TelephoneNumber
                MarketingNotificationEmails = [string]$_.MarketingNotificationEmails
                TechnicalNotificationMails  = [string]$_.TechnicalNotificationMails
                SecurityComplianceNotificationMails   = [string]$_.SecurityComplianceNotificationMails
                SecurityComplianceNotificationPhones  = [string]$_.SecurityComplianceNotificationPhones
                AssignedPlans          = [string]$_.AssignedPlans
                ProvisionedPlans       = [string]$_.ProvisionedPlans
                ProvisioningErrors     = [string]$_.ProvisioningErrors
                DeletionTimestamp      = [string]$_.DeletionTimestamp
                ObjectId               = [string]$_.ObjectId
        }       
        $tenantReconOutput += $tenantReconLine
    }
    $tenantReconOutput | Sort-Object InitialDomainName | Export-Csv -path $directoryInfoPath -NoTypeInformation
}


# Output the results file
function Write-AzureStealthResults {
    [CmdletBinding()]
    param(
    [switch]
    $CloudShellMode
    )

    $azureAdminsResults = $privilegedAzEntitiesDict.Values | Sort-Object -Descending EntityType | Sort-Object PrivilegeType, EntityDisplayName, RoleId
    $azureAdminsList = $azureAdminsResults |  select EntityDisplayName
    $azureAdminsList = $azureAdminsList.EntityDisplayName | Sort-Object | Get-Unique
    $numberAdmins = $azureAdminsList.count
    Write-Host "`n  [+] Discovered $numberAdmins Azure Admins! Check them out :)" -ForegroundColor Yellow

    if (-not $cloudShellMode) {
        $resultsFolder = $PSScriptRoot + "\Results-" + $resultsTime
	$resultsFolderExists = Test-Path -Path $resultsFolder
	if (-not $resultsFolderExists) {
	    New-Item -ItemType directory -Path $resultsFolder > $null
	}
        $mainResultsPath = $resultsFolder + "\AzureStealth-Results.csv"
        $azureAdminsResults | Export-Csv -path $mainResultsPath -NoTypeInformation
        Write-AzureReconInfo -ResultsFolder $resultsFolder
        Write-Host "`n  [+] Completed the scan, the AzureStealth results should be presented in a new  window"
        Write-Host "`n      To get the results files - go to the results folder - in the following location:`n      `"$resultsFolder`""
        # In addition, present the results in an automated gridview using Out-GridView
        $resultsForGridView = @()
        $azureAdminsResults | foreach {$resultsForGridView += $_}
        $resultsForGridView | Out-GridView -Title "AzureStealth Results"
    }
    else {
	$cloudDriveInfo = Get-CloudDrive
	$localCloudShellPath = $cloudDriveInfo.MountPoint
        $resultsFolder = $localCloudShellPath + "/AzureStealth/Results-" + $resultsTime
        $resultsFolderExists = Test-Path -Path $resultsFolder
        if (-not $resultsFolderExists) {
	    New-Item -ItemType directory -Path $resultsFolder > $null
	}
        $resultCSVpath = $resultsFolder + "/AzureStealthScan-Results.csv"
        $azureAdminsResults | Export-Csv -path $resultCSVpath -NoTypeInformation
	Write-AzureReconInfo -ResultsFolder $resultsFolder -CloudShellMode
        $resultsZipPath = $localCloudShellPath + "/AzureStealth/Results-" + $resultsTime +".zip"
        Compress-Archive -Path $resultsFolder -CompressionLevel Optimal -DestinationPath $resultsZipPath -Update
        Export-File -Path $resultsZipPath
	$storageName = $cloudDriveInfo.Name
	$fileShareName = $cloudDriveInfo.FileShareName
        Write-Host "`n  [+] Completed the scan - the results zip file was created and available at:`n      $resultsZipPath`n"
        Write-Host "`n  [+] You can also use the Azure Portal to view the results files:"
        Write-Host "      Go to => `"The Storage Accounts' main view`" => `"$storageName`" => `"Files view`""
	Write-Host "      Choose the File Share: `"$fileShareName`""
        Write-Host "      In this File Share:"
        Write-Host "      Open the folders => `"AzureStealth`" and `"Results-"$resultsTime"`"`n"
    }
}


# Main function of AzureStealth scanning module
function Scan-AzureAdmins {
    [CmdletBinding()]
    param(
    [switch]
    $UseCurrentCred,
    [switch]
    $GetPrivilegedUserPhotos
    )

    $CloudShellMode = $false
    try {
        $cloudShellRun = Get-CloudDrive
	if ($cloudShellRun){
            $CloudShellMode = $true
	}
    }
    catch {
        $CloudShellMode = $false
    }
    $AzModule = $true
    if (-not $CloudShellMode) {
        $AzModule = Check-AzureModule
    }
    if ($AzModule -eq $false) {
        Return
    }
    if (-not $UseCurrentCred) {
        $AzConnection = Connect-AzureEnvironment
        if ($AzConnection -eq $false) {
            Return
        }
        $currentAzContext = Get-AzContext
    }
    else {
        $currentAzContext = Get-AzContext
    }
    if ($CloudShellMode) {
        try {
            Connect-AzureADservice
        }
        catch {
            Write-Host "Couldn't connect using the `"Connect-AzureADservice`" API call,`nThe tool will connect with `"Connect-AzureActiveDirectory `" call"
            $AzConnection = Connect-AzureActiveDirectory -AzContext $currentAzContext 
        }
    }
    else {
        $AzConnection = Connect-AzureActiveDirectory -AzContext $currentAzContext 
    }
    if ($AzConnection -eq $false) {
        $scanTheDirecotry = $false
        Write-host "Couldn't connect to the target Directory, the scan will continue but there might be errors" -ForegroundColor Yellow
    }

    $privilegedAzEntitiesOutput = @()
    $privilegedAzEntitiesDict = @{}
    $entityDict = @{}
    $tenantDict = @{}
    $subscriptionDict = @{}
    $roleDict = @{}
    [string]$resultsTime = Get-Date -Format "yyyyMMdd"

    # Output to a result file all the information that was collected on all the AAD users
    if ($GetPrivilegedUserPhotos){
        $fullUserReconList = $false
    }
    else {
        $fullUserReconList = $true
    } 

    try {
        Write-host "`n  [+] Running the scan with user: "$currentAzContext.Account
        $tenantList = Get-AzTenant
        Write-Host "`nAvailable Tenant ID/s:`n"
        Write-Host "  "($tenantList.Id | Format-Table | Out-String)
        $subscriptionList = Get-AzSubscription | select Name, Id, TenantId
        if ($subscriptionList) {
            Write-Host "Available Subscription\s:"
            Write-Host ($subscriptionList | Format-Table | Out-String) -NoNewline
        }
    }
    catch {
        Write-Host "Encountered an error - check again the inserted Azure Credentials" -BackgroundColor red
        Write-Host "There was a problem when trying to access the target Azure Tenant\Subscription" -BackgroundColor Red
        Write-Host "Please try again.." 
        Write-Host "You can also try different Azure user credentials or test the scan on a different environment" 
        Return
    }      

    $AzContextAutosave = (Get-AzContextAutosaveSetting).CacheDirectory
    if ($AzContextAutosave -eq "None") {
        Enable-AzContextAutosave
    }

    # Scan all the available tenant\s
    $tenantList| foreach {
        Write-Host "  [+] Scanning tenant ID: "$_.Id
        Set-AzContext -Tenant $_.id > $null
        $usedUser = Get-AzADUser -UserPrincipalName $currentAzContext.Account
        Run-TenantScan -TenantId  $_.id -UsedUserPrincipalName $usedUser.UserPrincipalName -UsedUserId $usedUser.Id
    }    

    # Scan all the available subscription\s
    $subscriptionList | foreach {
        Write-Host "`n  [+] Scanning Subscription Name: "$_.Name", ID: "$_.Id
        Set-AzContext -SubscriptionId $_.id > $null
        Run-SubscriptionScan -subscriptionId $_.id
    }
    
    Write-Host "`n  [+] Working on the results files"

    if ($CloudShellMode) {
    	Write-AzureStealthResults -CloudShellMode
    }
    else {
    	Write-AzureStealthResults
    }    
    if ($AzContextAutosave -eq "None") {
        Disable-AzContextAutosave
    }
    Write-Host "`n" 
}


# Alias function for starting the AzureStealth scan
function Scan-AzureShadowAdmins {
    Scan-AzureAdmins
}
