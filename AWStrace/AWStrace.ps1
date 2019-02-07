<#

#######################################################
#                                                     #
#  AWStrace - Tool for analyzing AWS CloudTrail Logs  #
#                                                     #
#######################################################
#                                                     #
#                                                     #
#           Written by: Asaf Hecht (@Hechtov)         #
#                                                     #
#                                                     #
#######################################################

Welcome to SkyArk's AWStrace module.

It's time to analyze your CloudTrail logs & detect privileged actions.
Those sensitive action could have been triggered by potential attackers.

-------------------------------------------------------

Versions Notes:
Version 0.1 - 15.6.17
Version 0.2 - 8.4.18
Version 0.3 - 9.4.18
Version 1.0: RSA USA conference publication (19.4.18)

#>


$AWStraceVersion = "v1.0"

$AWStealth = @"
----------------------------------------------------
      __          _______ _                      
     /\ \        / / ____| |                     
    /  \ \  /\  / / (___ | |_ _ __ __ _  ___ ___ 
   / /\ \ \/  \/ / \___ \| __| '__/ _`` |/ __/ _ \
  / ____ \  /\  /  ____) | |_| | | (_| | (_|  __/
 /_/    \_\/  \/  |_____/ \__|_|  \__,_|\___\___|
                                                                                          
----------------------------------------------------
"@                                   

$Author = @"
          Author: Asaf Hecht - @Hechtov
	          CyberArk Labs
            Future updates via Twitter

----------------------------------------------------
"@

Write-Output $AWStealth
Write-Output "***   Welcome to SkyArk's AWStrace module $AWStraceVersion   ***`n"
Write-Output "It's time to analyze your CloudTrail logs &`nDetect privileged actions that could have been triggered by potential attackers`n"
Write-Output $Author

# Try loading the AWS PowerShell module
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
    Write-Host "`n[+] Loaded AWS credentials - $tempProfile [KeyID=$AccessKeyID,Region=$DefaultRegion]"

}


# Function to copy and download the CloudTrail log files from the trail's s3 bucket to a local folder
function Download-CloudTrailLogFiles {
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
        # The bucket's name where the CloudTrail log files are being stored
        [string]
        $TrailBucketName,
        # Filter with a given KeyPrefix the CloudTrail Bucket and download only the chosen log files
        [string]
        $BucketKeyPrefix,
        # A name of an existing profile to use
        [string]
        $ProfileName,
        # The local folder to save\load the downloaded CloudTrial log files
        [string]
        $LocalPath = $PSScriptRoot
    ) 

    # Load the AWS credentials
    $tempProfile = "AWStraceProfile"
    Load-AWScred -AccessKeyID $AccessKeyID -SecretKey $SecretKey -DefaultRegion $DefaultRegion -ProfileName $ProfileName -tempProfile $tempProfile
    if ($ProfileName) {
        Set-AWSCredential -ProfileName $ProfileName
    }
    else {
        Set-AWSCredential -ProfileName $tempProfile
    }
    # Check the needed parameters
    if (-not $TrailBucketName){
        Write-Warning "The tool didn't get the name of the CloudTrail bucket.`nIt cannot download the log files.. Please provide the trail's bucket name through the parameter `"TrailBucketName`""
        $TrailBucketName = read-host "Or - insert the `"TrailBucketName`" now:"
    }
    if (-not $BucketKeyPrefix){
        Write-Warning "The tool didn't get any KeyPrefix folder to filter the target bucket's files.`nThere could be lots of files.. Consider using the parameter `"BucketKeyPrefix`""
        $BucketKeyPrefix = read-host "Or - insert the `"BucketKeyPrefix`" now:"
    }
    if (-not $LocalPath){
        Write-Warning "The tool didn't get LocalPath to a local destination folder, it cannot download the log files.`nYou need to use `"LocalPath`" parameter"
        $LocalPath = read-host "Or - insert the `"LocalPath`" now:"
    }
    if ($BucketKeyPrefix[-1] -ne "/" -and $BucketKeyPrefix[-1] -ne '/'){
        $BucketKeyPrefix += "/"
    }

    $localPathZipped = $LocalPath + "\ZippedLogs"

    Write-Host "`n[+] Query the CloudTrail's bucket: `"$TrailBucketName`" with the KeyPrefix of `"$BucketKeyPrefix`""
    $objects = Get-S3Object -BucketName $TrailBucketName -KeyPrefix $BucketKeyPrefix

    if (-not $objects) {
        Write-Warning "Error - could not query the target Trail's bucket.`nIf the error is:`n    `"The bucket you are attempting to access must be addressed using the specified endpoint`"`nYou need to use different AWS region to query the target bucket, change the`"DefaultRegion`" parameter!`n"
    }
    else {
        $numberOfCloudTrailFiles = $objects.Length
        $percentOfFiles = [math]::Round($numberOfCloudTrailFiles/10)
        $counterFiles = 0
        $analyzedPercentage = 0

        Write-Host "`n[+] Discovered $numberOfCloudTrailFiles CloudTrail log files`nThe tool will save the logs in: $LocalPath`nIt could take a while.. (from 5 mins up to 5 hours and more - depends on how many logs are going to be downloaded)`nThe download process started, it will update on completion of every 10 percent...`n"

        # Start downloading each log file
        foreach($object in $objects) {
            $counterFiles += 1
	        $localFileName = $object.Key -replace $keyPrefix, ''
	        if ($localFileName -ne '') {
		        $localFilePath = Join-Path $localPathZipped $localFileName
		        Copy-S3Object -BucketName $TrailBucketName -Key $object.Key -LocalFile $localFilePath -ProfileName $tempProfile -Region $defaultRegion > $null
	        }
            if (($counterFiles % $percentOfFiles + 1) -eq  ($percentOfFiles - 2))
            {
                $analyzedPercentage += 10
                Write-Output "Downloaded $analyzedPercentage% of the CloudTrail files.."
            }
        }
        Write-Output "Finished downloading the files from the AWS s3 bucket."
    }

    # Unzip the local saved log files
    Unzip-CloudTrailFiles -LocalPath $LocalPath

    try {
        Remove-AWSCredentialProfile -ProfileName $tempProfile -force
        }
    catch {
        Write-Verbose "Could not remove the $tempProfile profile, it's probably doesn't exist."
    }
}




# Unzip function for GZ files, from https://social.technet.microsoft.com/Forums/windowsserver/en-US/5aa53fef-5229-4313-a035-8b3a38ab93f5/unzip-gz-files-using-powershell?forum=winserverpowershell
Function Unzip-GZfiles{
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$','')
        )

    $input = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)

    $buffer = New-Object byte[](1024)
    while($true){
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0){break}
        $output.Write($buffer, 0, $read)
        }

    $gzipStream.Close()
    $output.Close()
    $input.Close()
}


# Function to unzip the original CloutTrail files, it saves the new Uncompressed files in the same "LocalPath" folder under a new sub-folder "UnzippedLogs"
function Unzip-CloudTrailFiles {
    Param (
        [string]
        $LocalPath
    ) 

    if (-not $LocalPath)
    {
        Write-Warning "The tool didn't get LocalPath to a local destination folder, it cannot download the log files.`nYou need to use `"LocalPath`" parameter"
    }

    $localPathZipped = $LocalPath + "\ZippedLogs"
    if (-not (Test-Path $localPathZipped)){
        Write-Warning "Please check again the logs folder, and choose the `"LocalPath`" to be the folder that contains `"ZippedLogs`" folder. (and not the `"`"ZippedLogs`" path itself)"
    }
    $localPathUnzipped = $LocalPath + "\UnzippedLogs\"
    if (-not (Test-Path $localPathUnzipped)){
        New-Item -ItemType directory -Path $localPathUnzipped > $null
    }

    $CloudTrailsLogFiles = Get-ChildItem -Recurse -Path $localPathZipped
    
    $numberOfCloudTrailFiles = $CloudTrailsLogFiles.Length
    $percentOfFiles = [math]::Round($numberOfCloudTrailFiles/10)
    $counterFiles = 0
    $analyzedPercentage = 0
    
    Write-Output "`nDiscovered $numberOfCloudTrailFiles CloudTrail log files`nStarting to unzip them.."

    foreach ($item in $CloudTrailsLogFiles)
    {
        try {
            $counterFiles += 1
            if ((Get-Item $item.FullName) -is [System.IO.DirectoryInfo]){
                continue
            }
            else {
                $outputFile = $localPathUnzipped + $item.Name
                $outputFile = $outputFile.Substring(0,$outputFile.Length - 3) 
                Unzip-GZfiles -infile $item.FullName -outfile $outputFile
                if (($counterFiles % $percentOfFiles + 1) -eq  ($percentOfFiles - 2))
                {
                    $analyzedPercentage += 10
                    Write-Output "Unzipped $analyzedPercentage% of the CloudTrail files.."
                }
            }
        }
        catch {
            continue    
        }
    } 
    Write-Output "[+] Finished unzipping the log files to: $localPathUnzipped`n"
}


# Function for analyzing the CloudTrail logs
function Analyze-CloudTrailLogFiles {

    Param (
        # The local folder to load the previously downloaded CloudTrial log files
        [string]
        $LocalPath = $PSScriptRoot
    ) 

    if ($LocalPath[-1] -ne "\" -and $LocalPath[-1] -ne '\'){
        $LocalPath += "\"
    }
    $inputfolder = $LocalPath + "UnzippedLogs"
    $finalCSVpath = $LocalPath + "Full Analyzed Logs.csv"
    $prioritizedCSVpath = $LocalPath + "Sensitive IAM Actions.csv"

    if (-not (Test-Path $inputfolder)) {
        Write-Warning "Error - The `"LocalPath`" parameter is incorrect.. There is no `"UnzippedLogs`" folder inside.`nPlease choose another LocalPath and make sure you have downloaded the CloudTrail log files before - using `"Download-CloudTrailLogFiles`" function"
    }
    else {
        $CloudTrailsLogsFiles = Get-ChildItem -Recurse -Path $inputfolder

        $logObjects = @()
        $logListObjects = New-Object System.Collections.ArrayList
        $listSourceIPs = New-Object System.Collections.ArrayList
        $countNumberLogLines = 0
        $countLogsErrors = 0
        $countSAMLLogs = 0
        $numberOfCloudTrailFiles = $CloudTrailsLogsFiles.Length
        $analyzedLogFiles = 0
        $analyzedPercentage = 0
        $percentOfFiles = [math]::Round($numberOfCloudTrailFiles/10)
        Write-Output "`n[+] Discovered $numberOfCloudTrailFiles CloudTrail log files`nStarting to load and analyze the files..`n"
        $whoisIPDB = @{}

        foreach ($item in $CloudTrailsLogsFiles)
        {
            try{
                if ((Get-Item $item.FullName) -is [System.IO.DirectoryInfo]){
                    continue
                }
                else {
                    $inputFileName = $item.FullName
                    $oneLogObject = Get-Content -Raw -Path $inputFileName | ConvertFrom-Json
                    $analyzedLogFiles += 1
                    foreach ($value in $oneLogObject.psobject.properties.value)
                    {
                        # creates the structure to output the csv
                        try {
                            $userIdentityType = $value.userIdentity.type
                            $userIdentityPrincipleID = $value.userIdentity.principalId
                            $userIdentityARN = $value.userIdentity.arn
                            $userIdentityAccountID = $value.userIdentity.accountId
                            $userIdentityInvokedBy = $value.userIdentity.invokedBy
                            $userIdentityAccessKeyId = $value.userIdentity.accessKeyId
                            $userIdentityUserName = $value.userIdentity.userName
                            $MFA = $value.userIdentity.sessionContext.attributes.mfaAuthenticated

                            if ($value.sourceIPAddress -NotMatch "aws")
                            {
                                $listSourceIPs.Add($value.sourceIPAddress) > $null
                            }

                            $indexUpperCaseChar = 0
                            $actionCategory = ""
                            $charCounter = 0
                            # detect the first UpperCase char for the action's main category
                            $actionArray = ($value.eventName).ToCharArray()
                            foreach ($char in $actionArray) {
                                $charCounter += 1
                                if ($charCounter -gt 1) {
                                    if ($char -cmatch "[A-Z]"){
                                        $indexUpperCaseChar = $charCounter
                                        break
                                    }
                                }

                            }
                            $actionCategory = ($value.eventName).Substring(0, $charCounter - 1)

                            $timeDate = [DateTime]$value.eventTime
                            $dayDate = $timeDate.tostring("dd")
                            $monthDate = $timeDate.tostring("MM")
                            $yearDate = $timeDate.tostring("yyyy")
                            $dayOfTheWeek = $timeDate.tostring("dddd")
                                                                        
                            $ofs = " , "                        

                            $readAction =""
                            #$readActions = @("Describe", "Get", "List")
                            if ($actionCategory -eq "Describe" -or $actionCategory -eq "Get" -or $actionCategory -eq "List")
                            {
                                $actionType = "readAction"
                            }
                            else {
                                $actionType = "activeAction"
                            }

                            $credentailsType = ""
                            if ($userIdentityAccessKeyId) {
                                if ($MFA){
                                    $credentailsType = "TempSessionToken"
                                }
                                else {
                                    $credentailsType = "DirectAccessKey"
                                }
                            }

                            if ($value.errorCode){
                                $wasAnError = "True"
                            }
                            else {
                                $wasAnError = "-"
                            }

                            if ($userIdentityType -eq "Root") {
                                $userIdentityUserName = "RootAccount"
                            }

                            $logLine = [PSCustomObject][ordered] @{
                                # link for more details on the log's fields: http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
                                EntityUserName           = [string]$userIdentityUserName
                                EventName_TheAction      = [string]$value.eventName
                                ActionCategory           = [string]$actionCategory
                                ActionType               = [string]$actionType
                                GotError                 = [string]$wasAnError
                                EntityType               = [string]$userIdentityType
                                AccessKeyId              = [string]$userIdentityAccessKeyId
                                CredentailsType          = [string]$credentailsType
                                EventType                = [string]$value.eventType
                                EventTimeUTC             = [string]$value.eventTime
                                DayOfTheWeek             = [string]$dayOfTheWeek
                                Day                      = [string]$dayDate
                                Month                    = [string]$monthDate
                                Year                     = [string]$yearDate
                                InvokedBy                = [string]$userIdentityInvokedBy                       
                                EventSource              = [string]$value.eventSource
                                SourceAccountID          = [string]$userIdentityAccountID
                                RecipientAccountId       = [string]$value.recipientAccountId
                                # If the action was logged or used temporary security credentials, there will be a MFA field in the log:
                                LoginMFA                 = [string]$value.additionalEventData.MFAUsed
                                TempSessionMFA           = [string]$MFA
                                <#
                                More advanced fields regarding authentication and federation:
                                SessionIssuerType        = [string]$value.userIdentity.sessionContext.sessionIssuer.Type
                                SessionIssuerName        = [string]$value.userIdentity.sessionContext.sessionIssuer.userName
                                IssuedForARN             = [string]$value.userIdentity.sessionContext.sessionIssuer.arn
                                #identityProvider - The principal name of the external identity provider. This field appears only for SAMLUser or WebIdentityUser types:
                                IdentityProviderID       = [string]$value.userIdentity.identityProvider
                                WebIdFederation          = [string]$value.userIdentity.WebIdFederationData.federatedProvider
                                #RoleArn - The Amazon Resource Name (ARN) of the role that the caller assumed:
                                RoleAssumed          = [string]$value.requestParameters.RoleArn
                                #PrincipalArn - The Amazon Resource Name (ARN) of the SAML provider in IAM that describes the identity provider:
                                SAMLProvider             = [string]$value.requestParameters.PrincipalArn
                                #Issuer - The value of the Issuer element of the SAML assertion:
                                SAMLIssuer               = [String]$value.responseElements.issuer
                                #Audience - The value of the Recipient attribute of the SubjectConfirmationData element of the SAML assertion.
                                SAMLAudience             = [String]$value.responseElements.audience
                                #>
                                #The access key ID of the temporary security
                                ResponsedTokenID         = [String]$value.responseElements.credentials.accessKeyId
                                #When CreatAccessKey in use - the responsed AccessKeyId + the target username:
                                ResponsedAccessKeyID     = [String]$value.responseElements.accessKey.accessKeyId
                                ResponsedAccessKeyTarget = [String]$value.responseElements.accessKey.userName
                                PrincipleID              = [string]$userIdentityPrincipleID
                                ARN                      = [string]$userIdentityARN                        
                                AWSresources             = [string]$value.resources.arn
                                AwsRegion                = [string]$value.awsRegion
                                UserAgent                = [string]$value.userAgent
                                RequestParameters        = [string]$value.requestParameters.PSObject.Properties.Name
                                ResponseElements         = [string]$value.responseElements.PSObject.Properties.Name
                                ErrorCode                = [string]$value.errorCode
                                ErrorMessage             = [string]$value.errorMessage
                                RequestID                = [string]$value.requestID
                                EventID                  = [string]$value.eventID
                                SharedEventID            = [string]$value.sharedEventID
                                EventVersion             = [string]$value.eventVersion
                                SourceIP                 = [string]$value.sourceIPAddress
                                IPcountry                = [string]""
                                IPRegion                 = [string]""
                                IPCity                   = [string]""
                                IPHostName               = [string]""
                                IPOrganization           = [string]""
                                LogOriginalFilePath      = [string]$inputFileName
                            }                    
                        }
                        catch {
                            Write-Verbose "error in one of the log lines"
                            $countLogsErrors += 1
                        }
                        if ($value.eventVersion.length -gt 5){
                            $countLogsErrors += 1
                            continue
                        }
                        $countNumberLogLines += 1
                        $logListObjects.Add($logLine) > $null
                    }
                    if (($analyzedLogFiles % $percentOfFiles + 1) -eq  ($percentOfFiles - 2))
                    {
                        $analyzedPercentage += 10
                        Write-Output "Loaded $analyzedPercentage% of the log files"
                    }
                }
            }
            catch {
                continue    
            }
        }
        Write-Output "Finished analyzing all the logs"
        $logsDB = $logListObjects.ToArray()
        $ListIPs = $listSourceIPs.ToArray()
        $ListIPs = $ListIPs | select -uniq

        Write-Output "`n[+] Adding WhoIs information on the actions' source IP addresses.."
        try {
            Analyze-IP -infile $finalCSVpath -ListIPs $ListIPs -whoisIPDB $whoisIPDB
            foreach ($line in $logsDB) {
                if ($whoisIPDB.ContainsKey($line.sourceIP)){
                    $line.IPcountry = $whoisIPDB.($line.sourceIP).Country
                    $line.IPRegion = $whoisIPDB.($line.sourceIP).Region
                    $line.IPCity = $whoisIPDB.($line.sourceIP).City
                    $line.IPHostName = $whoisIPDB.($line.sourceIP).HostName
                    $line.IPOrganization = $whoisIPDB.($line.sourceIP).Organization
                }
            }
        }
        catch {
            Write-Warning "Sorry, could not get more information on the source IPs of the logged actions"
        }

        Write-Output "`n[+] Creating a prioritized csv file for sensitive IAM actions that were performed"
    
        # You can add to following filtering command more sensitive functions that you want to prioritized.
        # Currently the filter prioritizes only the 10 kinds of sensitive actions that might be part of a malicious scenario performed by AWS Shadow Admins
        $prioritizedActions = $logsDB | where {
            ($_.EventName_TheAction -eq "AddUserToGroup") -or
            ($_.EventName_TheAction -eq "CreateAccessKey") -or
            ($_.EventName_TheAction -eq "CreateLoginProfile") -or
            ($_.EventName_TheAction -eq "UpdateLoginProfile") -or
            ($_.EventName_TheAction -eq "AttachUserPolicy") -or ($_.EventName_TheAction -eq "AttachGroupPolicy") -or ($_.EventName_TheAction -eq "AttachRolePolicy") -or
            ($_.EventName_TheAction -eq "PutUserPolicy") -or ($_.EventName_TheAction -eq "PutGroupPolicy") -or ($_.EventName_TheAction -eq "PutRolePolicy") -or
            ($_.EventName_TheAction -eq "CreatePolicy") -or
            ($_.EventName_TheAction -eq "CreatePolicyVersion") -or ($_.EventName_TheAction -eq "SetDefaultPolicyVersion") -or
            ($_.EventName_TheAction -eq "PassRole") -or ($_.EventName_TheAction -eq "CreateInstanceProfile") -or($_.EventName_TheAction -eq "AddRoleToInstanceProfile") -or
            ($_.EventName_TheAction -eq "UpdateAssumeRolePolicy")
        }

        try {
            $logsDB | Export-Csv -NoTypeInformation $finalCSVpath
            $prioritizedActions | Export-Csv -NoTypeInformation $prioritizedCSVpath
            Write-Output "`n[+] Finished!`nTotal number of the analyzed logs: $countNumberLogLines`n`n[+] Check the final logs csv files:`n$finalCSVpath`n$prioritizedCSVpath`n"
        }
        catch {
            Write-Warning "Finished, but there was an error while trying to write the output CSV results file"
        }
    }
}


# Function for getting information on IPs
function Get-IPGeolocation
{
    Param
    (
        [string]
        $IPAddress
    )
    $ip = $IPAddress.Substring(8)
    $URL = "http://geoip.nekudo.com/api/" + $ip
    $requestFirst = Invoke-RestMethod -Method Get -Uri $URL
    $URL = "http://ipinfo.io/"  + $ip
    $requestSecond = Invoke-RestMethod -Uri $URL
    
    [PSCustomObject]@{
        IP           = $requestSecond.ip
        HostName     = $requestSecond.hostname
        City         = $requestSecond.city
        Region       = $requestSecond.region
        Country      = $requestFirst.country.name
        Organization = $requestSecond.org
        TimeZone  = $requestFirst.Location.Time_zone
    }
}


# Function for analyzing source IPs of the log events
function Analyze-IP {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [String]
        $infile,
        [Array]
        $ListIPs,
        [hashtable]
        $whoisIPDB
    )
    $numberIPs = $ListIPs.Length
    Write-Output "Got $numberIPs IPs to check"

    $whoIsDB = New-Object System.Collections.ArrayList
    $percentOfIPs = [math]::Round($numberIPs/10)
    $counterIP = 0
    $analyzedPercentage = 0
    foreach ($ip in $ListIPs)
    {
        $whoisObject = Get-IPGeolocation -IPAddress [string]$ip
        $whoIsDB.Add($whoisObject) > $null      
        $counterIP += 1
        if ($numberIPs -gt 50) {
            if (($counterIP % $percentOfIPs + 1) -eq  ($percentOfIPs - 2))
            {
                $analyzedPercentage += 10
                Write-Output "$analyzedPercentage% analyzed IPs"
            }
        }
    }
    Write-Output "Finished adding WhoIs information on the actions' source IPs"
    $whoIsDBobjects = $whoIsDB.ToArray()
    # create Hash Table for future quick search
    foreach($objectIP in $whoIsDBobjects){
        if (-Not $whoisIPDB.ContainsKey($objectIP.IP)){
            $whoisIPDB.add($objectIP.IP, $objectIP)
        }
    }
}
