<#

#################################################################
#                                                               #  
#           AWSHostRecon - AWS Host Reconnaissance Tool         #
#                                                               #
#################################################################
#                                                               #
#                                                               #
#               Written by: Asaf Hecht (@Hechtov)               #
#                    More Updates on Twitter                    #
#                                                               #
#                                                               #
#################################################################


Welcome to AWSHostRecon.
It's time to discover critical AWS informaiton on the target hosts.

#################################################################

Versions Notes:
 
Version 0.1: 8.1.19

#>

$AWStealthVersion = "v0.1"

$AWStealth = @"
---------------------------------------------------------------------------

      __          _______ _    _           _   _____                       
     /\ \        / / ____| |  | |         | | |  __ \                      
    /  \ \  /\  / / (___ | |__| | ___  ___| |_| |__) |___  ___ ___  _ __   
   / /\ \ \/  \/ / \___ \|  __  |/ _ \/ __| __|  _  // _ \/ __/ _ \| '_ \  
  / ____ \  /\  /  ____) | |  | | (_) \__ \ |_| | \ \  __/ (_| (_) | | | | 
 /_/    \_\/  \/  |_____/|_|  |_|\___/|___/\__|_|  \_\___|\___\___/|_| |_| 
                                                                           
                                                                                                                                                                                                                      
---------------------------------------------------------------------------
"@                                   

$Author = @"
                      Author:  Asaf Hecht - @Hechtov
                               CyberArk Labs
                        Future updates via Twitter

---------------------------------------------------------------------------

"@

Write-Output $AWStealth
Write-Output "`n                  ***   Welcome to AWSHostRecon $AWStealthVersion   ***"
Write-Output "                       AWS Host Reconnaissance Tool`n"
Write-Output $Author



# Search for AWS environment variables
function Scan-AWSEnvironmentVariables {
    #Param (
    #    [boolean]
    #    $foundAWSenvironmentVariables
    #)
    $foundAWSenvironmentVariables = $false

    $envVars = (get-item env:) | where {($_.Name -eq "AWS_CONFIG_FILE") -or ($_.Name -eq "AWS_CREDENTIAL_FILE") -or ($_.Name -eq "AWS_SHARED_CREDENTIALS_FILE") -or ($_.Name -eq "BOTO_CONFIG")}
    if ($envVars) {
        $foundAWSenvironmentVariables = $true
        Write-host "[+] Found AWS environment variables on the machine, the findings:"
        $envVars | foreach {
            $envName = "        " +$_.Name
            $envValue = $_.Value
         Write-host $envName" :: "$envValue
         }
    }
    else {
        Write-host "[-] Didn't find AWS environment variables on the machine"
    }

    return $foundAWSenvironmentVariables
}

# Search for local AWS credentials files
function Scan-localAWScredFile {
    [CmdletBinding()]
    #Param (
    #    [array]
    #    $foundAWScredFiles
    #)

    $foundAWScredFiles = @()

    $mainUsersFolder = "C:\Users"
    $usersfolders = Get-ChildItem -Path $mainUsersFolder -Directory -Force -ErrorAction SilentlyContinue
    $usersfolders | foreach {
        $foundFile = $false
        $localAWScredPath = $mainUsersFolder + "\" + $_.Name + "\.aws\credentials"
        $foundFile = Test-Path $localAWScredPath
        if ($foundFile) {
            $foundAWScredFiles += $localAWScredPath
        }
    }
    # Check via the userprofile environment variable
    $localAWScredPath = (Get-Childitem env:userprofile).value
    $localAWScredPath = $localAWScredPath + "\.aws\credentials"
    $foundFile = $false
    $foundFile = Test-Path $localAWScredPath
    if ($foundFile) {
        if ($foundAWScredFiles -notcontains $localAWScredPath) {
            $foundAWScredFiles += $localAWScredPath
        }
    }
        
    if ($foundAWScredFiles) {
        Write-host "[+] Found AWS local credentials files:"
        $foundAWScredFiles | foreach {
            $temp = "        "+$_
            Write-host $temp
        }
    }
    else {
        Write-host "[-] Didn't find AWS local credentials files in the default locations"
    }
    return $foundAWScredFiles
}


# Read the discovered local AWS credentials files
function Get-localAWScred {
    $foundAWScredDB = @{}
    $foundKeys = @{}
    #$foundAWScredList = @()
    $numKeysFound = 0
    $foundAWScredFiles | foreach {
        $localAWScredPath = $_
        $localCredFile = Get-Content -Path $localAWScredPath
        $line = 0
        $profileLines = @()
        $localCredFile | foreach {
            $line++
            if ($_ -like '`[*`]') {
                $profileLines += $line
            }
        }
        $profileLines | foreach {
            $profileName = $localCredFile[$_-1]
            $accessKeyID = ((($localCredFile[$_]).Split("="))[1]) -replace '\s',''
            $secretKey = ((($localCredFile[$_+1]).Split("="))[1]) -replace '\s',''
            $keyInfo = @($localAWScredPath, $profileName, $accessKeyID, $secretKey)
            $foundKeys[$accessKeyID] = $secretKey

            if (-not $foundAWScredDB.ContainsKey($localAWScredPath)) {
                $foundAWScredDB[$localAWScredPath] = $keyInfo
            }
            else {
                $foundAWScredDB[$localAWScredPath] += $keyInfo
            }

            #$foundAWScredList += $keyInfo

            $numKeysFound ++
        }
    }

    if ($foundKeys) {
        $numUniqueKeys = $foundKeys.Count
        Write-Host "[+] Found $numUniqueKeys AWS access keys in default locations:"
        $foundKeys.Keys | foreach {
             $keyOutput = "        " + $_ + " : " + $foundKeys[$_]
             Write-Host $keyOutput
        }
    }

    return $foundAWScredDB
}



# Search for folder with the name of AWS
function Scan-SavedPwdBrowsers {
    
    $usersfolders = Get-ChildItem -Path $mainUsersFolder -Directory -Include *aws* -Force -ErrorAction SilentlyContinue

    return
}


# Scan browsers for AWS history and bookmarks
function Scan-AWSbrowserData {
    $foundAWSbrowsersData = @()
    $awsURLlist = @()
    $browserResults = Get-BrowserData
    $awsBrowsersData = $browserResults | Where-Object {$_.Data -like "*aws*"} | foreach {
        $awsBrowserInfo = @($_.Browser, $_.User, $_.DataType, $_.Data)
        $foundAWSbrowsersData += $awsBrowserInfo
        #$browserOutputLine = $_.Data + "    used by username " + $_.User + "    in browser " + $_.Browser
        $browserOutputLine = $_.Data
        $awsURLlist += $browserOutputLine 
    }
    $numAwsURLs = $awsURLlist.count
    if ($awsURLlist) {
        Write-Host "[+] Found $numAwsURLs AWS URL fingerprints from browsers history and bookmarks:"
        $awsURLlist | foreach {
        $keyOutput = "        " + $_
        Write-Host $keyOutput
        }
    }
    else {
        Write-host "[-] Didn't find AWS URL fingerprints from browsers history and bookmarks"
    }

    return $foundAWSbrowsersData
}


# Scan for AWS folders
function Scan-AWSfolders {
    
    $foundAWSfolders = @()
    $folderListRecurse = @()

    # Search python path
    $folderListRecurse += (Get-Childitem env:python -ErrorAction SilentlyContinue).value
    # Search TEMP path
    $folderListRecurse += (Get-Childitem env:TEMP -ErrorAction SilentlyContinue).value
    # Search CommonProgramFiles path
    $folderListRecurse += (Get-Childitem env:CommonProgramFiles -ErrorAction SilentlyContinue).value
    # Search ProgramData path
    $folderListRecurse += (Get-Childitem env:ProgramData -ErrorAction SilentlyContinue).value
    # Search CommonProgramW6432 path
    $folderListRecurse += (Get-Childitem env:CommonProgramW6432 -ErrorAction SilentlyContinue).value
    # Search PSModulePath path
    $folderListRecurse += (Get-Childitem env:PSModulePath -ErrorAction SilentlyContinue).value
    # Search the Users folder
    $userCpath = "C:\Users"
    $foundFolder = Test-Path $userCpath
    if ($foundFolder) {
        $folderListRecurse += $userCpath
    }
    $usersFolder = ((Get-Childitem env:userprofile -ErrorAction SilentlyContinue).value).Substring(0, (((Get-Childitem env:userprofile).value).LastIndexOf("\")))
    if ($usersFolder) {
        if ($usersFolder -ne $userCpath) {
            $folderListRecurse += $usersFolder
        }
    }

    $folderListNoRecurse = @()
    # Search ProgramFiles x86 path
    $folderListNoRecurse += (Get-Childitem env:ProgramFiles`(x86`) -ErrorAction SilentlyContinue).value
    # Search ProgramW6432 path
    $folderListNoRecurse += (Get-Childitem env:ProgramW6432 -ErrorAction SilentlyContinue).value
    # Search ProgramFiles path
    $folderListNoRecurse += (Get-Childitem env:ProgramFiles -ErrorAction SilentlyContinue).value
    # Search windir path
    $folderListNoRecurse += (Get-Childitem env:windir -ErrorAction SilentlyContinue).value
    
    $folderListRecurse | foreach {
        Get-ChildItem -Path $_ -Directory -Recurse -Include *aws* -Force -ErrorAction SilentlyContinue | foreach {
            $foundAWSfolders += $_.FullName
        }
    }

    $folderListNoRecurse | foreach {
        Get-ChildItem -Path $_ -Directory -Include *aws* -Force -ErrorAction SilentlyContinue | foreach {
            $foundAWSfolders += $_.FullName
        }
    }

    $foundAWSfolders = $foundAWSfolders | Sort-Object -Unique
    $numAwsFolders = $foundAWSfolders.count
    if ($foundAWSfolders) {
        Write-Host "[+] Found $numAwsFolders AWS folders in popular locations:"
        $num = 0 
        $manyResults =$false
        $foundAWSfolders | foreach {
            $num++
            if ($manyResults) {
                return $foundAWSfolders
            }
            if ($num -le 20) {
                $keyOutput = "        " + $_
                Write-Host $keyOutput
            }
            else {
                Write-Host "        ..."
                Write-Host "        ..."
                Write-Host "        ..."
                Write-Host "        Found many folders.. check the final results file for the full list"
                $manyResults = $true
                return
            }
        }
    }
    else {
        Write-host "[-] Didn't find AWS folders in popular locations"
    }

    return $foundAWSfolders
}


# Scan for AWS files
function Scan-AWSfiles {
    
    $foundAWSfiles = @()
    $filesListRecurse = @()

    # Search UserProfile path (e.g. C:\Users\UserName)
    $filesListRecurse += (Get-Childitem env:userprofile -ErrorAction SilentlyContinue).value
    # Search python path
    $filesListRecurse += (Get-Childitem env:python -ErrorAction SilentlyContinue).value
    # Search TEMP path
    $filesListRecurse += (Get-Childitem env:TEMP -ErrorAction SilentlyContinue).value
    # Search CommonProgramFiles path
    $filesListRecurse += (Get-Childitem env:CommonProgramFiles -ErrorAction SilentlyContinue).value
    # Search ProgramData path
    $filesListRecurse += (Get-Childitem env:ProgramData -ErrorAction SilentlyContinue).value
    # Search CommonProgramW6432 path
    $filesListRecurse += (Get-Childitem env:CommonProgramW6432).value
    # Search PSModulePath path
    $filesListRecurse += (Get-Childitem env:PSModulePath).value
    # Search the Users folder
    (Get-Childitem env:userprofile)
    $userCpath = "C:\Users"
    $foundFolder = Test-Path $userCpath
    if ($foundFolder) {
        $filesListRecurse += $userCpath
    }
    $usersFolder = ((Get-Childitem env:userprofile -ErrorAction SilentlyContinue).value).Substring(0, (((Get-Childitem env:userprofile).value).LastIndexOf("\")))
    if ($usersFolder) {
        if ($usersFolder -ne $userCpath) {
            $filesListRecurse += $usersFolder
        }
    }

    $filesListRecurse | foreach {
        Get-ChildItem -Path $_ -File -Recurse -Include *aws* -Force -ErrorAction SilentlyContinue | foreach {
            $foundAWSfiles += $_.FullName
        }
    }

    $foundAWSfiles = $foundAWSfiles | Sort-Object -Unique
    $numAwsFiles = $foundAWSfiles.count
    if ($foundAWSfiles) {
        Write-Host "[+] Found $numAwsFiles AWS files in popular locations:"
        $num = 0 
        $manyResults =$false
        $foundAWSfiles | foreach {
            $num++
            if ($manyResults) {
                return $foundAWSfolders
            }
            if ($num -le 20) {
                $keyOutput = "        " + $_
                Write-Host $keyOutput
            }
            else {
                Write-Host "        ..."
                Write-Host "        ..."
                Write-Host "        ..."
                Write-Host "        Found many files.. check the final results file for the full list"
                $manyResults = $true
                return
            }
        }
    }
    else {
        Write-host "[-] Didn't find AWS files in popular locations"
    }

    return $foundAWSfiles
}





# Main function
function Scan-HostForAWS {
    $time = New-Object system.Diagnostics.Stopwatch  
    $time.Start()

    Write-Host "Starting the scan..."
    Write-Host ""
    $foundAWSenvironmentVariables = Scan-AWSEnvironmentVariables
    Write-Host ""
    $foundAWScredFiles = Scan-localAWScredFile
    Write-Host ""
    if ($foundAWScredFiles) {
        $foundAWScredDB = Get-localAWScred
    }
    Write-Host ""
    $foundAWSbrowsersData = Scan-AWSbrowserData
    Write-Host ""
    $foundAWSfolders = Scan-AWSfolders
    Write-Host ""
    $foundAWSfiles = Scan-AWSfiles 

    #$foundSavedPwdBrowsers = Scan-SavedPwdBrowsers

    $time.Stop()
    $runtime = $time.Elapsed.TotalMilliseconds
    $runtime = ($runtime/1000)
    $runtimeMin = ($runtime/60)
    $runtimeHours = ($runtime/3600)
    $runtime = [math]::round($runtime , 2)
    $runtimeMin = [math]::round($runtimeMin , 2)
    $runtimeHours = [math]::round($runtimeHours , 3)
    Write-Host "`nTotal time of the scan: $runtimeMin Minutes, $runtimeHours Hours`n"
}



########################################################################################################################
# Get-BrowserData was taked from the Open Source repository: https://github.com/rvrsh3ll/Misc-Powershell-Scripts
# Thanks @424f424f
function Get-BrowserData {
<#
    .SYNOPSIS
        Dumps Browser Information
        Author: @424f424f
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION
        Enumerates browser history or bookmarks for a Chrome, Internet Explorer,
        and/or Firefox browsers on Windows machines.
#>
    # Small modification for the following hard-coded parameters:
    $Browser = 'All'
    $DataType = 'All'
    $Search = ''

    function ConvertFrom-Json20([object] $item){
        #http://stackoverflow.com/a/29689642
        Add-Type -AssemblyName System.Web.Extensions
        $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        return ,$ps_js.DeserializeObject($item)
        
    }
    
    # Small modification for searching all the users on the machine:
    $usersPath = "$Env:systemdrive\Users\"
    $userList = Get-ChildItem -Path $usersPath -Directory
    $userList | foreach {
        $UserName = $_.Name

        function Get-ChromeHistory {
            $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
            if (-not (Test-Path -Path $Path)) {
                Write-Verbose "[!] Could not find Chrome History for username: $UserName"
            }
            $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History" -ErrorAction SilentlyContinue |Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
            $Value | ForEach-Object {
                $Key = $_
                if ($Key -match $Search){
                    New-Object -TypeName PSObject -Property @{
                        User = $UserName
                        Browser = 'Chrome'
                        DataType = 'History'
                        Data = $_
                    }
                }
            }        
        }
        function Get-ChromeBookmarks {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find FireFox Bookmarks for username: $UserName"
        }   else {
                $Json = Get-Content $Path
                $Output = ConvertFrom-Json20($Json)
                $Jsonobject = $Output.roots.bookmark_bar.children
                $Jsonobject.url |Sort -Unique | ForEach-Object {
                    if ($_ -match $Search) {
                        New-Object -TypeName PSObject -Property @{
                            User = $UserName
                            Browser = 'Chrome'
                            DataType = 'Bookmark'
                            Data = $_
                        }
                    }
                }
            }
        }
        function Get-InternetExplorerHistory {
            #https://crucialsecurityblog.harris.com/2011/03/14/typedurls-part-1/

            $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
            $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

            ForEach($Path in $Paths) {

                $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value

                $Path = $Path | Select-Object -ExpandProperty PSPath

                $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
                if (-not (Test-Path -Path $UserPath)) {
                    Write-Verbose "[!] Could not find IE History for SID: $Path"
                }
                else {
                    Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $Key = $_
                        $Key.GetValueNames() | ForEach-Object {
                            $Value = $Key.GetValue($_)
                            if ($Value -match $Search) {
                                New-Object -TypeName PSObject -Property @{
                                    User = $UserName
                                    Browser = 'IE'
                                    DataType = 'History'
                                    Data = $Value
                                }
                            }
                        }
                    }
                }
            }
        }
        function Get-InternetExplorerBookmarks {
            $URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
            ForEach ($URL in $URLs) {
                if ($URL.FullName -match 'Favorites') {
                    $User = $URL.FullName.split('\')[2]
                    Get-Content -Path $URL.FullName | ForEach-Object {
                        try {
                            if ($_.StartsWith('URL')) {
                                # parse the .url body to extract the actual bookmark location
                                $URL = $_.Substring($_.IndexOf('=') + 1)

                                if($URL -match $Search) {
                                    New-Object -TypeName PSObject -Property @{
                                        User = $User
                                        Browser = 'IE'
                                        DataType = 'Bookmark'
                                        Data = $URL
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Error parsing url: $_"
                        }
                    }
                }
            }
        }
        function Get-FireFoxHistory {
            $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
            if (-not (Test-Path -Path $Path)) {
                Write-Verbose "[!] Could not find FireFox History for username: $UserName"
            }
            else {
                $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
                $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
                $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
                $Value.Value |ForEach-Object {
                    if ($_ -match $Search) {
                        ForEach-Object {
                        New-Object -TypeName PSObject -Property @{
                            User = $UserName
                            Browser = 'Firefox'
                            DataType = 'History'
                            Data = $_
                            }    
                        }
                    }
                }
            }
        }
        Get-ChromeHistory
        Get-ChromeBookmarks
        Get-InternetExplorerHistory
        Get-InternetExplorerBookmarks
        Get-FireFoxHistory
     }   
}
########################################################################################################################
#>

# Start the scan
Scan-HostForAWS

<#
function x([ref]$y) {
    $y.Value=2
}
$y = 1
$y
x([ref]$y)
$y
#>


