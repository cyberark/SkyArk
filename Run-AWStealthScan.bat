@echo off
set var=%~d0%~p0%
cd "%var%"
set "var=%cd%\AWStealth\AWStealth.ps1"
echo.
echo  Welcome, starting AWStealth scan
powershell -noprofile -ExecutionPolicy Bypass Import-Module '%var%' -force ; Scan-AWShadowAdmins
pause