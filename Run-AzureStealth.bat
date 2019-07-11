@echo off
set var=%~d0%~p0%
cd "%var%"
set "var=%cd%\AzureStealth\AzureStealth.ps1"
echo.
echo  Welcome, starting AzureStealth scan
powershell -noprofile -ExecutionPolicy Bypass Import-Module '%var%' -force ; Scan-AzureAdmins
pause