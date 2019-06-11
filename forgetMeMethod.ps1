#requires -RunAsAdministrator 
<#
.SYNOPSIS
Execute Powershell code with Intune Management Extension, and have it run everytime IME reloads (about every hour)
.DESCRIPTION
Normally a script executed successfully through IME will never be run again.
The code in this script will erase the registry entry that tells IME that it has already run the script.
.REQUIREMENTS
This script must be run as with SYSTEM priviledges.
Executed in 64bit PowerShell.
.EXAMPLE
Assign the script to a test user or device in Intune, then restart the IME service on your test computer.
The script will run and generate output files in c:\windows\temp\ for your perusal...
.COPYRIGHT
MIT License, feel free to distribute and use as you like, please leave author information.
.AUTHOR
Michael Mardahl - @michael_mardahl on twitter - BLOG: https://www.iphase.dk
.DISCLAIMER
This script is provided AS-IS, with no warranty - Use at own risk!
Proof of Concept version! Could use alot of cleanup :)
#>
Start-Transcript -Path "$($env:windir)\temp\forgetMeScript_log.txt"

### Do something that you want IME to repeat everytime it runs configuration scripts (every hour or so).
# put your code in the TRY block - The FINALLY block will make sure that even if your code fails, Intune will still run your script again.

try {

    Write-Output "Ran the forgetMeMethod on $((get-date).DateTime)" >> "$($env:windir)\temp\forgetMeScript_log_proof.txt"

} finally {
    ### These aren't the droids you're looking for...

    # starting the process that will remove this scripts policy from IME after it has run... (can't really do it while it's running!)
    # getting the name of the script file as it is run by IME
    # NOTICE! this will ONLY work when run by IME, so testing is not really easy.
    $scriptName = $MyInvocation.MyCommand.Name.Split(".")[0]
    $userGUID = $scriptName.Split("_")[0]
    $policyGUID = $scriptName.Split("_")[1]

    # generating the reg key path that we need to remove in order to have IME forget it ever ran this script.
    $regKey = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Policies\$userGUID\$policyGUID"

    # where to log the delete process
    $removalOutput = "$($env:windir)\temp\forgetMeScript_job_log.txt"

    # the delete registry key script (don't tab this code, it will break)
$deleteScript = @'
start-transcript "{0}";
Start-Sleep -Seconds 30;
Remove-Item -path "{1}" -Force -confirm:$false;
Write-Output "Next line should say false if all whent well...";
Test-Path -path "{1}";
Stop-Transcript;
'@ -f $removalOutput,$regKey

    $deleteScriptName = "c:\windows\temp\delete_$policyGUID.ps1"
    $deleteScript | Out-File $deleteScriptName -Force

    # starting a seperate powershell process that will wait 30 seconds before deleting the IME Policy registry key.
    $deleteProcess = New-Object System.Diagnostics.ProcessStartInfo "Powershell";
    $deleteProcess.Arguments = "-File " + $deleteScriptName
    $deleteProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($deleteProcess);

    Stop-Transcript
    exit
}


