<#
.SYNOPSIS
    This script runs a specified script block every 20 minutes and logs the output to a file.

.DESCRIPTION
    The script uses a scheduled job to run a specified script block every 20 minutes. The output of the script block is logged to a file.

.NOTES
    Ensure you have the necessary permissions to create and manage scheduled jobs.
#>

# Check if running as administrator
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You need to run this script as an administrator."
    Exit
}

# Define the script block to be executed
$scriptBlock = {
    # Define the log file path
    $logFilePath = "C:\lab\lab4\RecurringAttackSurfaceMappingScriptLog.txt"

    # Ensure the directory exists
    $logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory | Out-Null
    }
    Start-Transcript -Path $using:logFilePath -Append
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] Running recurring script block..."


    # Get the nonce first
    roadrecon auth --prt-init 

    # Get a new PRT Cookie
    .\ROADtoken.exe <nonce> 

    # this will AUTOMATICALLY open a browser and log in as that user (!)
    roadrecon auth -r msgraph -c "1950a258-227b-4e31-a9cf-717495945fc2" --prt-cookie $prtToken 
    <eyJh... PRT COOKIE>
    Stop-Transcript
}

# Check if the scheduled job already exists
$jobName = "RecurringAttackSurfaceMappingScript"
$existingJob = Get-ScheduledJob -Name $jobName -ErrorAction SilentlyContinue

if ($null -eq $existingJob) {
    # Define the job trigger to run every 20 minutes
    $trigger = New-JobTrigger -Once -At (Get-Date).AddMinutes(20) -RepetitionInterval (New-TimeSpan -Minutes 20) -RepetitionDuration ([TimeSpan]::MaxValue)

    # Register the scheduled job
    Register-ScheduledJob -Name $jobName -ScriptBlock $scriptBlock -Trigger $trigger -MaxResultCount 1

    Write-Output "Scheduled job '$jobName' created to run every 20 minutes."
} else {
    # Update the existing job with the new script block
    Set-ScheduledJob -Name $jobName -ScriptBlock $scriptBlock

    Write-Output "Scheduled job '$jobName' already exists. Script block updated."
}