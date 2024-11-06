param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [string]$DomainUser,

    [Parameter(Mandatory = $true)]
    [string]$DomainPassword
)

# Start logging
Start-Transcript -Path "c:\labPrepareLog.txt" -Append
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

# Log the accepted arguments
Write-Output "DomainName: $DomainName"
Write-Output "DomainUser: $DomainUser"
Write-Output "DomainPassword: $DomainPassword"
# Convert the plain text password to a secure string
$DomainPasswordSecured = ConvertTo-SecureString $DomainPassword -AsPlainText -Force

function Copy-DirectoryContentToWindows {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceDir
    )

    # Check if the source directory exists
    if (-Not (Test-Path -Path $SourceDir -PathType Container)) {
        Write-Output "The source directory does not exist."
        return
    }

    # Define the destination directory
    $destinationDir = "C:\Windows"

    # Get all files and directories in the source directory
    $items = Get-ChildItem -Path $SourceDir -Recurse

    foreach ($item in $items) {
        # Define the destination path for each item
        $destinationPath = Join-Path -Path $destinationDir -ChildPath ($item.FullName -replace [regex]::Escape($SourceDir), "")

        # Create the destination directory if it doesn't exist
        if (-Not (Test-Path -Path (Split-Path -Path $destinationPath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path -Path $destinationPath -Parent) | Out-Null
        }

        # Move the item to the destination
        Copy-Item -Path $item.FullName -Destination $destinationPath -Force
    }
}


# Disable AV
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/disableAv.ps1" -OutFile "C:\\DisableAV.ps1"; & "C:\\DisableAV.ps1"
if ($?) {
    Write-Output "disableAv.ps1 downloaded and ran successfully."
}
else {
    Write-Output "disableAv.ps1 Failed to download and run."
}

if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) {
    Write-Output "This is a Windows Server system."

    function Disable-IEESC {
        Write-Output "Disabling IE Enhanced Security Configuration (ESC)..."
    
        # Disable for Administrators
        $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    
        # Disable for Users
        $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
        Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    
        # Restart Explorer to apply changes
        Stop-Process -Name Explorer -Force
    
        Write-Output "IE Enhanced Security Configuration (ESC) has been disabled."
    }
    
    Disable-IEESC

    # Create 40 dummy domain users and add them to Domain Admins group
    Write-Output "Creating 40 dummy domain users and adding them to Domain Admins group..."
    for ($i = 1; $i -le 40; $i++) {
        $username = "user$i"
        try {
            New-ADUser `
                -Name "$username victim" `
                -GivenName "$username" `
                -Surname "victim" `
                -SamAccountName "$username" `
                -AccountPassword $DomainPasswordSecured `
                -ChangePasswordAtLogon $False `
                -Company "Victim Company Inc." `
                -Title "CEO" `
                -State "California" `
                -City "San Francisco" `
                -Description "victim user account for the lab" `
                -EmployeeNumber "45" `
                -Department "Engineering" `
                -DisplayName "$username" `
                -Country "us" `
                -PostalCode "90210" `
                -Enabled $True    

            Add-ADGroupMember -Identity "Domain Admins" -Members $username
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
        }
    }

    Write-Output "Downloading AzureADConnect.msi to Desktop..."
    # Download AzureADConnect.msi to Desktop
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi" -OutFile "$desktopPath\AzureADConnect.msi"
    if ($?) {
        Write-Output "adconnect downloaded and ran successfully."
    }
    else {
        Write-Output "adconnect Failed to download and run."
    }

    # Write-Output "Downloading and extracting BadBlood zip file..."
    # # Download and extract BadBlood zip file
    # $zipUrl = "https://github.com/davidprowe/BadBlood/archive/refs/heads/master.zip"
    # $zipPath = "$desktopPath\BadBlood.zip"
    # Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
    # Expand-Archive -Path $zipPath -DestinationPath $desktopPath
    # if ($?) {
    #     Write-Output "badblood downloaded and ran successfully."
    # } else {
    #     Write-Output "badblood Failed to download and run."
    # }
    # Run the extracted BadBlood script
    #$badBloodScript = "$desktopPath\BadBlood-master\invoke-badblood.ps1"
    #Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $badBloodScript" -Verb RunAs
}
else {
    Write-Output "This is a Windows Client system."
    Write-Output "Getting the network adapter..."
    # Get the network adapter
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

    Write-Output "Setting the primary and secondary DNS servers..."
    # Set the primary and secondary DNS servers
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("10.0.0.4", "8.8.8.8")
    if ($?) {
        Write-Output "DNS servers have been set to 10.0.0.4 and 8.8.8.8."
    }
    else {
        Write-Output "DNS servers failed to be set"
    }
}


############################
# Install PS, Python and attack tools
################################

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
if ($?) {
    Write-Output "PowerShellGet has been installed."
}
else {
    Write-Output "PowerShellGet failed to be installed."
}

write-output "Installing Azure CLI..."
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
if ($?) {
    Write-Output "Azure CLI has been installed."
}
else {
    Write-Output "Azure CLI failed to be installed."
}

write-output "Installing Python..."
# Define the URL for the Python installer
$pythonInstallerUrl = "https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe"

# Define the path to save the installer
$installerPath = "$env:TEMP\python-3.9.7-amd64.exe"
$env:Path += ";$env:C:\Program Files\Python313\Scripts"
$env:Path += ";$env:C:\Program Files\Python313\"

# Download the installer
Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath
if ($?) {
    Write-Output "Python installer downloaded successfully."
}
else {
    Write-Output "Python installer failed to download."
}

# Install Python silently
Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
if ($?) {
    Write-Output "Python has been installed."
}
else {
    Write-Output "Python failed to be installed."
}

write-output "Installing AzureAD module..."
Install-Module -Name AzureAD -Force -AllowClobber -Scope AllUsers
if ($?) {
    Write-Output "AzureAD module has been installed."
}
else {
    Write-Output "AzureAD module failed to be installed."
}

write-output "Installing DSInternals module..."
Install-Module DSInternals -Force -AllowClobber -Scope AllUsers
if ($?) {
    Write-Output "DSInternals module has been installed."
}
else {
    Write-Output "DSInternals module failed to be installed."
}

write-output "Installing AADInternals module..."
Install-Module AADInternals -Force -AllowClobber -Scope AllUsers
if ($?) {
    Write-Output "AADInternals module has been installed."
}
else {
    Write-Output "AADInternals module failed to be installed."
}

pip install roadlib
if ($?) {
    Write-Output "roadlib has been installed."
}
else {
    Write-Output "roadlib failed to be installed."
}

pip install roadrecon
if ($?) {
    Write-Output "roadrecon has been installed."
}
else {
    Write-Output "roadrecon failed to be installed."
}


# Define the URL for Mimikatz
$mimikatzUrl = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
$mimikatzZipPath = "$env:TEMP\mimikatz.zip"
$mimikatzExtractPath = "C:\tools\Mimikatz"

# Download Mimikatz
Invoke-WebRequest -Uri $mimikatzUrl -OutFile $mimikatzZipPath

# Extract Mimikatz
Expand-Archive -Path $mimikatzZipPath -DestinationPath $mimikatzExtractPath

# Clean up
Remove-Item -Path $mimikatzZipPath

Write-Output "Mimikatz downloaded and extracted to $mimikatzExtractPath"
Copy-DirectoryContentToWindows "C:\tools\Mimikatz\x64"


######
# Define the URLs for Sysinternals Suite
$sysinternalsUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$sysinternalsZipPath = "$env:TEMP\SysinternalsSuite.zip"
$sysinternalsExtractPath = "C:\Windows"

# Download Sysinternals Suite
Invoke-WebRequest -Uri $sysinternalsUrl -OutFile $sysinternalsZipPath

# Extract Sysinternals Suite
Expand-Archive -Path $sysinternalsZipPath -DestinationPath $sysinternalsExtractPath

# Clean up
Remove-Item -Path $sysinternalsZipPath
Write-Output "Sysinternals Suite downloaded and extracted to $sysinternalsExtractPath"



######
# THE FOLLOWING MUST RUN LAST AS IT WILL DISCONNECT THE SESSIONS
####
function New-DesktopFinishFile {
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $filePath = Join-Path -Path $desktopPath -ChildPath 'lab-setup.txt'
    "Lab prepartion script successfully finished" | Out-File -FilePath $filePath -Force
}

Write-Output "Enabling multiple, parallel RDP connections... this will restart the current session."
Start-Sleep -Seconds 5
# Enable multiple, parallel RDP connections
# Check if the paths exist and set the item properties
if (Test-Path -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server") {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fSingleSessionPerUser" -Value 0
}

if (Test-Path -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\Licensing Core") {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\Licensing Core" -Name "LicensingMode" -Value 2
}

if (Test-Path -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod") {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod" -Name "L$RTMTIMEBOMB" -Value 0 -Type DWord
}

if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2) {
    # windows server
    
    # enable TLS 1.2
    If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
        New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319')) {
        New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')) {
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')) {
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    Write-Output 'TLS 1.2 has been enabled. restart will start for the changes to take affect.' -ForegroundColor Cyan
    # Stop logging
    Stop-Transcript
    New-DesktopFinishFile
    
}
else {
    # "This is a Windows Client system."
    Write-Output "Creating a PSCredential object..."
    $Credential = New-Object System.Management.Automation.PSCredential ($DomainUser, $DomainPasswordSecured)

    Write-Output "Joining the computer to the domain..."
    Add-Computer -DomainName $DomainName -Credential $Credential -Force
    if ($?) {
        New-DesktopFinishFile
        Write-Output "Successfully joined the domain $DomainName."
        Write-Output "Restarting the Remote Desktop Services service..."
    }
    else {
        Write-Output "Failed to join the domain $DomainName."
    }

    # Stop logging
    Stop-Transcript
}

Restart-Computer -Force