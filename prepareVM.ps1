param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [string]$DomainUser,

    [Parameter(Mandatory = $true)]
    [string]$DomainPassword
)

# Start logging
Start-Transcript -Path "c:\preparevm.txt" -Append

# Log the accepted arguments
Write-Output "DomainName: $DomainName"
Write-Output "DomainUser: $DomainUser"
Write-Output "DomainPassword: $DomainPassword"
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

# Disable AV
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/disableAv.ps1" -OutFile "C:\\DisableAV.ps1"; & "C:\\DisableAV.ps1"

$DomainPasswordSecured = ConvertTo-SecureString $DomainPassword -AsPlainText -Force

# Allow PowerShell script execution to be Unrestricted
Set-ExecutionPolicy Unrestricted -Force

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
        
        New-ADUser `
        -Name "$username victim" `
        -GivenName "$username" `
        -Surname "victim" `
        -SamAccountName "$username" `
        -AccountPassword $DomainPasswordSecured `
        -ChangePasswordAtLogon $False `
        -Company "Code Duet" `
        -Title "CEO" `
        -State "California" `
        -City "San Francisco" `
        -Description "victim user account for the lab" `
        -EmployeeNumber "45" `
        -Department "Engineering" `
        -DisplayName "$username" `
        -Country "us" `
        -PostalCode "940001" `
        -Enabled $True    

        Add-ADGroupMember -Identity "Domain Admins" -Members $username
    }

    Write-Output "Downloading AzureADConnect.msi to Desktop..."
    # Download AzureADConnect.msi to Desktop
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi" -OutFile "$desktopPath\AzureADConnect.msi"

    Write-Output "Downloading and extracting BadBlood zip file..."
    # Download and extract BadBlood zip file
    $zipUrl = "https://github.com/davidprowe/BadBlood/archive/refs/heads/master.zip"
    $zipPath = "$desktopPath\BadBlood.zip"
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $desktopPath

    # Run the extracted BadBlood script
    #$badBloodScript = "$desktopPath\BadBlood-master\invoke-badblood.ps1"
    #Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $badBloodScript" -Verb RunAs
} else {
    Write-Output "This is a Windows Client system."
    Write-Output "Getting the network adapter..."
    # Get the network adapter
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

    Write-Output "Setting the primary and secondary DNS servers..."
    # Set the primary and secondary DNS servers
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("10.0.0.4", "8.8.8.8")

    Write-Output "DNS servers have been set to 10.0.0.4 and 8.8.8.8."

    Write-Output "Creating a PSCredential object..."
    # Create a PSCredential object
    $Credential = New-Object System.Management.Automation.PSCredential ($DomainUser, $DomainPasswordSecured)

    Write-Output "Joining the computer to the domain..."
    # Join the computer to the domain
    Add-Computer -DomainName $DomainName -Credential $Credential -Restart -Force

    # Output the result
    if ($?) {
        Write-Output "Successfully joined the domain $DomainName."
    } else {
        Write-Output "Failed to join the domain $DomainName."
    }
}

Write-Output "Disabling Windows Updates..."
# Disable Windows Updates
Set-Service -Name wuauserv -StartupType Disabled
Stop-Service -Name wuauserv

############################
# Install PS, Python and attack tools
################################

write-output "Installing PowerShellGet..."
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

write-output "Installing Python..."
# Define the URL for the Python installer
$pythonInstallerUrl = "https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe"

# Define the path to save the installer
$installerPath = "$env:TEMP\python-3.9.7-amd64.exe"
$env:Path += ";$env:C:\Program Files\Python313\Scripts"
$env:Path += ";$env:C:\Program Files\Python313\"
# Download the installer
Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath

# Install Python silently
Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait

write-output "Installing AADInternals module..."
Install-Module AADInternals -Force -AllowClobber -Scope AllUsers

pip install roadlib
pip install roadrecon

######
# THE FOLLOWING MUST RUN LAST AS IT WILL DISCONNECT THE SESSIONS
####

Write-Output "Enabling multiple, parallel RDP connections..."
# Enable multiple, parallel RDP connections
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fSingleSessionPerUser" -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\Licensing Core" -Name "LicensingMode" -Value 2
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod" -Name "L$RTMTIMEBOMB" -Value 0 -Type DWord
Restart-Service -Name TermService -Force


# Stop logging
Stop-Transcript
exit 0