param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [string]$DomainUser,

    [Parameter(Mandatory = $true)]
    [string]$DomainPassword
)

# Start logging
$global:jobs = @()
$global:LAB_DIR = "c:\lab"
$DomainUserForPcVM = "user1" # do not modify this as it is used to join the domain
$global:SETUP_RESULTS = @() # holds the results of the validation for every part of the script
$NUM_OF_USERS = 5 # do not modify this as it is used to create dummy domain users

if (-Not (Test-Path -Path $global:LAB_DIR)) { New-Item -Path $global:LAB_DIR -ItemType Directory }
Start-Transcript -Path "$global:LAB_DIR\LabSetupLog.txt" -Append

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

# Log the accepted arguments
Write-Output "DomainName: $DomainName"
Write-Output "DomainUser: $DomainUser"
Write-Output "DomainUserForPcVM: $DomainUserForPcVM"
Write-Output "DomainPassword: $DomainPassword"
# Convert the plain text password to a secure string
$DomainPasswordSecured = ConvertTo-SecureString $DomainPassword -AsPlainText -Force

# List of modules to install
$modulesToInstall = @(
    "Microsoft.Graph",
    "DSInternals",
    "AzureAD", 
    "AADInternals"
)

function Test-SoftwareInstallation {
    param (
        [string]$softwareName
    )
    $installed = Get-WmiObject -Query "SELECT Name FROM Win32_Product WHERE Name LIKE '%$softwareName%'"
    if ($installed) {
        return "$softwareName is installed.\n", $true
    } else {
        return "$softwareName is NOT installed.\n", $false
    }
}

function Test-ModuleInstallation {
    param (
        [string]$moduleName
    )
    $module = Get-Module -ListAvailable -Name $moduleName
    if ($module) {
        return "PS Module $moduleName is installed.\n", $true
    } else {
        return "PS Module $moduleName is not installed.\n", $false
    }
}

function Test-UserCreation {
    param (
        [string]$userName
    )
    $user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
    if ($user) {
        return "User $userName exists.\n", $true
    } else {
        return "User $userName does not exist.\n", $false
    }
}

function Test-DomainCreation {
    param (
        [string]$domainName
    )
    $domain = Get-ADDomain -Identity $domainName -ErrorAction SilentlyContinue
    if ($domain) {
        return "Domain $domainName exists.\n", $true
    } else {
        return "Domain $domainName does not exist.\n", $false
    }
}

function Test-DomainJoin {
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    if ($computerSystem.PartOfDomain) {
        return "Computer is joined to the domain.\n";  $true
    } else {
        return "Computer is NOT joined to the domain.\n";  $false
    }
}


# Function to finish the script loggging and restart the computer
function Finish ($isSuccessfull) {
    # Ensure the directory exists
    if (-Not (Test-Path -Path $global:LAB_DIR)) {
        New-Item -Path $global:LAB_DIR -ItemType Directory -Force | Out-Null
    }

    # Write all results to a file
    $outputFile = Join-Path -Path $global:LAB_DIR -ChildPath "LabSetupResults.txt"
    $global:SETUP_RESULTS | Out-File -FilePath $outputFile -Force

    Write-Output "Validation results written to $outputFile"
    if($isSuccessfull) {
        $global:SETUP_RESULTS += "Lab setup script has finished successfully."
        $global:SETUP_RESULTS | Out-File -FilePath $outputFile
        Stop-Transcript
        Restart-Computer -Force
    }
    else {
        $global:SETUP_RESULTS += "Lab setup script has failed."
        Write-Output "Lab setup script has failed."
        $global:SETUP_RESULTS | Out-File -FilePath $outputFile
        Stop-Transcript
    }
}

# Function to install a module
function Install-ModuleWithParams {
    param (
        [Parameter(Mandatory = $true)]
        [string]$moduleToInstall,

        [Parameter(Mandatory = $true)]
        [bool]$waitForCompletion
    )

    $arguments = "-NoProfile -Command Install-Module $moduleToInstall -AllowClobber -Force -Scope AllUsers"
    if ($waitForCompletion) {
        Start-Process powershell -ArgumentList $arguments -Verb RunAs -Wait
    }
    else {
        $job = Start-Job -ScriptBlock {
            param ($arguments)
            Start-Process powershell -ArgumentList $arguments -Verb RunAs
        } -ArgumentList $arguments
        $global:jobs += $job
    }
}

function Install-Software {
    param (
        [Parameter(Mandatory = $false)]
        [string]$url,

        [Parameter(Mandatory = $false)]
        [string]$fileName,

        [Parameter(Mandatory = $false)]
        [string]$processArgList,

        [Parameter(Mandatory = $false)]
        [string]$startProcess
    )

    if (-Not [string]::IsNullOrEmpty($url)) {
        if (-Not [string]::IsNullOrEmpty($fileName) -and (-Not (Test-Path -Path $fileName))) {
            Write-Output "Installing software from $url..."
            $maxRetries = 3
            $retryCount = 0
            $success = $false
        
            while (-Not $success -and $retryCount -lt $maxRetries) {
                try {
                    Invoke-WebRequest -Uri $url -OutFile $fileName
                    $success = $true
                }
                catch {
                    Write-Output "Failed to resolve $url. Retrying... ($($retryCount + 1)/$maxRetries)"
                    Start-Sleep -Seconds 2
                    $retryCount++
                }
            }
            if (-Not $success) {
                Write-Output "Failed to download $url ($fileName) file after $maxRetries retries." 
                return
            }
        }
    }
    
    if ([string]::IsNullOrEmpty($startProcess)) {
        # No start process defined, just download the file
        return
    }
    Write-Output "Running $startProcess..."
    if (-not [string]::IsNullOrEmpty($processArgList)) {
        Start-Process $startProcess -Wait -ArgumentList $processArgList
    }
    else {
        Start-Process $startProcess -Wait
    }
    try {
        if ($?) {
            Write-Output "$fileName ($startProcess) has been installed."
        }
        else {
            Write-Output "$fileName ($startProcess) failed to be installed."
        }   
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
}


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

        try {
            # Create the destination directory if it doesn't exist
            if (-Not (Test-Path -Path (Split-Path -Path $destinationPath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path -Path $destinationPath -Parent) | Out-Null
            }

            # Copy the item to the destination
            if (-Not (Test-Path -Path $destinationFile)) {
            Copy-Item -Path $item.FullName -Destination $destinationPath -Force
            }
        }
        catch {
        }
    }
}

function Is-WindowsServer {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    return $os.ProductType -eq 2 -or $os.ProductType -eq 3
}

# Disable AV
Install-Software -url "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/disableAv.ps1" `
    -fileName "$global:LAB_DIR\DisableAV.ps1" `
    -startProcess "powershell" `
    -processArgList "-ExecutionPolicy Bypass -File $global:LAB_DIR\DisableAV.ps1"

if (Is-WindowsServer) {
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

    # Validate the domain
    $text, $status = Test-DomainCreation -domainName "$DomainName"
    $global:SETUP_RESULTS += $text
    if(-Not $status) {
        Write-Output $text
        Write-Output "Cannot continue without a domain. Exiting..."
        Finish($false)
        exit
    }

    # Create dummy domain users and add them to Domain Admins group
    Write-Output "Creating $NUM_OF_USERS dummy domain users and adding them to Domain Admins group..."
    for ($i = 1; $i -le $NUM_OF_USERS; $i++) { # do not modify this as this username is used below to join the pc vm to the domain
        $username = "user$i" # do not modify this as this username is used below to join the pc vm to the domain
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
                -EmployeeNumber "$i" `
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

    # Validate the users
    for ($i = 1; $i -le $NUM_OF_USERS; $i++)
    {
        $username = "user$i"
        $text, $status = Test-UserCreation -userName $username
        $global:SETUP_RESULTS += $text
        if(-Not $status) {
            Write-Output $text
            Write-Output "Cannot continue without the users. Exiting..."
            Finish($false)
            exit
        }
    }

    # Install Azure AD Connect
    Install-Software -url "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi" `
        -fileName "$global:LAB_DIR\AzureADConnect.msi" `
        -startProcess "" `
        -processArgList ""
}
else {
    Write-Output "This is a Windows Client system."
    Write-Output "Getting the network adapter..."
    # Get the network adapter
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

    Write-Output "Setting the primary and secondary DNS servers..."
    # Set the primary and secondary DNS servers
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("10.0.0.10", "8.8.8.8")
    if ($?) {
        Write-Output "DNS servers have been set to 10.0.0.10 and 8.8.8.8."
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

# Install the PS modules
foreach ($module in $modulesToInstall) {
    Install-ModuleWithParams -moduleToInstall $module -waitForCompletion $false
}

# Install Azure CLI
Install-Software -url "https://aka.ms/installazurecliwindows" `
    -fileName "$global:LAB_DIR\azureCli.msi" `
    -startProcess "msiexec.exe" `
    -processArgList "/I $global:LAB_DIR\AzureCLI.msi /quiet"

$text, $status = Test-SoftwareInstallation -softwareName "Azure CLI"
$global:SETUP_RESULTS += $text

Install-Software -url "https://telerik-fiddler.s3.amazonaws.com/fiddler/FiddlerSetup.exe" `
    -fileName "$global:LAB_DIR\FiddlerSetup.exe" 

# Install Python
Install-Software -url "https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe" `
    -fileName "$global:LAB_DIR\python-3.9.7-amd64.exe" `
    -startProcess "$global:LAB_DIR\python-3.9.7-amd64.exe" `
    -processArgList "/quiet InstallAllUsers=1 PrependPath=1"

$env:Path += ";$env:C:\Program Files\Python313\Scripts"
$env:Path += ";$env:C:\Program Files\Python313\"

$text, $status = Test-SoftwareInstallation -softwareName "Python"
$global:SETUP_RESULTS += $text

Install-Software -startProcess "pip" -processArgList "install roadlib"
Install-Software -startProcess "pip" -processArgList "install roadrecon"
Install-Software -startProcess "pip" -processArgList "install roadtx"
Install-Software -startProcess "pip" -processArgList "install setuptools"

$text, $status = Test-SoftwareInstallation -softwareName "pip"
$global:SETUP_RESULTS += $text


# install mimikatz
Install-Software -url "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip" `
    -fileName "$global:LAB_DIR\mimikatz.zip" `
    -startProcess "powershell" `
    -processArgList "-Command Expand-Archive -Path $global:LAB_DIR\mimikatz.zip -DestinationPath $global:LAB_DIR\mimikatz"
Copy-DirectoryContentToWindows "$global:LAB_DIR\mimikatz\x64"

# Install Sysinternals Suite
Install-Software -url "https://download.sysinternals.com/files/SysinternalsSuite.zip" `
    -fileName "$global:LAB_DIR\SysinternalsSuite.zip" `
    -startProcess "powershell" `
    -processArgList "-Command Expand-Archive -Path $global:LAB_DIR\SysinternalsSuite.zip -DestinationPath C:\Windows"


foreach ($job in $global:jobs) {
    Write-Output "Waiting for job $($job.Id) to complete..."
    Wait-Job -Job $job
    write-Output "Job $($job.Id) has completed."
    Receive-Job -Job $job
    Remove-Job -Job $job
}
Update-Help -Force

# Validate the installation of the modules
foreach ($module in $modulesToInstall) {
    $result, $status = Test-ModuleInstallation -moduleName $module
    $global:SETUP_RESULTS += $result
}

######
# THE FOLLOWING MUST RUN LAST AS IT WILL DISCONNECT THE SESSIONS
####
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

if (Is-WindowsServer) {
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
}
else {
    # "This is a Windows Client system."
    Write-Output "Creating a PSCredential object..."
    $Credential = New-Object System.Management.Automation.PSCredential ($DomainUserForPcVM, $DomainPasswordSecured)

    Write-Output "Joining the computer to the domain..."
    Add-Computer -DomainName $DomainName -Credential $Credential -Force
    if ($?) {
        Write-Output "Successfully joined the domain $DomainName."
        Write-Output "Restarting the Remote Desktop Services service..."
    }
    else {
        Write-Output "Failed to join the domain $DomainName."
    }

    $result, $status = Test-DomainJoin
    $global:SETUP_RESULTS += $result
}

Finish($true)




