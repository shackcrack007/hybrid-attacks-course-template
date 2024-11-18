function Validate-SoftwareInstallation {
    param (
        [string]$softwareName
    )
    $installed = Get-WmiObject -Query "SELECT * FROM Win32_Product" | Where-Object { $_.Name -like "*$softwareName*"}
    if ($installed) {
        Write-Output "$softwareName is installed."
        return $true
    } else {
        Write-Output "$softwareName is not installed."
        return $false
    }
}

function Validate-ModuleInstallation {
    param (
        [string]$moduleName
    )
    $module = Get-Module -ListAvailable -Name $moduleName
    if ($module) {
        Write-Output "Module $moduleName is installed."
    } else {
        Write-Output "Module $moduleName is not installed."
    }
}

function Validate-UserCreation {
    param (
        [string]$userName
    )
    $user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
    if ($user) {
        Write-Output "User $userName exists."
    } else {
        Write-Output "User $userName does not exist."
    }
}

function Validate-DomainCreation {
    param (
        [string]$domainName
    )
    $domain = Get-ADDomain -Identity $domainName -ErrorAction SilentlyContinue
    if ($domain) {
        Write-Output "Domain $domainName exists."
    } else {
        Write-Output "Domain $domainName does not exist."
    }
}

# Example usage
Validate-SoftwareInstallation -softwareName "YourSoftwareName"
Validate-UserCreation -userName "user1"
Validate-DomainCreation -domainName "boazwassergmail.onmicrosoft.com"


$modules = @("Microsoft.Graph", "DSInternals", "AzureAD", "AADInternals")
foreach ($module in $modules) {
    Validate-ModuleInstallation -moduleName $module
}

