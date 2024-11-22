<#
.SYNOPSIS
    This script connects to Azure using provided credentials, creates a storage account, uploads a text file, and assigns a Reader role to a specified user.

    The script MUST run with administrator privileges
.DESCRIPTION
    The script performs the following tasks:
    1. Connects to Azure using the provided credentials.
    2. Checks if a specified resource group exists; if not, creates it.
    3. Creates a storage account in the resource group.
    4. Creates a container in the storage account.
    5. Uploads a text file named "secret.txt" with specific content to the container.
    6. Assigns a Reader role to a specified user on the storage account if the user does not already have the role.

.EXAMPLE
    .\lab4PreparationScript.ps1 

.NOTES
    Ensure you have the necessary permissions to create resources and assign roles in Azure.
#>
[CmdletBinding()]
param (
)
# Check if running as administrator
If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You need to run this script as an administrator."
    Exit
}

# bypass PS 5.1 limitations:
$MaximumFunctionCount = 18000
$script:MaximumFunctionCount = 18000
$script:MaximumVariableCount = 18000
$MaximumVariableCount = 18000

$resourceGroupName = "hybrid-attacks-lab-rg"
$location = "EastUS"

function Generate-StorageAccountName {
    param (
        [int]$length = 24
    )

    $prefix = "secret"
    $suffixLength = $length - $prefix.Length
    $suffix = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count $suffixLength | ForEach-Object {[char]$_})
    $storageAccountName = ($prefix + $suffix).ToLower()

    return $storageAccountName
}

$storageAccountName = Generate-StorageAccountName

Write-Verbose "Starting.. "
if (-not (Get-Module -ListAvailable -Name Az.*)) {
    Write-Verbose "Installing Az module, this wil take a 5-10 mins..."
    Install-Module -Name Az -Force -Verbose
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Verbose "Installing Microsoft.Graph module, this wil take a 5-10 mins..."
    Install-Module -Name Microsoft.Graph -Force -Verbose
}

Write-Verbose "Importing modules..."
#Import-Module Az
Import-Module Az.Accounts
Import-Module Az.Resources
Import-Module Az.Storage
#Import-Module Microsoft.Graph

# Connect to Azure
Start-Process "msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"
Connect-AzAccount -DeviceCode


# Extract domain from username
$domain = (Get-AzContext).Account.Id.ToString().Split('@')[1]
# Get the user1 object ID
$userObjectId = (Get-AzADUser -UserPrincipalName "user1@$domain").Id
$user2ObjectId = (Get-AzADUser -UserPrincipalName "user2@$domain").Id




Write-Verbose "Getting subscription ID..."
$subscriptionId = (Get-AzSubscription).Id
Write-Verbose "Selected subscription ID: $subscriptionId"

# Get the current Azure context
$context = Get-AzContext

# Display the selected subscription
Write-Verbose "Selected Subscription:"
Write-Verbose "Subscription Name: $($context.Subscription.Name)"
Write-Verbose "Tenant ID: $($context.Tenant.Id)"
Write-Verbose "Account: $($context.Account.Id)"
Write-Verbose "Domain: $domain"


################## User1 preps ##################

Write-Verbose "Registering the Microsoft.Storage resource provider..."
$none = Register-AzResourceProvider -ProviderNamespace Microsoft.Storage


# Check if the resource group exists
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue

if (-not $resourceGroup) {
    Write-Verbose "Resource group '$resourceGroupName' not found. Creating a new resource group..."
    $resourceGroup = New-AzResourceGroup -Name $resourceGroupName -Location $location
} else {
    Write-Verbose "Resource group '$resourceGroupName' already exists. Using the existing resource group."
}

# Get the storage account context
$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName -ErrorAction SilentlyContinue

if (-not $storageAccount) {
    # Create the storage account if it doesn't exist
    $storageAccount = New-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName -Location $location -SkuName Standard_LRS
    Write-Verbose "Storage account '$storageAccountName' created."
} else {
    Write-Verbose "Storage account '$storageAccountName' already exists. Using the existing storage account."
}

# Get the storage account context
$ctx = $storageAccount.Context

Write-Verbose "Creating a new container 'secretcontainer' in the storage account..."
$containerName = "secretcontainer"
$none = New-AzStorageContainer -Name $containerName -Context $ctx

# Create a text file in the container
Write-Verbose "Creating a text file 'secret.txt' in the container..."
$content = "MAZAL TOV! YOU SUCCESSFULLY FINISHED THE EXERCISE!"
Set-Content -Path "secret.txt" -Value $content
Set-AzStorageBlobContent -File "secret.txt" -Container $containerName -Blob "secret.txt" -Context $ctx

# Check if the user already has the Reader role
$roleAssignment = Get-AzRoleAssignment -ObjectId $userObjectId -Scope $storageAccount.Id | Where-Object { $_.RoleDefinitionName -eq "Reader" }

if (-not $roleAssignment) {
    # Assign Reader role to user1@mydomain.onmicrosft.com if not already assigned
    $none = New-AzRoleAssignment -ObjectId $userObjectId -RoleDefinitionName "Reader" -Scope $storageAccount.Id
    Write-Verbose "Reader role assigned to user1@$domain."
} else {
    Write-Verbose "User user1@$domain already has the Reader role."
}


################## User2 preps ##################
Write-Verbose "Assigning roles to user2@$domain..."
$roles = @("Reader", "Virtual Machine Contributor")
$scope = "/subscriptions/$subscriptionId"
foreach ($role in $roles) {
    # Check if the role assignment already exists
    $existingAssignment = Get-AzRoleAssignment -ObjectId $user2ObjectId -RoleDefinitionName $role -Scope $scope -ErrorAction SilentlyContinue

    if ($null -eq $existingAssignment) {
        # Assign the role if it does not exist
        New-AzRoleAssignment -ObjectId $user2ObjectId -RoleDefinitionName $role -Scope $scope
        Write-Verbose "Role '$role' assigned successfully."
    } else {
        Write-Verbose "Role '$role' already assigned."
    }
}


Write-Output "Script execution completed successfully."
Write-Output "Once done with the lab, delete the resource group '$resourceGroupName' to clean up the resources."