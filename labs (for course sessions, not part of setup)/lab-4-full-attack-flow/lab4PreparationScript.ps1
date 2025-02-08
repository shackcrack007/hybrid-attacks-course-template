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
    7. Creates an OAuth app with secret and assigns necessary permissions to the storage account.

.EXAMPLE
    .\lab4PreparationScript.ps1 -DomainName "mydomain.onmicrosoft.com"

.NOTES
    Ensure you have the necessary permissions to create resources and assign roles in Azure.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName = "mydomain_rafdsfdsfdom35443fd.onmicrosoft.com"
)

$ProgressPreference = 'SilentlyContinue'
Write-Output "Starting the script, this may take a while - watch out for prompts!"
# bypass PS 5.1 limitations:
$MaximumFunctionCount = 18000
$script:MaximumFunctionCount = 18000
$script:MaximumVariableCount = 18000
$MaximumVariableCount = 18000

$resourceGroupName = "hybrid-attacks-lab4-rg"
$location = "EastUS"
$user2 = "user2"
$oauthAppName = "MyStorageBackupApp"
$NUM_OF_USERS = 17
######################################################
######################################################
######################################################

Write-Output "Starting.. "
function Get-TenantIdByDomain {
    param (
        [string]$DomainName
    )
    $response = $null
    try {
        # Construct the OpenID Configuration URL for the domain
        $url = "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"

        # Make a web request to fetch the configuration
        $response = Invoke-RestMethod -Uri $url -Method Get

        # Extract the Tenant ID from the URL
        $regex = [regex]"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        $match = $regex.Match($response.issuer)
        if ($match.Success) {
            $tenantId = $match.Value
            return $tenantId
        }
        else {
            Write-Error "Tenant ID not found in the response."
            return $null
        }
    }
    catch {
        Write-Error "Failed to retrieve Tenant ID: $_"
        return $null
    }
}

$tenantId = Get-TenantIdByDomain -DomainName $DomainName
if ($null -eq $tenantId) {
    Write-Error "Failed to retrieve Tenant ID, make sure domain name is correct."
    return
}
Write-Output "Tenant ID: $tenantId"

if (-not (Get-Module -ListAvailable -Name Az.*)) {
    # Check if running as administrator
    If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "You need to run this script as an administrator."
        Exit
    }
    Write-Output "Installing Az module, this wil take a 5-10 mins..."
    Install-Module -Name Az -Force -Verbose
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    # Check if running as administrator
    If (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "You need to run this script as an administrator."
        Exit
    }
    Write-Output "Installing Microsoft.Graph module, this wil take a 5-10 mins..."
    Install-Module -Name Microsoft.Graph -Force -Verbose
}

Write-Output "Importing modules, this will take a few..."
Import-Module Az.Accounts
Import-Module Az.Resources
Import-Module Az.Storage
Import-Module Microsoft.Graph.Identity.Governance

# Connect to Microsoft Graph for assigning roles on user2 later
Start-Process "msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"
Connect-MgGraph -TenantId $tenantId -UseDeviceCode -NoWelcome -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "RoleManagement.ReadWrite.Directory"  
Write-Output "Connect-MgGraph Connected successfully."

# Connect to Azure for creating resources
Write-Output "Login to Azure Resource Manager API:"
Start-Process "msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"
Connect-AzAccount -DeviceCode -TenantId $tenantId -AuthScope MicrosoftGraphEndpointResourceId
if (-Not (Get-AzContext).Name.Contains("Visual Studio Enterprise Subscription")) {
    $selectedAzureSub = (Get-AzContext).Name
    Write-Warning "NOTICE: The Azure subscription that's going to be used is: $selectedAzureSub"
    Write-Warning "It is not the 150$ one, Please select the subscription you'd like to proceed with:"
    # Get the list of subscriptions
    $subscriptions = Get-AzSubscription | Select-Object TenantId, Name

    # Prompt the user to select a subscription
    Write-Output "Available Subscriptions:"
    $subscriptions | ForEach-Object { Write-Output "$($_.Name) - TenantId: $($_.TenantId)" }
    $selectedSubscription = $subscriptions | Out-GridView -Title "Select a subscription" -PassThru
    
    if ($selectedSubscription) {
        $tenantId = $selectedSubscription.TenantId
        Write-Output "Selected TenantId: $tenantId"
        Set-AzContext -Tenant $tenantId -SubscriptionName $selectedSubscription.Name
    }
    else {
        Write-Output "Subscription not found. Please try again."
        return
    }
}

# Get the current Azure context
$context = Get-AzContext
$subscriptionId = (Get-AzContext).Subscription.Id
# Display the selected subscription
Write-Verbose "Selected Subscription:"
Write-Verbose "Subscription ID: $subscriptionId"
Write-Verbose "Subscription Name: $($context.Subscription.Name)"
Write-Verbose "Tenant ID: $($context.Tenant.Id)"
Write-Verbose "Account: $($context.Account.Id)"

###############################################################################################
############ Create oAuth App with secret and permissions to Storage Account  #################
###############################################################################################

# Step 1: Check if the App Registration already exists
$app = Get-MgApplication -Filter "identifierUris/any(uri: uri eq 'https://$DomainName/$oauthAppName')"
if ($null -eq $app) {
    Write-Verbose "Creating App Registration..."
    $app = New-MgApplication -DisplayName "My Storage Backup App" -IdentifierUris "https://$DomainName/$oauthAppName"
    Write-Verbose "App Registration created: $($app.AppId)"
}
else {
    Write-Verbose "App Registration already exists: $($app.AppId)"
}

# Step 2: Create required permissions
Write-Verbose "Creating required permissions..."
$appRequiredResourceAccess = @(
)

Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $appRequiredResourceAccess
Write-Verbose "Required permissions created."

# Step 3: Check if the Service Principal already exists
$sp = Get-MgServicePrincipal -Filter "AppId eq '$($app.AppId)'"
if ($null -eq $sp) {
    Write-Verbose "Creating Service Principal for the App..."
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Verbose "Service Principal created: $($sp.Id)"
}
else {
    Write-Verbose "Service Principal already exists: $($sp.Id)"
}
$spId = $sp.id

################## permissions for azure ##################
Write-Verbose "Assigning azure roles to the SPN $spId so it can read the storage account secret..."

$roles = @("Reader", "Storage Account Key Operator Service Role", "Storage Account Contributor")
$scope = "/subscriptions/$subscriptionId"
$scope = "/subscriptions/$subscriptionId"
foreach ($role in $roles) {
    # Check if the role assignment already exists
    $existingAssignment = Get-AzRoleAssignment -ObjectId $spId -RoleDefinitionName $role -Scope $scope -ErrorAction SilentlyContinue

    if ($null -eq $existingAssignment) {
        # Assign the role if it does not exist
        New-AzRoleAssignment -ObjectId $spId -RoleDefinitionName $role -Scope $scope > $null
        Write-Verbose "Role '$role' assigned successfully."
    }
    else {
        Write-Verbose "Role '$role' already assigned."
    }
}

################## create secret ##################
$secretStartDate = (Get-Date).ToUniversalTime()
$secretEndDate = $secretStartDate.AddYears(1)  # Set expiration date to 1 year
$secret = @{
    passwordCredential = @{
        displayName   = "AutoGeneratedSecret"
        startDateTime = $secretStartDate
        endDateTime   = $secretEndDate
    }
}

# Create the secret and store the value
$generatedSecret = Add-MgServicePrincipalPassword -ServicePrincipalId $spId -BodyParameter $secret

# Extract and display the secret value (IMPORTANT: Save this immediately, as it won't be retrievable later!)
$clientSecret = $generatedSecret.SecretText
Write-Verbose "Generated Secret: $clientSecret"
Write-Verbose "Generated Secret: $generatedSecret.KeyId"
Set-Content -Path "backup_app_secret.txt" -Value $clientSecret > $null


####################################################################################
############################ Handle storage account ################################
####################################################################################

function Generate-StorageAccountName {
    param (
        [int]$length = 24
    )

    $prefix = "secret"
    $suffixLength = $length - $prefix.Length
    $suffix = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count $suffixLength | ForEach-Object { [char]$_ })
    $storageAccountName = ($prefix + $suffix).ToLower()

    return $storageAccountName
}

$storageAccountName = Generate-StorageAccountName


Write-Output "Continuing with the script execution..."

################## Storage account preps ##################

Write-Verbose "Registering the Microsoft.Storage resource provider..."
Register-AzResourceProvider -ProviderNamespace Microsoft.Storage > $null


# Check if the resource group exists
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue

if (-not $resourceGroup) {
    Write-Verbose "Resource group '$resourceGroupName' not found. Creating a new resource group..."
    $resourceGroup = New-AzResourceGroup -Name $resourceGroupName -Location $location
}
else {
    Write-Verbose "Resource group '$resourceGroupName' already exists. Using the existing resource group."
}

# Get the storage account context
$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName -ErrorAction SilentlyContinue

if (-not $storageAccount) {
    # Create the storage account if it doesn't exist
    $storageAccount = New-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageAccountName -Location $location -SkuName Standard_LRS
    Write-Verbose "Storage account '$storageAccountName' created."
}
else {
    Write-Verbose "Storage account '$storageAccountName' already exists. Using the existing storage account."
}

# Get the storage account context
$ctx = $storageAccount.Context

Write-Verbose "Creating a new container 'secretcontainer' in the storage account..."
$containerName = "secretcontainer"
New-AzStorageContainer -Name $containerName -Context $ctx > $null

# Create a text file in the container
Write-Verbose "Creating a text file 'secret.txt' in the container..."
$content = "MAZAL TOV! YOU SUCCESSFULLY FINISHED THE EXERCISE!"
Set-Content -Path "secret.txt" -Value $content > $null
Set-AzStorageBlobContent -File "secret.txt" -Container $containerName -Blob "secret.txt" -Context $ctx > $null
Remove-Item "secret.txt" -Force -ErrorAction SilentlyContinue

######################################################################################
################## assign role so these users can "RunCommand" on the VM #############
######################################################################################
$roleDefinitionADO = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq 'Azure DevOps Administrator'"

for ($i = 2; $i -le $NUM_OF_USERS; $i++) {
    # starting with 2 because user1 is connected to the VM
    $username = "user$i"
    $usernameObjectId = (Get-AzADUser -UserPrincipalName "$username@$DomainName").Id

    Write-Verbose "Assigning azure roles to $username@$DomainName..."
    $roles = @("Virtual Machine Contributor")
    $scope = "/subscriptions/$subscriptionId"
    foreach ($role in $roles) {
        # Check if the role assignment already exists
        $existingAssignment = Get-AzRoleAssignment -ObjectId $usernameObjectId -RoleDefinitionName $role -Scope $scope -ErrorAction SilentlyContinue

        if ($null -eq $existingAssignment) {
            # Assign the role if it does not exist
            New-AzRoleAssignment -ObjectId $usernameObjectId -RoleDefinitionName $role -Scope $scope -ErrorAction SilentlyContinue > $null
            Write-Verbose "Role '$role' assigned successfully to $username."
        }
        else {
            Write-Verbose "Role '$role' already assigned to $username."
        }
    }

    # Assign the "Azure DevOps Administrator" role , this is just for the students to see this user as a lucrative and potential target, we don't really use this role
    New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId "/" -PrincipalId $usernameObjectId -RoleDefinitionId $roleDefinitionADO.Id -ErrorAction SilentlyContinue > $null
}



# disconnect
Disconnect-MgGraph -ErrorAction SilentlyContinue
try {
    Disconnect-AzureAD -ErrorAction SilentlyContinue
}
catch {
}
Disconnect-AzAccount -ErrorAction SilentlyContinue
################## FINISHED ##################

Write-Output "Script execution completed successfully."
Write-Output "Once done with the lab, delete the resource group $resourceGroupName to clean up the resources."