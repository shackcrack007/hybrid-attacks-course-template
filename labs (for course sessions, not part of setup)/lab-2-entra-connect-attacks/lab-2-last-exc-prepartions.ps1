param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    [string]$OwnerUsername = "user1" # Default owner
)

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
        } else {
            Write-Error "Tenant ID not found in the response."
            return $null
        }
    } catch {
        Write-Error "Failed to retrieve Tenant ID: $_"
        return $null
    }
}

# Ensure Microsoft Graph module is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}
Write-Output "Loading modules..."
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Applications
$tenantId = Get-TenantIdByDomain -DomainName $DomainName
if ($null -eq $tenantId) {
    return
}

Connect-MgGraph -Scopes "Application.ReadWrite.All Directory.ReadWrite.All Directory.AccessAsUser.All AdministrativeUnit.Read.All AdministrativeUnit.ReadWrite.All Application.Read.All Application.ReadWrite.All AppRoleAssignment.ReadWrite.All DelegatedPermissionGrant.ReadWrite.All Domain.Read.All email IdentityProvider.ReadWrite.All openid Organization.ReadWrite.All Policy.Read.All Policy.ReadWrite.ApplicationConfiguration Policy.ReadWrite.MobilityManagement profile" -TenantId $tenantId -UseDeviceCode -NoWelcome

# Step 1: Check if the App Registration already exists
$app = Get-MgApplication -Filter "identifierUris/any(uri: uri eq 'https://$DomainName/MyBackupApp')"
if ($null -eq $app) {
    Write-Verbose "Creating App Registration..."
    $app = New-MgApplication -DisplayName "My Backup App" -IdentifierUris "https://$DomainName/MyBackupApp"
    Write-Verbose "App Registration created: $($app.AppId)"
} else {
    Write-Verbose "App Registration already exists: $($app.AppId)"
}

# Step 2: Create required permissions
Write-Verbose "Creating required permissions..."
$appRequiredResourceAccess = @(
    @{
        ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        ResourceAccess = @(
            @{
                Id = "741f803b-c850-494e-b5df-cde7c675a1ca" # Directory.ReadWrite.All
                Type = "Role"
            },
            @{
                Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7" # User.ReadWrite.All
                Type = "Role"
            },
            @{
                Id = "06b708a9-e830-4db3-a914-8e69da51d44f" # AppRoleAssignment.ReadWrite.All
                Type = "Role"
            },
            @{
                Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" # RoleManagement.ReadWrite.Directory
                Type = "Role"
            }
        )
    }
)

Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $appRequiredResourceAccess
Write-Verbose "Required permissions created."

# Step 3: Check if the Service Principal already exists
$sp = Get-MgServicePrincipal -Filter "AppId eq '$($app.AppId)'"
if ($null -eq $sp) {
    Write-Verbose "Creating Service Principal for the App..."
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Verbose "Service Principal created: $($sp.Id)"
} else {
    Write-Verbose "Service Principal already exists: $($sp.Id)"
}

# Step 4: Assign Application Permissions
Write-Verbose "Assigning Application Permissions and Granting Admin Consent..."
$msGraphServicePrincipalId = (Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'").Id
$spId = $sp.id

$msgraphPermissions = @("741f803b-c850-494e-b5df-cde7c675a1ca", "19dbc75e-c2e2-444c-a770-ec69d8559fc7", "06b708a9-e830-4db3-a914-8e69da51d44f", "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8")

foreach ($permission in $msgraphPermissions) {
    $param = @{  
        "PrincipalId" = "$spId"  
        "ResourceId"  = "$msGraphServicePrincipalId"  
        "AppRoleId"   = "$permission"  
    }
    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "$msGraphServicePrincipalId" -BodyParameter $param -ErrorAction SilentlyContinue
}

Write-Verbose "Application Permissions assigned and Admin Consent granted."

# Step 5: Assign User as Owner if not already assigned
Write-Verbose "Assigning $OwnerUsername as Owner of the App Registration..."
$owner = Get-MgUser -Filter "userPrincipalName eq '$OwnerUsername@$DomainName'"
if ($null -eq $owner) {
    throw "User '$OwnerUsername@$DomainName' not found in the tenant."
}

$existingOwner = Get-MgApplicationOwner -ApplicationId $app.Id | Where-Object { $_.Id -eq $owner.Id }
if ($null -eq $existingOwner) {
    $odataId = "https://graph.microsoft.com/v1.0/directoryObjects/$($owner.Id)"
    $null = New-MgApplicationOwnerByRef -ApplicationId $app.Id -OdataId $odataId
    Write-Verbose "$OwnerUsername assigned as owner successfully."
} else {
    Write-Verbose "$OwnerUsername is already an owner."
}

Write-Verbose "App Registration setup completed."

Write-Output "Finished successfully."