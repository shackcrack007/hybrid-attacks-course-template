# Preparation instructions for hybrid lab deployment 
#### The lab is comprised from an Active Directory domain + VMs, synced to an Entra tenant, hosted on Azure VMs

WARNING: Deploying this infrastructure in your Entra ID and Azure environment may incur additional costs, and any security risks associated with its deployment and use are solely your responsibility.

![lab](pics/lab.png)

**As part of the lab setup, you will:**
* Create an Entra tenant - which will play the "cloud" role
* Deploy Azure template to your subscription account, this will only be used to host the "On-premise" Active Directory VMs
* Install and confiugre Entra (AD) Connect

### AD Creds:
```
* domain: YOURDOMAIN.onmicrosoft.com
* user: rootuser
* password: CHOSEN AT DEPLOYMENT TIME, follow instructions
```

# Instructions 
* Use only your **personal** Microsoft account (not corporate/work)

### 1. Entra Tenant + Azure Prep
- If you don't have an Entra tenant and you create a new one, use as small as possible name, so the tenant name will be **no longer than 15 chars** (***TENANT-NAME***.onmicrosoft.com)

1. **Azure subscription**: [activate your free 150$ Azure credits](https://my.visualstudio.com/Benefits) (put in your personal Microsoft account, such as *yourname@outlook.com*), this will be used to deploy the Azure template and host the VMs

2. **Entra tenant**: 
    1. go to https://entra.microsoft.com and login with your personal Microsoft account, if you see an error "**``you don't have access``**"..: go to https://signup.azure.com to create a new Entra tenant (choose PAY AS YOU GO and enter credit cart, don't worry it's not gonna be used)
    
    2. Now that you have a tenant and can successfully browse https://entra.microsoft.com, **create a new admin user for the Entra tenant:** login to [Entra portal](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers/menuId/)

        ![createuser](pics/create_tenant_admin_user.png)

    2. under *Assignments* > add *Hybrid Identity Administrator* and *Global Administrator* > *Save > Review > Create*: 

        <img src="pics/role_assignment.png" width="500" />

    3. verify by signing in using the new account and finishing MFA setup:
    
        <img src="pics/signin.png" width="300" />

    4. keep these credentials, *we'll refer to them as **"ENTRA CREDS"***

    5. get your domain name (***YOURDOMAIN.onmicrosoft.com***): using your new ENTRA CREDS, find your domain [here](https://admin.microsoft.com/#/Domains)

3. **Enable Azure subscription management** using your **new Entra admin account**: 
    1. sign into [Azure portal](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties) (if link doesn't work, inside the Azure portal search for "Entra ID") and turn on the following toggle: 
        * make sure you are logged in with the correct, new Entra admin account (!)
        <img src="pics/manage_tenant.png" width="600" />

        * if the toggle is disabled, it probably means that you don't have any Azure subscription associated to your Entra tenant. If this is the case- go back and create another Entra admin account, this time in the CORRECT Entra tenant directory, that has an associated subscription.
    2. Refresh browser, Choose your Subscription > *IAM > Add role assignment*:

        <img src="pics/add_ga_azure.png" width="500" />

        *Privileged administrator roles > Owner*:

        <img src="pics/owner.png" width="400" />

        Next, select your new Entra admin user:

        <img src="pics/user_selected.png" width="400" />

    
        Next, select *Allow user to assign all roles (highly privileged)*
        Then, Click *Review and assign* and finish the process.

        **From this point on, you will this Entra admin account for the rest of the actions involving Entra / Azure**

##
### 2. Deploy Azure VMs - "On premise" Active Directory VMs
This part will deploy and configure an active directory domain with two VMs: a Domain Controller ("dcVm") and Win11 VM

Using your new Entra tenant's admin account, click here and follow instructions below:

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fshackcrack007%2Fhybrid-attacks-course-template%2Fmain%2Fmain.json)    

1. **Create a resource group:** where all the lab resources will be created
    * you may use *Israel Central* region, if something fails switch to US East 2

2. **Choose a password:** this password will be used for all Active Directory users + VMs (*we'll refer to them as **"AD CREDS"***)

4. **Choose a domain name:** it MUST be:
    * up to 15 chars (if not, follow [this guide](https://github.com/shackcrack007/hybrid-attacks-course-template/tree/main/OpenNewEntraTenantAndTransferSubscriptionOwnership))
    * **same as your Entra tenant!** (you can find it [here](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView))
    <img src="pics/deployment.png" width="600" />

5. **Choose VM Size**: if not auto filled you may choose the cheapest one: 1x Standard DS1 v2, 1 vcpu, 3.5 GB memory

6. **Deploy**: wait until it finishes
    * if the deployment fails again, you might need to re-register a provider: 
        Search for your subscription > **Resource providers** > look for **Microsoft.Network** and select **Re-register**: 
    
        <img src="pics/register_provider.png" width="500" />
    
    Alternatively, try Copilot error diagnose inside Azure, it's usually very helpful
    * If your deployment fails because your domain name is longer than 15 chars, then follow [this guide](https://github.com/shackcrack007/hybrid-attacks-course-template/tree/main/OpenNewEntraTenantAndTransferSubscriptionOwnership)

##
### 3. Prepare VMs
Once deployment has finished (will take a while..), do the following for **each VM, starting with dcVm**:
1. RDP (**to dcVm first**), using **```rootuser```** and your chosen password (you may find the IP address in the *Azure portal > Virtual machines*)

2. **Disable BOTH the Defender runtime protection AND cloud delivered protection** under *Virus and threat protection > Manage settings*:

    <img src="pics/defender.jpg" width="500" />

3. Open Powershell **as administrator** and run the script:
    * modify ***CHANGEME*** to your chosen password from the deployment ("AD CREDS")
    * modify ***YOURDOMAIN*** to your Entra tenant domain
    * if you see a pop up suggesting you to restart, WAIT until all scripts finish executio
    * the script should restart the VM when it finishes

    ```powershell 
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/prepareVM.ps1" -OutFile "C:\\prepareVM.ps1"; `
    & "C:\\prepareVM.ps1" `
    -DomainUser rootuser `
    -DomainPassword CHANGEME `
    -DomainName YOURDOMAIN.onmicrosoft.com # the one listed here https://admin.microsoft.com/#/Domains
    ```

4. repeat 1-3 for the **other VM**

* you might see errors here and there - ignore them

5. **Verification:**
    1. RDP to each VM using your **```YOURDOMAIN\user1```** and your chosen password
    2. look at c:\lab\LabSetupResults.txt and make sure all is installed properly, if something isn't then manually install it
    3. turn off the VMs, see you when the course starts!

### 4. Prepare local machine (PC / laptop)

Open Powershell as administrator and run:
```powershell 
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Verbose "Installing Az module, this wil take a few mins..."
    Install-Module -Name Az -Force -AllowClobber -Verbose
}
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Verbose "Installing Microsoft.Graph module, this wil take a few mins..."
    Install-Module -Name Microsoft.Graph -Force -AllowClobber -Verbose
}
```
# Resources Deletion

1. Delete any resources groups created (should be 2 if you've done lab-4)
1. Delete the synced users from Entra portal (`user1`, `user2`...)
1. Delete the application registration and service principals created for those apps under Enterprise Apps in the Entra portal


# Instructor internal prep notes for in-class sessions:
- Reset all MFA methods for the users 2-N
- Assign students with numbers starting with 2, this will be the user that they will be using throughout the class (ask them to send u their number so they won't forget)
- Share with students VMs ip address + creds
- Enable on Win11 VM multiple RDP sessions: 
    - Install https://github.com/fabianosrc/TermsrvPatcher to allow multiple RDP sessions on the Win11 - this only allows 4~ parallel connections
    - Enable unlimited connections: https://www.youtube.com/watch?v=mIyAceQbsXE
    - just to be on the safe side create another win11 vm / prepare multiple vms (or a client that is Win Server)
- Enable on DC VM multiple RDP sessions: 
    - follow this guide https://www.youtube.com/watch?v=S8QW_qiWin0
    - add the RDS license + then add it to the AD DS group by going to RD License manager -> dcVm right click -> Review
        - use Windows Server 2019 Remote Desktop Services device connections (50) license code (encrypted with aes-256-cbc): U2FsdGVkX1+vUUVLVbWv8EvfRkDw/Q+Ou7muMVdfQIMUVktnzzNowjyBPPS7U7sr
        - decrypt using my leet password (same as the video) on https://encrypt-online.com/
        - got the license code from https://my.visualstudio.com/ProductKeys?mkt=en-us
    - on gpedit.msc: 
        - `Computer Configuration\Administrative Templates\Windows Components\Terminal Services\Terminal Server\Connections\` Change `Restrict each user to a single session` to `Disable`
        - Enable unlimited connections: https://www.youtube.com/watch?v=mIyAceQbsXE
    - Add all users to remote desktop users group
    - restart