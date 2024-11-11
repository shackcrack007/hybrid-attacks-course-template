---
description: This template creates a new Azure VM, it configures the VM to be an AD DC + Win11 VM
---
# Create an Azure VM with a new AD domain

This template will deploy a lab for the course: a new VM (along with a new VNet ) and will configure it as a Domain Controller and create a new forest and domain + win11 vm

As part of the lab setup, you will:
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
* Use only your personal Microsoft account, unless instructed otherwise

### 1. Entra Tenant + Azure Prep
1. **Azure subscription**: [activate your free 150$ Azure credits](https://my.visualstudio.com/Benefits) (put in your personal Microsoft account), this will be used to deploy the Azure template and host the VMs

2. **Entra tenant**: 
    1. create a new admin user for the Entra tenant: login to [Entra portal](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers/menuId/), and create a new user: 

        ![createuser](pics/create_tenant_admin_user.png)

    2. under *Assignments* > add *Hybrid Identity Administrator* and *Global Administrator* > *Save > Review > Create*: 

        <img src="pics/role_assignment.png" width="500" />

    3. verify by signing in using the new account and finishing MFA setup:
    
        <img src="pics/signin.png" width="300" />

    4. keep these credentials, *we'll refer to them as **"ENTRA CREDS"***

3. **Enable Azure subscription management** using your **new Entra admin account**: 
    1. sign into [Azure portal](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties) (if link doesn't work, inside the Azure portal search for "Entra ID") and turn on the following toggle: 
        * make sure you are logged in with the correct, new Entra admin account (!)
        <img src="pics/manage_tenant.png" width="600" />

        * if the toggle is disabled, it probably means that you don't have any Azure subscription associated to your Entra tenant. If this is the case- go back and create another Entra admin account, this time in the CORRECT Entra tenant directory, that has an associated subscription.
    2. Refresh browser, find your subscription > *IAM > Add role assignment*:

        <img src="pics/add_ga_azure.png" width="500" />

        *Privileged administrator roles > Owner*:

        <img src="pics/owner.png" width="400" />

        Next, select your new Entra admin user:

        <img src="pics/user_selected.png" width="400" />

    
        Next, select *Allow user to assign all roles (highly privileged)*
        Then, Click *Review and assign* and finish the process.

        ### **From this point on, you will this Entra admin account for the rest of the actions involving Entra / Azure**

##
### 2. Deploy Azure VMs - "On premise" Active Directory VMs
This part will deploy and configure an active directory domain with two VMs: a Domain Controller ("dcVm") and Win11 VM
1. Using your new Entra tenant's admin account: 

    [![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fshackcrack007%2Fhybrid-attacks-course-template%2Fmain%2Fmain.json)

2. create a resource group where all the lab resources will be created
    * you may use *Israel Central* region, if something fails switch to US East 2

3. Choose a password - this password will be used for all Active Directory users + VMs (*we'll refer to them as **"AD CREDS"***)

4. Choose a domain name: it MUST be the same as your Entra tenant (!)

5. Deploy and wait until it finishes
    <img src="pics/deployment.png" width="600" />

    * if the deployment fails again, you might need to re-register a provider: 
        Search for your subscription > **Resource providers** > look for **Microsoft.Network** and select **Re-register**: 
    
    <img src="pics/register_provider.png" width="500" />
    
    * Alternatively, try Copilot error diagnose inside Azure, it's usually very helpful

##
### 3. Prepare VMs
Once deployment has finished (will take a while..), do the following for **each VM**, starting with dcVm:
1. RDP using '***rootuser***' and your chosen password (you may find the IP address in the *Azure portal > Virtual machines*)
2. **Disable BOTH the Defender runtime protection AND cloud delivered protection** under *Virus and threat protection > Manage settings*:

    <img src="pics/defender.jpg" width="500" />

3. Open Powershell **as administrator** and run the script:
* modify ***CHANGEME*** to your chosen password
* modify ***YOURDOMAIN*** to your Entra tenant domain

    ```powershell 
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/prepareVM.ps1" -OutFile "C:\\prepareVM.ps1"; `
    & "C:\\prepareVM.ps1" `
    -DomainUser rootuser `
    -DomainPassword CHANGEME `
    -DomainName YOURDOMAIN.onmicrosoft.com
    ```

* ignore the errors
* check for a text file on your desktop, if doesn't exists, run the script again
    * *make sure it exists on both VMs*
* when done, turn off the VMs, see you when the course starts!