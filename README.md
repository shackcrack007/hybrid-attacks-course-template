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
* domain: mylab.local
* user: rootuser
* password: CHOSEN AT DEPLOYMENT TIME, follow instructions
```

# Instructions 
* Use only your personal Microsoft account, unless instructed otherwise

### 1. Entra Tenant + Azure Prep
1. **Azure subscription**: [activate your free 150$ Azure credits](https://my.visualstudio.com/Benefits) (put in your personal Microsoft account), this will be used to deploy the Azure template and host the VMs

2. **Entra tenant**: 
    1. create a new admin user for the Entra tenant: login to [Entra portal](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers/menuId/), and create a new user: ![createuser](pics/create_tenant_admin_user.png)

    2. under *Assignments* > add *Hybrid Identity Administrator* and *Global Administrator* and save: 
    ![roles](pics/role_assignment.png) 

    3. verify by signing in using the new account and finishing MFA setup: ![signin](pics/signin.png)

    4. keep these creds, *we'll refer to them as **"ENTRA CREDS"***

3. **Enable Azure subscription management**, using your **new Entra admin account**: 
    1. sign into [Azure portal](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties) (if link doesn't work, look inside for "Entra") and turn on the following toggle: ![manage_enable](pics/manage_tenant.png) 

    2. Refresh browser, search and select your subscription > *IAM > Add role assignment*:
    ![addrole](pics/add_ga_azure.png)
    *Privileged administrator roles > Owner*:
    ![owner](pics/owner.png)
    Next, select your new Entra admin user:
    ![user](pics/user_selected.png)
    Next, select *Allow user to assign all roles (highly privileged)*

    Then, Click *Review and assign* and finish the process.

### 2. Deploy Azure VMs - "On premise" Active Directory VMs
1. create a resource group where all the lab resources will be created (you may use Israel Central, if something fails switch to US East 2)  
2. in your **personal** Azure subscription click here: [![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fshackcrack007%2Fhybrid-attacks-course-template%2Fmain%2Fmain.json)
    * if fails, you might need to re-register a provider: Search for your subscription > **Resource providers** > look for **Microsoft.Network** and seelct **Re-register**: ![register](pics/register_provider.png)
    * if it fails, try Copilot error diagnose inside Azure, it's usually very helpful
3. keep the password- *we'll refer to it as **"AD CREDS"***:
![deployment](pics/deployment.png)

### 3. Prepare VMs
Once deployment is finished, do the following for **each VM**:
1. RDP using '***rootuser***' and your chosen password 
2. **disable the Defender runtime protection and cloud delivered protection** (under *Virus and threat protection > Manage settings*)
![defender](pics/defender.jpg)
3. Open Powershell **as administrator** and run the script, modify *CHANGEME* to your chosen password:
```powershell 
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/prepareVM.ps1" -OutFile "C:\\prepareVM.ps1"; `
& "C:\\prepareVM.ps1" `
-DomainUser rootuser `
-DomainPassword CHANGEME `
-DomainName mylab.local
```
* ignore the errors, validation will occur later

### 4. Entra Connect configurations
Prepare your Entra + AD creds:
1. on the DC VM, install "AzureADConnect.msi" from your dekstop and then run it
2. If you encounter an error where it cannot resolve a domain, then open Internet Explorer and Edge and browse to google
3. follow setup
4. if you encounter another unknown error, it's probably due to MFA enforced (AD Connect must have an exclusion):
    1. [here](https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies/fromNav/) look for "***Require multifactor authentication for all users***" policy, and add an exlclusion like this to the "Sync" user, and save the policy: ![add_mfa_exclusion](pics/fix_mfa.png)

5. Configure > "Customize synchronization options" > check "password writeback" !["password writeback"](pics/pass_writeback.png) and finish setup

6. Configure > "Configure device options" > "Configure Hybrid Microsoft Entra ID join" > check "Windows 10 or later".. > select "mylab" and click Add and enter your AD Creds > select Authentication service "Entra ID" > click Configure

### 5. Verify
1. go to https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices/menuId/Overview and look for your onboarded devices, they should be listed as "Microsoft Entra hybrid joined" under the "Join type" column

2. go to https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers/menuId/ and look for users1-40, they should be listed as "Yes" under the "On-premise sync enabled" column