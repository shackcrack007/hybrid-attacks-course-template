# Agenda
## Theoretical:
- device  + application identities
- aadinternals + roadrecon - quick demo
- powershell msgraph + aadgraph - quick demo
- demo (screenshosts): entra connect: dump creds -> recon target users -> reset password
- demo (video): steal PRT Token
 
## Labs:
- Instructor internal notes:
    - Reset all MFA methods for the users 2-N
    - Assign students numbers starting with 2, this will be the user that they will be using throughout the class
    - Share VMs ip address + creds
    - prepare multiple vms (or a client that is Win Server) as there can be only 4 users connected to a single VM in parallel, even if using TermsrvPatcher    
        - Install https://github.com/fabianosrc/TermsrvPatcher to allow multiple RDP sessions on the Win11 - this only allows 4~ parallel connections
    - Enable on DC VM multiple RDP sessions: 
        - follow this guide https://www.youtube.com/watch?v=S8QW_qiWin0
        - add the RDS license + then add it to the AD DS group by going to RD License manager -> dcVm right click -> Review
            - use Windows Server 2019 Remote Desktop Services device connections (50) license code (encrypted with aes-256-cbc): U2FsdGVkX1+vUUVLVbWv8EvfRkDw/Q+Ou7muMVdfQIMUVktnzzNowjyBPPS7U7sr
            - decrypt using my leet password (same as the video) on https://encrypt-online.com/
            - got the license code from https://my.visualstudio.com/ProductKeys?mkt=en-us
        - on gpedit.msc Navigate to: Computer Configuration\Administrative Templates\Windows Components\Terminal Services\Terminal Server\Connections\
            Change `Restrict each user to a single session` to `Disable`
        - Add all users to remote desktop users group
        
        - shouldn't be needed:
            ```powershell
            # Run as Administrator

            # Install Remote Desktop Services Role
            Write-Host "Installing Remote Desktop Services..." -ForegroundColor Green
            Install-WindowsFeature -Name RDS-RD-Server -IncludeAllSubFeature -IncludeManagementTools -Restart

            # Install Remote Desktop Licensing Role
            Write-Host "Installing Remote Desktop Licensing..." -ForegroundColor Green
            Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools

            # Set RDS Licensing Server
            $LicensingServer = "Your-Licensing-Server-Name"  # Change this to your actual server name
            Write-Host "Setting RDS Licensing Server to $LicensingServer..." -ForegroundColor Green
            $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSLicensing"
            New-ItemProperty -Path $RegPath -Name "SpecifiedLicenseServerList" -Value $LicensingServer -PropertyType String -Force

            # Set Licensing Mode (2 = Per Device, 4 = Per User)
            Write-Host "Configuring RDS Licensing Mode to 'Per User'..." -ForegroundColor Green
            $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core"
            New-ItemProperty -Path $RegPath -Name "LicensingMode" -Value 4 -PropertyType DWORD -Force

            # Configure Group Policy Settings
            Write-Host "Configuring Group Policy settings for RDS Licensing..." -ForegroundColor Green
            $GPOPath = "HKLM:\SOFTWARE\Pol
        
            ```
- Lab 3 - Token Attacks
    - RDP using your assigned user (**not** `user1`)
    - Skip MFA setup if possible
    - after rdp login, try to go to entra.microsoft.com and make sure you are logged in
- Lab 4 - CTF
    - skip Preparations  
    - Start with RDP to the DC VM using rootuser and the cred the instructor gave you