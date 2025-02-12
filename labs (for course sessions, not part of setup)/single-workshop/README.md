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
    - Install https://github.com/fabianosrc/TermsrvPatcher to allow multiple RDP sessions on the Win11
- Lab 3 - Token Attacks
    - RDP using your assigned user (**not** `user1`)
    - Skip MFA setup if possible
    - after rdp login, try to go to entra.microsoft.com and make sure you are logged in
- Lab 4 - CTF
    - skip Preparations  
    - Start with RDP to the DC VM using rootuser and the cred the instructor gave you