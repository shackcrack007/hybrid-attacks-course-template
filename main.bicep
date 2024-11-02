@description('DO NOT CHANGE! The name of the administrator account of the new VM and domain')
var adminUsername = 'rootuser'

@description('The password for the administrator account of the new VM and domain')
@secure()
param adminPassword string 

@description('DO NOT CHANGE! The FQDN of the Active Directory Domain to be created')
var domainName = 'mylab.local'

@description('Size of the VM for the controller')
param vmSize string = 'Standard_D2s_v3'

@description('The location of resources, such as templates and DSC modules, that the template depends on. do not modify.')
var _artifactsLocation = deployment().properties.templateLink.uri

@description('Auto-generated token to access _artifactsLocation. Leave it blank unless you need to provide your own value.')
var _artifactsLocationSasToken = ''

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Virtual machine name.')
var DCvirtualMachineName = 'dcVM'

@description('Windows 11 virtual machine name.')
var windows11VMName = 'win11VM'

@description('Virtual network name.')
var virtualNetworkName = 'lab-VNET'

@description('Virtual network address range.')
var virtualNetworkAddressRange = '10.0.0.0/16'

@description('Private IP address.')
var privateIPAddress = '10.0.0.4'

@description('Subnet name.')
var subnetName = 'lab-subnet'

@description('Subnet IP range.')
var subnetRange = '10.0.0.0/24'

@description('Private IP address for Windows 11 VM.')
var windows11PrivateIPAddress = '10.0.0.10'

resource runCommandOnDCVMPrepartion 'Microsoft.Compute/virtualMachines/runCommands@2022-08-01' = {
  parent: virtualMachineDC
  name: 'RunPowerShellScriptDCDisablePrepartion'
  location: location
  properties: {
    source: {
      script: '''
      param (
        [string]$adminUsername
        [string]$adminPassword
        [string]$domainName
      )

      Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/prepareVM.ps1" -OutFile "C:\\prepareVM.ps1"; & "C:\\prepareVM.ps1" -DomainUser $adminUsername -DomainPassword $adminPassword -DomainName $domainName
      '''
    }
    parameters: [
      {
        name: 'adminUsername'
        value: adminUsername
      }
      {
        name: 'adminPassword'
        value: adminPassword
      }
      {
        name: 'domainName'
        value: domainName
      }
    ]
  }
  dependsOn: [
    runCommandOnDCVMDisableAV
  ]
}

resource runCommandOnDCVMDisableAV 'Microsoft.Compute/virtualMachines/runCommands@2022-08-01' = {
  parent: virtualMachineDC
  name: 'RunPowerShellScriptDCDisableAV'
  location: location
  properties: {
    source: {
      script: '''
      # Start logging
      Start-Transcript -Path "c:\DisableAV.txt" -Append

      # Disable Windows Updates
      Set-Service -Name wuauserv -StartupType Disabled
      Stop-Service -Name wuauserv

      # Disable Windows Defender
      try {   
          Set-MpPreference -DisableRealtimeMonitoring $true
          Set-MpPreference -DisableBehaviorMonitoring $true
          Set-MpPreference -DisableBlockAtFirstSeen $true
          Set-MpPreference -DisableIOAVProtection $true
          Set-MpPreference -DisablePrivacyMode $true
          Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
          Stop-Service -Name WinDefend
          Set-Service -Name WinDefend -StartupType Disabled
      } catch {
      }
      Set-MpPreference -MAPSReporting Disabled
      # Disable Intrusion Prevention System
      Set-MpPreference -DisableIntrusionPreventionSystem $true
      # Disable Automatic Sample Submission
      Set-MpPreference -SubmitSamplesConsent 2
      
      # Stop logging
      Stop-Transcript
      '''
    }
    parameters: []
  }
}

resource runCommandOnWin11VMDisableAV 'Microsoft.Compute/virtualMachines/runCommands@2022-08-01' = {
  parent: virtualMachineWin11
  name: 'RunPowerShellScriptWin11DisableAV'
  location: location
  properties: {
    source: {
      script: '''
      # Start logging
      Start-Transcript -Path "c:\DisableAV.txt" -Append

      # Disable Windows Updates
      Set-Service -Name wuauserv -StartupType Disabled
      Stop-Service -Name wuauserv

      # Disable Windows Defender
      try {   
          Set-MpPreference -DisableRealtimeMonitoring $true
          Set-MpPreference -DisableBehaviorMonitoring $true
          Set-MpPreference -DisableBlockAtFirstSeen $true
          Set-MpPreference -DisableIOAVProtection $true
          Set-MpPreference -DisablePrivacyMode $true
          Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
          Stop-Service -Name WinDefend
          Set-Service -Name WinDefend -StartupType Disabled
      } catch {
      }
      Set-MpPreference -MAPSReporting Disabled
      # Disable Intrusion Prevention System
      Set-MpPreference -DisableIntrusionPreventionSystem $true
      # Disable Automatic Sample Submission
      Set-MpPreference -SubmitSamplesConsent 2
      
      # Stop logging
      Stop-Transcript
      '''
    }
  }
}

resource runCommandOnWin11VMPrepartion 'Microsoft.Compute/virtualMachines/runCommands@2022-08-01' = {
  parent: virtualMachineWin11
  name: 'RunPowerShellScriptWin11Prepartion'
  location: location
  properties: {
    source: {
      script: '''
      param (
        [string]$adminUsername
        [string]$adminPassword
        [string]$domainName
      )

      Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/prepareVM.ps1" -OutFile "C:\\prepareVM.ps1"; & "C:\\prepareVM.ps1" -DomainUser $adminUsername -DomainPassword $adminPassword -DomainName $domainName
      '''
    }
    parameters: [
      {
        name: 'adminUsername'
        value: adminUsername
      }
      {
        name: 'adminPassword'
        value: adminPassword
      }
      {
        name: 'domainName'
        value: domainName
      }
    ]
  }
  dependsOn: [
    runCommandOnWin11VMDisableAV
  ]
}

resource dcPublicIPAddress 'Microsoft.Network/publicIPAddresses@2022-07-01' = {
  name: '${DCvirtualMachineName}-publicIP'
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

module VNet 'nestedtemplates/vnet.bicep' = {
  scope: resourceGroup()
  name: 'VNet'
  params: {
    virtualNetworkName: virtualNetworkName
    virtualNetworkAddressRange: virtualNetworkAddressRange
    subnetName: subnetName
    subnetRange: subnetRange
    location: location
  }
}

resource networkInterface 'Microsoft.Network/networkInterfaces@2022-07-01' = {
  name: '${DCvirtualMachineName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: privateIPAddress
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', virtualNetworkName, subnetName)
          }
          publicIPAddress: {
            id: dcPublicIPAddress.id
          }
        }
      }
    ]
  }
  dependsOn: [
    VNet
    ]
}

resource virtualMachineDC 'Microsoft.Compute/virtualMachines@2022-08-01' = {
  name: DCvirtualMachineName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: DCvirtualMachineName
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2019-Datacenter'
        version: 'latest'
      }
      osDisk: {
        name: '${DCvirtualMachineName}_OSDisk'
        caching: 'ReadOnly'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
      dataDisks: [
        {
          name: '${DCvirtualMachineName}_DataDisk'
          caching: 'ReadWrite'
          createOption: 'Empty'
          diskSizeGB: 20
          managedDisk: {
            storageAccountType: 'StandardSSD_LRS'
          }
          lun: 0
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
        }
      ]
    }
  }
}

resource createADForest 'Microsoft.Compute/virtualMachines/extensions@2022-08-01' = {
  parent: virtualMachineDC
  name: 'CreateADForest'
  location: location
  properties: {
    publisher: 'Microsoft.Powershell'
    type: 'DSC'
    typeHandlerVersion: '2.19'
    autoUpgradeMinorVersion: true
    settings: {
      ModulesUrl: uri(_artifactsLocation, 'DSC/CreateADPDC.zip${_artifactsLocationSasToken}')
      ConfigurationFunction: 'CreateADPDC.ps1\\CreateADPDC'
      Properties: {
        DomainName: domainName
        AdminCreds: {
          UserName: adminUsername
          Password: 'PrivateSettingsRef:AdminPassword'
        }
      }
    }
    protectedSettings: {
      Items: {
        AdminPassword: adminPassword
      }
    }
  }
}

module updateVNetDNS 'nestedtemplates/vnet-with-dns-server.bicep' = {
  scope: resourceGroup()
  name: 'UpdateVNetDNS'
  params: {
    virtualNetworkName: virtualNetworkName
    virtualNetworkAddressRange: virtualNetworkAddressRange
    subnetName: subnetName
    subnetRange: subnetRange
    DNSServerAddress: [
      privateIPAddress
    ]
    location: location
  }
  dependsOn: [
    createADForest
  ]
}

resource windows11PublicIPAddress 'Microsoft.Network/publicIPAddresses@2022-07-01' = {
  name: '${windows11VMName}-publicIP'
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

resource windows11NetworkInterface 'Microsoft.Network/networkInterfaces@2022-07-01' = {
  name: '${windows11VMName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: windows11PrivateIPAddress
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', virtualNetworkName, subnetName)
          }
          publicIPAddress: {
            id: windows11PublicIPAddress.id
          }
        }
      }
    ]
  }
  dependsOn: [
    VNet
  ]
}

resource virtualMachineWin11 'Microsoft.Compute/virtualMachines@2022-08-01' = {
  name: windows11VMName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: windows11VMName
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsDesktop'
        offer: 'Windows-11'
        sku: 'win11-21h2-pro'
        version: 'latest'
      }
      osDisk: {
        name: '${windows11VMName}_OSDisk'
        caching: 'ReadOnly'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: windows11NetworkInterface.id
        }
      ]
    }
  }
}

resource autoShutdownScheduleDcVm_8AM 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: '${DCvirtualMachineName}-autoShutdownScheduleDcVm_8AM'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: '08:00' // 8 AM Israel time (UTC+2)
    }
    timeZoneId: 'Israel Standard Time'
    targetResourceId: virtualMachineDC.id
    notificationSettings: {
      status: 'Disabled'
    }
  }
}

resource autoShutdownScheduleDcVm_8PM 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: '${DCvirtualMachineName}-autoShutdownScheduleDcVm_8PM'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: '20:00' // 8 PM Israel time (UTC+2)
    }
    timeZoneId: 'Israel Standard Time'
    targetResourceId: virtualMachineDC.id
    notificationSettings: {
      status: 'Disabled'
    }
  }
}

resource autoShutdownScheduleWin11VM_8AM 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: '${windows11VMName}-autoShutdownScheduleWin11VM_8AM'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: '08:00' // 8 AM Israel time (UTC+2)
    }
    timeZoneId: 'Israel Standard Time'
    targetResourceId: virtualMachineWin11.id
    notificationSettings: {
      status: 'Disabled'
    }
  }
}

resource autoShutdownScheduleWin11VM_8PM 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: '${windows11VMName}-autoShutdownScheduleWin11VM_8PM'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: '20:00' // 8 PM Israel time (UTC+2)
    }
    timeZoneId: 'Israel Standard Time'
    targetResourceId: virtualMachineWin11.id
    notificationSettings: {
      status: 'Disabled'
    }
  }
}
