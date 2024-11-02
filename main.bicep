@description('DO NOT CHANGE! The name of the administrator account of the new VM and domain')
var adminUsername = 'rootuser'

@description('The password for the administrator account of the new VM and domain')
@secure()
param adminPassword string 

@description('DO NOT CHANGE! The FQDN of the Active Directory Domain to be created')
var domainName = 'mylab.local'

@description('Size of the VM for the controller (preffered Standard_D2s_v3)')
param vmSize string = 'Standard_DS1_v2'

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
    disableDefenderScriptonDc
  ]
}

resource disableDefenderScriptonDc 'Microsoft.Compute/virtualMachines/extensions@2021-07-01' = {
  name: 'disableDefenderDC'
  parent: virtualMachineDC
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    settings: {
      fileUris: [
        'https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/disableAv.ps1'
      ]
    }
    protectedSettings: {
      commandToExecute: 'powershell -ExecutionPolicy Unrestricted -File disableAv.ps1'
    }
  }
}


resource disableDefenderScriptonWin11 'Microsoft.Compute/virtualMachines/extensions@2021-07-01' = {
  name: 'disableDefenderWin11'
  parent: virtualMachineWin11
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    settings: {
      fileUris: [
        'https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/disableAv.ps1'
      ]
    }
    protectedSettings: {
      commandToExecute: 'powershell -ExecutionPolicy Unrestricted -File disableAv.ps1'
    }
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
      Start-Transcript -Path "c:\download-DisableAV.txt" -Append

      Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
      Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shackcrack007/hybrid-attacks-course-template/main/disableAv.ps1" -OutFile "C:\\DisableAV.ps1"; & "C:\\DisableAV.ps1"
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
      Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
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
