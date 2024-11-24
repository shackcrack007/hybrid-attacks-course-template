output tenantDisplayName string = tenant().displayName

@description('DO NOT CHANGE! The name of the administrator account of the new VM and domain')
var adminUsername = 'rootuser'

@description('The password for the administrator account of the new VM and domain')
@secure()
param adminPassword string 

@description('Change to *your* tenant domain name (e.g. "YOURDOMAIN.onmicrosoft.com"), it will set up the Active Directory Domain with the same name (must be the same). "YOURDOMAIN" cant be more than 15 chars!')
param domainName string = 'YOURDOMAIN.onmicrosoft.com'

@description('Size of the VM for the controller (preffered Standard_D2s_v3)')
param vmSize string = 'Standard_DS1_v2'

@description('The location of resources, such as templates and DSC modules, that the template depends on. do not modify.')
var _artifactsLocation = deployment().properties.templateLink.uri

@description('Auto-generated token to access _artifactsLocation. Leave it blank unless you need to provide your own value.')
var _artifactsLocationSasToken = ''

@description('Location for all resources.')
var location = resourceGroup().location

@description('Virtual machine name.')
var DCvirtualMachineName = 'dcVM'

@description('Windows 11 virtual machine name.')
var windows11VMName = 'win11VM'

@description('Virtual network name.')
var virtualNetworkName = 'lab-VNET'

@description('Virtual network address range.')
var virtualNetworkAddressRange = '10.0.0.0/16'

@description('Private IP address for the DC VM.')
var privateIPAddress = '10.0.0.10'

@description('Subnet name.')
var subnetName = 'lab-subnet'

@description('Subnet IP range.')
var subnetRange = '10.0.0.0/24'

@description('Private IP address for Windows 11 VM.')
var windows11PrivateIPAddress = '10.0.0.11'

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
