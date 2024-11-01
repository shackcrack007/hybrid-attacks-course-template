@description('DO NOT CHANGE! The name of the administrator account of the new VM and domain')
var adminUsername = 'rootuser'

@description('The password for the administrator account of the new VM and domain')
@secure()
param adminPassword string 

@description('DO NOT CHANGE! The FQDN of the Active Directory Domain to be created')
var domainName = 'mylab.local'

@description('DO NOT CHANGE! The DNS prefix for the public IP address used by the Load Balancer')
var dnsPrefix = 'mylab'

@description('Size of the VM for the controller')
param vmSize string = 'Standard_D2s_v3'

@description('The location of resources, such as templates and DSC modules, that the template depends on. do not modify.')
var _artifactsLocation = deployment().properties.templateLink.uri

@description('Auto-generated token to access _artifactsLocation. Leave it blank unless you need to provide your own value.')
var _artifactsLocationSasToken = ''

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Virtual machine name.')
var DCvirtualMachineName = 'adDcVM'

@description('Virtual network name.')
var virtualNetworkName = 'adVNET'

@description('Virtual network address range.')
var virtualNetworkAddressRange = '10.0.0.0/16'

@description('Load balancer front end IP address name.')
var loadBalancerFrontEndIPName = 'LoadBalancerFE'

@description('Backend address pool name.')
var backendAddressPoolName = 'LoadBalancerBE'

@description('Inbound NAT rules name.')
var inboundNatRulesName = 'adRDP'

@description('Network interface name.')
var networkInterfaceName = 'adNic'

@description('Private IP address.')
var privateIPAddress = '10.0.0.4'

@description('Subnet name.')
var subnetName = 'adSubnet'

@description('Subnet IP range.')
var subnetRange = '10.0.0.0/24'

@description('Subnet IP range.')
var publicIPAddressName = 'adPublicIP'

@description('Availability set name.')
var availabilitySetName  = 'adAvailabiltySet'

@description('Load balancer name.')
var loadBalancerName = 'adLoadBalancer'

@description('Windows 11 virtual machine name.')
var windows11VMName = 'win11VM'

@description('Private IP address for Windows 11 VM.')
var windows11PrivateIPAddress = '10.0.0.10'

@description('Public IP address name for Windows 11 VM.')
var windows11PublicIPAddressName = 'win11PublicIP'

resource publicIPAddress 'Microsoft.Network/publicIPAddresses@2022-07-01' = {
  name: publicIPAddressName
  location: location
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: dnsPrefix
    }
  }
}

resource availabilitySet 'Microsoft.Compute/availabilitySets@2022-08-01' = {
  location: location
  name: availabilitySetName
  properties: {
    platformUpdateDomainCount: 20
    platformFaultDomainCount: 2
  }
  sku: {
    name: 'Aligned'
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

resource loadBalancer 'Microsoft.Network/loadBalancers@2022-07-01' = {
  name: loadBalancerName
  location: location
  properties: {
    frontendIPConfigurations: [
      {
        name: loadBalancerFrontEndIPName
        properties: {
          publicIPAddress: {
            id: publicIPAddress.id
          }
        }
      }
    ]
    backendAddressPools: [
      {
        name: backendAddressPoolName
      }
    ]
    inboundNatRules: [
      {
        name: inboundNatRulesName
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', loadBalancerName, loadBalancerFrontEndIPName)
          }
          protocol: 'Tcp'
          frontendPort: 3389
          backendPort: 3389
          enableFloatingIP: false
        }
      }
    ]
  }
}

resource networkInterface 'Microsoft.Network/networkInterfaces@2022-07-01' = {
  name: networkInterfaceName
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
          loadBalancerBackendAddressPools: [
            {
              id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', loadBalancerName, backendAddressPoolName)
            }
          ]
          loadBalancerInboundNatRules: [
            {
              id: resourceId('Microsoft.Network/loadBalancers/inboundNatRules', loadBalancerName, inboundNatRulesName)
            }
          ]
        }
      }
    ]
  }
  dependsOn: [
    VNet
    loadBalancer
  ]
}

resource virtualMachine 'Microsoft.Compute/virtualMachines@2022-08-01' = {
  name: DCvirtualMachineName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    availabilitySet: {
      id: availabilitySet.id
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
  dependsOn: [
    loadBalancer
  ]
}

resource createADForest 'Microsoft.Compute/virtualMachines/extensions@2022-08-01' = {
  parent: virtualMachine
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
  name: windows11PublicIPAddressName
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
    windows11PublicIPAddress
  ]
}

resource windows11VM 'Microsoft.Compute/virtualMachines@2022-08-01' = {
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
  dependsOn: [
    windows11NetworkInterface
  ]
}

resource runCommandOnADVM 'Microsoft.Compute/virtualMachines/runCommands@2022-08-01' = {
  name: '${DCvirtualMachineName}/RunPowerShellScript'
  location: location
  properties: {
    source: {
      script: 'Invoke-WebRequest -Uri "https://url.com/script.ps1" -OutFile "C:\\script.ps1"; & "C:\\script.ps1"'
    }
    parameters: []
  }
  dependsOn: [
    virtualMachine
  ]
}
