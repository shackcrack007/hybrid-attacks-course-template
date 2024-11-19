
@description('Location for all resources.')
var location = resourceGroup().location

@description('Name of the subnet within the existing Virtual Network.')
param subnetName string

@description('ID of the existing Virtual Network.')
param virtualNetworkId string

@description('Private IP address for the second Windows 11 VM.')
var windows11PrivateIPAddress = '10.0.0.11'

@description('DO NOT CHANGE! The name of the administrator account of the new VM and domain')
var adminUsername = 'rootuser'

@description('The password for the administrator account of the new VM and domain')
@secure()
param adminPassword string 

@description('Change to *your* tenant domain name (e.g. "YOURDOMAIN.onmicrosoft.com"), it will set up the Active Directory Domain with the same name (must be the same). "YOURDOMAIN" cant be more than 15 chars!')
param domainName string = 'YOURDOMAIN.onmicrosoft.com'

@description('Size of the VM for the controller (preffered Standard_D2s_v3)')
param vmSize string = 'Standard_DS1_v2'

@description('Windows 11 virtual machine name.')
var windows11VMName = 'win11VM-lab4'

@description('DNS servers to use for the network interface of the win11 VMs.')
var dnsServers = [
  '10.0.0.10'
  '8.8.4.4'
]
resource windows11PublicIPAddress 'Microsoft.Network/publicIPAddresses@2022-07-01' = {
  name: '${windows11VMName}-2-publicIP'
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

resource windows11NetworkInterface 'Microsoft.Network/networkInterfaces@2022-07-01' = {
  name: '${windows11VMName}-2-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: windows11PrivateIPAddress
          subnet: {
            id: '${virtualNetworkId}/subnets/${subnetName}'
          }
          publicIPAddress: {
            id: windows11PublicIPAddress.id
          }
        }
      }
    ]
    dnsSettings: {
      dnsServers: dnsServers
    }
  }
}

resource virtualMachineWin11_lab4 'Microsoft.Compute/virtualMachines@2022-08-01' = {
  name: '${windows11VMName}-2'
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: '${windows11VMName}-2'
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
        name: '[format("{0}_OSDisk", "${windows11VMName}-2")]'
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
