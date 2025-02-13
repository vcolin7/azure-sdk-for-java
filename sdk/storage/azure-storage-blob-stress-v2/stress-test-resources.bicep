param baseName string
param endpointSuffix string = 'core.windows.net'
param location string = resourceGroup().location
param storageApiVersion string = '2022-09-01'

var primaryAccountName = '${baseName}'
var pageBlobStorageAccountName = '${baseName}pageblob'

resource primaryAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: primaryAccountName
  location: location
  sku: {
    name: 'Premium_LRS'
  }
  kind: 'BlockBlobStorage'
  properties: {}
}


var sasToken = primaryAccount.listAccountSas('2021-04-01', {
  signedServices: 'b'
  signedResourceTypes: 'c'
  signedPermission: 'rwdl'
  signedExpiry: '2025-12-31T23:59:59Z'
}).accountSasToken

/*resource pageBlobStorageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: pageBlobStorageAccountName
  location: location
  sku: {
    name: 'Premium_LRS'
  }
  kind: 'StorageV2'
  properties: {}
}*/

output STORAGE_ENDPOINT_STRING string = '"https://${primaryAccountName}.blob.core.windows.net/${sasToken}"'
output PAGE_BLOB_STORAGE_ENDPOINT_STRING string = '"https://${pageBlobStorageAccountName}.blob.core.windows.net/${sasToken}"'
