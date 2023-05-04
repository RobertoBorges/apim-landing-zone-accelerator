param keyVaultName            string
param managedIdentity         object      
param location                string
param appGatewayFQDN          string
@secure()
param certPassword            string  
param appGatewayCertType      string

var secretName = replace(appGatewayFQDN,'.', '-')
var subjectName='CN=${appGatewayFQDN}'

var certData = appGatewayCertType == 'selfsigned' ? 'null' : loadFileAsBase64('../certs/appgw.pfx')
var certPwd = appGatewayCertType == 'selfsigned' ? 'null' : certPassword

resource accessPolicyGrant 'Microsoft.KeyVault/vaults/accessPolicies@2019-09-01' = {
  name: '${keyVaultName}/add'
  properties: {
    accessPolicies: [
      {
        objectId: managedIdentity.properties.principalId
        tenantId: managedIdentity.properties.tenantId
        permissions: {
          secrets: [ 
            'get' 
            'list'
          ]
          certificates: [
            'import'
            'get'
            'list'
            'update'
            'create'
          ]
        }                  
      }
    ]
  }
}

resource appGatewayCertificate 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
  name: '${secretName}-certificate'
  dependsOn: [
    accessPolicyGrant
  ]
  location: location 
  kind: 'AzurePowerShell'
  properties: {
    azPowerShellVersion: '6.6'
    arguments: ' -vaultName ${keyVaultName} -certificateName ${secretName} -subjectName ${subjectName} -certPwd ${certPwd} -certDataString ${certData} -certType ${appGatewayCertType}'
    scriptContent: '''
      Install-Module -Name Az
      Import-Module Az

      $password = ConvertTo-SecureString -String "Ab156423" -Force -AsPlainText

      # Creating Root Certificate
      $rootCert = New-SelfSignedCertificate -CertStoreLocation "cert:\LocalMachine\My" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(10) -KeySpec Signature -KeyUsage CertSign, CRLSign, DigitalSignature, DataEncipherment, KeyAgreement -FriendlyName 'mydemocompany.com' -Subject 'CN=*.mydemocompany.com' -TextExtension @("2.5.29.17={text}DNS=*.mydemocompany.com&DNS=mydemocompany.com&DNS=*.scm.myase.mydemocompany.com") 
      $exportedCert = $rootCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      Set-Content -Path ".\mydemocompany.com.cer" -Value $exportedCert -Encoding Byte
      $exportedRootPfx = $rootCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password)
      Set-Content -Path ".\mydemocompany.com.pfx" -Value $exportedRootPfx -Encoding Byte

      # Creating the leaf certificate
      $signedLeafCert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation "cert:\LocalMachine\My" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(2) -KeySpec Signature -KeyUsage CertSign, CRLSign, DigitalSignature, DataEncipherment, KeyAgreement  -FriendlyName $certificateName -Subject 'CN='$certificateName -Signer $rootCert 
      $exportedCert = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      Set-Content -Path ".\apim.mydemocompany.com.cer" -Value $exportedCert -Encoding Byte
      $exportedPfx = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password)
      Set-Content -Path ".\apim.mydemocompany.com.pfx" -Value $exportedPfx -Encoding Byte

      # Creating the leaf certificate
      $signedLeafCert = New-SelfSignedCertificate -DnsName 'app1.mydemocompany.com' -CertStoreLocation "cert:\LocalMachine\My" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(2) -KeySpec Signature -KeyUsage CertSign, CRLSign, DigitalSignature, DataEncipherment, KeyAgreement  -FriendlyName 'app1.mydemocompany.com' -Subject 'CN=app1.mydemocompany.com' -Signer $rootCert 
      $exportedCert = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      Set-Content -Path ".\app1.mydemocompany.com.cer" -Value $exportedCert -Encoding Byte
      $exportedPfx = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password)
      Set-Content -Path ".\app1.mydemocompany.com.pfx" -Value $exportedPfx -Encoding Byte

      # Creating the leaf certificate
      $signedLeafCert = New-SelfSignedCertificate -DnsName 'app2.mydemocompany.com' -CertStoreLocation "cert:\LocalMachine\My" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(2) -KeySpec Signature -KeyUsage CertSign, CRLSign, DigitalSignature, DataEncipherment, KeyAgreement  -FriendlyName 'app1.mydemocompany.com' -Subject 'CN=app2.mydemocompany.com' -Signer $rootCert 
      $exportedCert = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      Set-Content -Path ".\app2.mydemocompany.com.cer" -Value $exportedCert -Encoding Byte
      $exportedPfx = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password)
      Set-Content -Path ".\app2.mydemocompany.com.pfx" -Value $exportedPfx -Encoding Byte

      # Creating the leaf certificate
      $signedLeafCert = New-SelfSignedCertificate -DnsName 'app3.mydemocompany.com' -CertStoreLocation "cert:\LocalMachine\My" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(2) -KeySpec Signature -KeyUsage CertSign, CRLSign, DigitalSignature, DataEncipherment, KeyAgreement  -FriendlyName 'app1.mydemocompany.com' -Subject 'CN=app3.mydemocompany.com' -Signer $rootCert 
      $exportedCert = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      Set-Content -Path ".\app3.mydemocompany.com.cer" -Value $exportedCert -Encoding Byte
      $exportedPfx = $signedLeafCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password)
      Set-Content -Path ".\app3.mydemocompany.com.pfx" -Value $exportedPfx -Encoding Byte

      # Importing certificates into Azure Key Vault
      $rootCertName = 'mydemocompany-com2'
      $leafCertName = 'apim-mydemocompany-com2'
      $leafCertName2 = 'app1-mydemocompany-com2'
      $leafCertName3 = 'app2-mydemocompany-com2'
      $leafCertName4 = 'app3-mydemocompany-com2'

      Import-AzKeyVaultCertificate -VaultName $vaultName -Name $rootCertName -FilePath ".\mydemocompany.com.pfx" -Password $password
      Import-AzKeyVaultCertificate -VaultName $vaultName -Name $leafCertName -FilePath ".\apim.mydemocompany.com.pfx" -Password $password
      Import-AzKeyVaultCertificate -VaultName $vaultName -Name $leafCertName2 -FilePath ".\app1.mydemocompany.com.pfx" -Password $password
      Import-AzKeyVaultCertificate -VaultName $vaultName -Name $leafCertName3 -FilePath ".\app2.mydemocompany.com.pfx" -Password $password
      Import-AzKeyVaultCertificate -VaultName $vaultName -Name $leafCertName4 -FilePath ".\app3.mydemocompany.com.pfx" -Password $password
      '''
    retentionInterval: 'P1D'
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '/subscriptions/${managedIdentity.subscriptionId}/resourceGroups/${managedIdentity.resourceGroupName}/providers/${managedIdentity.resourceId}': {}
    }
  }
}

module appGatewaySecretsUri 'certificateSecret.bicep' = {
  name: '${secretName}-certificate'
  dependsOn: [
    appGatewayCertificate
  ]
  params: {
    keyVaultName: keyVaultName
    secretName: secretName
  }
}

output secretUri string = appGatewaySecretsUri.outputs.secretUri
