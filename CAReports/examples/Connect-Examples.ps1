# Examples showing how to connect to Microsoft Graph using the Connect-CAGraph function

# Example 1: Basic interactive authentication
Connect-CAGraph -TenantId "contoso.onmicrosoft.com"

# Example 2: Interactive authentication with client ID
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012"

# Example 3: Client credential flow with secure string
# Note: As of module version 0.1.0+, ClientSecret must be a SecureString
$secureSecret = ConvertTo-SecureString -String "YourSecretHere" -AsPlainText -Force
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -ClientSecret $secureSecret

# Example 4: Certificate-based authentication
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

# Example 5: Using different environment and custom output path
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -Environment "Development" -OutputPath "C:\CAReports"

# Migration Example: Converting code from older version with string-based ClientSecret
# If you have existing scripts using the old format:
# OLD: Connect-CAGraph -TenantId "tenant" -ClientId "id" -ClientSecret "secret"
# 
# Change it to:
$secureSecret = ConvertTo-SecureString -String "secret" -AsPlainText -Force
Connect-CAGraph -TenantId "tenant" -ClientId "id" -ClientSecret $secureSecret 