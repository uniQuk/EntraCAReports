# CAReports PowerShell Module User Guide

## Introduction

CAReports is a PowerShell module designed for Microsoft Entra ID administrators to analyze, document, and report on Conditional Access policies. This guide provides detailed instructions on how to use the module effectively across both Windows and macOS platforms.

## Prerequisites

Before using CAReports, ensure you have:

- PowerShell 7.0 or higher installed
- Required PowerShell modules:
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Groups
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.DirectoryManagement
  - ImportExcel
  - powershell-yaml
- Appropriate permissions in your Microsoft Entra ID tenant (Policy.Read.All, Directory.Read.All, Application.Read.All)

## Installation

### Manual Installation

1. Clone or download the repository:
   ```powershell
   git clone https://github.com/yourusername/CAReports.git
   ```

2. Import the module (development mode):
   ```powershell
   Import-Module ./CAReports/CAReports.psd1
   ```

## Configuration

CAReports uses a default configuration file located at `CAReports/config/default-config.psd1`. The default output path for reports is the current working directory where the script is executed from. This can be overridden by specifying custom paths in function parameters.

## Core Functions

### Authentication

Before using CAReports functions, authenticate to Microsoft Graph:

```powershell
# Interactive authentication (browser prompt)
Connect-CAGraph -TenantId "contoso.onmicrosoft.com"

# Service principal with client secret
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -ClientSecret "your-client-secret"

# Certificate-based authentication
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "certificate-thumbprint"
```

### Retrieving Policies

Fetch Conditional Access policies with various options:

```powershell
# Basic retrieval
$policies = Get-CAPolicy

# Get policies with enhanced metadata (users, groups, applications)
$enhancedPolicies = Get-CAPolicy -IncludeMetadata

# Save policies to disk (default location)
Get-CAPolicy -SaveOriginal -SaveEnhanced

# Save policies to a custom location
Get-CAPolicy -SaveOriginal -SaveEnhanced -OutputPath "./CustomPath"

# Retrieve a specific policy by ID
$specificPolicy = Get-CAPolicy -Id "00000000-0000-0000-0000-000000000000"
```

## Analysis Functions

### Policy Analysis

Analyze Conditional Access policies for patterns and statistics:

```powershell
# Analyze policies
$analysis = Get-CAPolicyAnalysis -Policies $enhancedPolicies

# View pattern summary
$analysis.PatternSummary | Format-Table

# View policy statistics
$analysis.Statistics | Format-List
```

### Naming Analysis

Analyze naming conventions used in policies:

```powershell
# Analyze naming conventions
$namingAnalysis = Get-CANamingAnalysis -Policies $policies

# View naming format recommendations
$namingAnalysis.Recommendations | Format-Table
```

### Security Gap Analysis

Identify potential security gaps in your Conditional Access implementation:

```powershell
# Analyze security gaps
$gaps = Get-CASecurityGap -Policies $policies

# View gaps by severity
$gaps | Where-Object Severity -eq "High" | Format-Table
```

## Reporting and Export Functions

### YAML Export

Convert and export policies to YAML format:

```powershell
# Convert policies to YAML in memory
$yamlPolicies = ConvertTo-CAYaml -Policies $policies

# Convert and save policies as clean YAML
$cleanPolicies = ConvertTo-CACleanYaml -Policies $policies -OutputPath "./yaml-policies"

# Generate a comprehensive YAML report
Export-CAYamlReport -Policies $enhancedPolicies -OutputPath "./reports/yaml"
```

### Excel Reports

Generate Excel reports with policy details and analysis:

```powershell
# Generate basic Excel report
Export-CAExcelReport -Policies $policies -OutputPath "./reports/excel"

# Generate detailed Excel report with analysis data
Export-CAExcelReport -Policies $enhancedPolicies -Analysis $analysis -OutputPath "./reports/excel"
```

### Diagrams

Create visual diagrams of policy configurations:

```powershell
# Generate Mermaid diagrams for all policies
Export-CADiagram -Policies $policies -OutputPath "./reports/diagrams"

# Generate diagrams for specific policies
$selectedPolicies = $policies | Where-Object { $_.displayName -like "*MFA*" }
Export-CADiagram -Policies $selectedPolicies -OutputPath "./reports/diagrams/mfa"
```

## Advanced Usage

### Processing Multiple Tenants

Process policies from multiple tenants:

```powershell
$tenants = @(
    @{ TenantId = "tenant1.onmicrosoft.com"; Name = "Tenant1" },
    @{ TenantId = "tenant2.onmicrosoft.com"; Name = "Tenant2" }
)

foreach ($tenant in $tenants) {
    # Connect to tenant
    Connect-CAGraph -TenantId $tenant.TenantId
    
    # Get policies
    $policies = Get-CAPolicy -IncludeMetadata
    
    # Export tenant-specific report
    $outputPath = "./reports/$($tenant.Name)"
    Export-CAExcelReport -Policies $policies -OutputPath $outputPath
}
```

### Customizing Output

Customize the fields included in reports:

```powershell
# Get specific properties
$customView = $policies | Select-Object displayName, state, 
    @{Name="UsersIncluded"; Expression={$_.conditions.users.includeUsers.Count}},
    @{Name="AppsIncluded"; Expression={$_.conditions.applications.includeApplications.Count}}

# Export custom view
$customView | Export-Csv -Path "./custom-report.csv" -NoTypeInformation
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Ensure your account has the required permissions
   - Check tenant ID for typos
   - Verify client ID and secret if using service principal

2. **Missing Data in Reports**
   - Use the `-IncludeMetadata` parameter to ensure all data is retrieved
   - Check for null values in policy conditions before processing

3. **Performance Issues**
   - For large tenants, consider filtering policies before analysis
   - Use `-IncludeMetadata:$false` if you don't need detailed user/group info

### Logging

Enable verbose logging for troubleshooting:

```powershell
$VerbosePreference = "Continue"
Get-CAPolicy -IncludeMetadata
```

## Examples

See the examples directory for complete sample scripts:

- `Basic-Example.ps1`: Demonstrates core functionality
- `Enhanced-Example.ps1`: Shows comprehensive usage with all features

## Support and Feedback

For support or to provide feedback, please open an issue in the GitHub repository.

---

Last Updated: 2025-04-04