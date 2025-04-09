# CAReports PowerShell Module

## Overview
CAReports is a PowerShell module designed to help analyze, document, and report on Microsoft Entra ID Conditional Access policies. It provides a comprehensive set of tools for retrieving, enhancing, analyzing, and visualizing CA policies.

## Key Features
- Fetch Conditional Access policies with enhanced metadata
- Generate visual diagrams of policy configurations
- Analyze policies for patterns and security gaps
- Create detailed reports in Excel, YAML, and Markdown formats
- Support for different naming conventions

## Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/CAReports.git

# Import the module (development mode)
Import-Module .\CAReports\CAReports.psd1
```

## Requirements
- PowerShell 7.x or higher
- The following PowerShell modules:
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Groups
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.DirectoryManagement
  - ImportExcel
  - powershell-yaml

## Usage Examples

### Connecting to Microsoft Graph
```powershell
# Interactive authentication
Connect-CAGraph -TenantId "contoso.onmicrosoft.com"

# Client credential flow
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -ClientSecret "mySecret"

# Certificate-based authentication
Connect-CAGraph -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
```

### Fetching Policies
```powershell
# Get all policies
$policies = Get-CAPolicy

# Get policies with enhanced metadata
$enhancedPolicies = Get-CAPolicy -IncludeMetadata

# Get policies and save to disk (saves to current working directory by default)
Get-CAPolicy -IncludeMetadata -SaveOriginal -SaveEnhanced

# Get policies and save to a specific location
Get-CAPolicy -IncludeMetadata -SaveOriginal -SaveEnhanced -OutputPath "./CAReports"

# Get a specific policy by ID
$policy = Get-CAPolicy -Id "00000000-0000-0000-0000-000000000000"
```

### Analyzing Policies
```powershell
# Analyze policies for patterns and statistics
$analysis = Get-CAPolicyAnalysis -Policies $enhancedPolicies

# Analyze policies for naming conventions
$namingAnalysis = Get-CANamingAnalysis -Policies $enhancedPolicies

# Identify security gaps
$gaps = Get-CASecurityGap -Policies $enhancedPolicies
```

### Generating Reports
```powershell
# Generate a YAML report
Export-CAYamlReport -Policies $enhancedPolicies -OutputPath "./CAReports/yaml"

# Generate Excel report
Export-CAExcelReport -Policies $enhancedPolicies -OutputPath "./CAReports/excel"

# Generate policy diagrams
Export-CADiagram -Policies $enhancedPolicies -OutputPath "./CAReports/diagrams"
```

## Module Structure
The module is organized into the following components:

- **Public**: Exported cmdlets and functions
  - **Connect**: Authentication functions
  - **Fetch**: Data retrieval functions
  - **Analyze**: Analysis functions
  - **Export**: Report generation functions
  - **Format**: Data formatting functions

- **Private**: Internal helper functions
  - **Helpers**: Common utility functions
  - **Graph**: Graph API utilities
  - **Data**: Data processing utilities

## Documentation
For detailed documentation, see the [docs](./docs) folder. 