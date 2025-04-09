@{
    # Script module or binary module file associated with this manifest
    RootModule = 'CAReports.psm1'
    
    # Version number of this module.
    ModuleVersion = '0.1.0'
    
    # ID used to uniquely identify this module
    GUID = '8e4f9b5a-f7e1-4d35-a2e1-c9b7b6e2f8d0'
    
    # Author of this module
    Author = 'Josh (uniQuk)'
    
    # Company or vendor of this module
    CompanyName = 'North7'
    
    # Copyright statement for this module
    Copyright = '(c) 2025 Josh (uniQuk)'
    
    # Description of the functionality provided by this module
    Description = 'PowerShell module for analyzing and reporting on Microsoft Entra ID Conditional Access policies'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0'
    
    # Modules that might be needed depending on which functions are used
    # RequiredModules = @(
    #     @{ModuleName='Microsoft.Graph.Identity.SignIns'; ModuleVersion='2.0.0'},
    #     @{ModuleName='Microsoft.Graph.Groups'; ModuleVersion='2.0.0'},
    #     @{ModuleName='Microsoft.Graph.Users'; ModuleVersion='2.0.0'},
    #     @{ModuleName='Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion='2.0.0'},
    #     @{ModuleName='ImportExcel'; ModuleVersion='7.0.0'},
    #     @{ModuleName='powershell-yaml'; ModuleVersion='0.4.0'}
    # )
    
    # Functions to export from this module, for best performance, do not use wildcards
    FunctionsToExport = @(
        # Connect
        'Connect-CAGraph',
        
        # Fetch
        'Get-CAPolicy',
        
        # Export
        'Export-CADiagram',
        'Export-CAExcelReport', 
        'Export-CAYamlReport',
        
        # Analyze
        'Get-CAPolicyAnalysis',
        'Get-CANamingAnalysis',
        'Get-CASecurityGap',
        
        # Format
        'ConvertTo-CAYaml',
        'ConvertTo-CACleanYaml',
        'New-CASecurityGapReport',
        
        # Utility
        'Get-CAConfig'
    )
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Conditional-Access', 'Microsoft-Graph', 'Security', 'Reporting')
            
            # A URL to the license for this module
            LicenseUri = ''
            
            # A URL to the main website for this project
            ProjectUri = ''
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
Initial release of the CAReports module

Changes:
- Added standardized parameter names for Get-SafeFilename function
- Fixed module loading order to ensure helper functions load first
- Improved error handling in the Get-CAPolicy function
'@
        }
    }
} 