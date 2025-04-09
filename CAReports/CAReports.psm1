#requires -Version 7.0

<#
.SYNOPSIS
    Main module file for CAReports
.DESCRIPTION
    This file loads all the module components and sets up the module environment.
.NOTES
    File Name      : CAReports.psm1
    Author         : Josh (uniQuk)
    Prerequisite   : PowerShell 7.x
    Copyright 2025 - North7
#>

#Region Module Variables

# Module path
$script:ModuleRoot = $PSScriptRoot

# Config path
$script:ConfigPath = Join-Path -Path $ModuleRoot -ChildPath 'config'

# Store runtime configuration (initialized during Connect-CAGraph)
$script:CAConfig = @{
    ConnectionStatus = $false
    TenantId = $null
    BaseOutputPath = $null
    RunMode = 'Interactive' # Interactive, Silent, Verbose
    Environment = 'Production' # Production, Development
}

#EndRegion Module Variables

#Region Module Initialization

# Load common helper functions first to ensure they're available to other functions
$HelperFunctions = @(
    # Priority load for these critical helper functions
    "$PSScriptRoot\Private\Helpers\Get-SafeFilename.ps1"
)

# Import the helpers first
foreach ($Helper in $HelperFunctions) {
    if (Test-Path $Helper) {
        try {
            Write-Verbose "Importing helper function: $Helper"
            . $Helper
        }
        catch {
            Write-Error -Message "Failed to import helper function $Helper`: $_"
        }
    }
    else {
        Write-Warning "Helper function file not found: $Helper"
    }
}

# Get remaining private and public function definition files - include nested directories
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Public\**\*.ps1" -Recurse -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\**\*.ps1" -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.FullName -notin $HelperFunctions })

# Debug
Write-Verbose "Loading $($Public.Count) public and $($Private.Count) private functions"

# Dot source the function files
foreach ($ImportItem in @($Private + $Public)) {
    try {
        Write-Verbose "Importing $($ImportItem.FullName)"
        . $ImportItem.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($ImportItem.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function @(
    # Core functions
    'Connect-CAGraph',
    'Get-CAPolicy',
    'Get-CAPolicyAnalysis',
    'Get-CANamingAnalysis',
    'Get-CASecurityGap',
    'Get-CAConfig',
    
    # Export functions
    'Export-CAYamlReport',
    'Export-CAExcelReport',
    'Export-CADiagram',
    'Export-CATableReport',
    
    # Format functions
    'ConvertTo-CAYaml',
    'ConvertTo-CACleanYaml',
    'New-CASecurityGapReport'
)

# Define any initialization that should happen when the module is imported
Write-Verbose "CAReports module loaded. Use Connect-CAGraph to authenticate before using other cmdlets."

# Warn about potential module dependencies without preventing module loading
$potentialDependencies = @(
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'ImportExcel',
    'powershell-yaml'
)

$missingModules = @()
foreach ($module in $potentialDependencies) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Warning "Some CAReports functionality requires modules that are not installed: $($missingModules -join ', ')"
    Write-Warning "You can continue to use functions that don't require these dependencies."
    Write-Warning "To install all dependencies, run: Install-Module <ModuleName> -Scope CurrentUser"
}

#EndRegion Module Initialization 