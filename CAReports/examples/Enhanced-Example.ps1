#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups, Microsoft.Graph.Users, ImportExcel

<#
.SYNOPSIS
    Enhanced example script for the CAReports PowerShell module.

.DESCRIPTION
    This script demonstrates comprehensive usage of the CAReports module.
    It connects to Microsoft Graph, retrieves and enhances Conditional Access policies,
    performs detailed analysis, and generates various report formats.

.NOTES
    File Name      : Enhanced-Example.ps1
    Prerequisite   : PowerShell 7+, CAReports module and its dependencies
#>

# Get the script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleDir = Split-Path -Parent $scriptDir

# Import the CAReports module with full path
try {
    Import-Module -Name $moduleDir -Force -ErrorAction Stop
    Write-Host "Successfully imported CAReports module from $moduleDir" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import the CAReports module: $_"
    Write-Host "Module Path: $moduleDir" -ForegroundColor Red
    Write-Host "Current Directory: $(Get-Location)" -ForegroundColor Red
    Write-Host "PSModulePath: $($env:PSModulePath)" -ForegroundColor Red
    exit
}

# Display the script purpose
Write-Host "CAReports Enhanced Example" -ForegroundColor Cyan
Write-Host "This script demonstrates comprehensive functionality of the CAReports module." -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------------" -ForegroundColor Cyan

# Initialize variables to track step completion
$policiesRetrieved = $false
$analysisCompleted = $false
$namingAnalysisCompleted = $false
$yamlReportGenerated = $false
$frameworkReportGenerated = $false

try {
    # Step 1: Connect to Microsoft Graph
    Write-Host "`nStep 1: Connecting to Microsoft Graph..." -ForegroundColor Green
    Connect-CAGraph -TenantId "3d2d7ada-f01f-4ef0-93d0-68d667114493"
    
    # Step 2: Fetch Conditional Access policies with enhanced metadata
    Write-Host "`nStep 2: Fetching Conditional Access policies with enhanced metadata..." -ForegroundColor Green
    $enhancedPolicies = Get-CAPolicy -IncludeMetadata -SaveOriginal -SaveEnhanced -ErrorAction Stop
    
    if ($null -eq $enhancedPolicies -or $enhancedPolicies.Count -eq 0) {
        Write-Warning "No policies were retrieved or the tenant may not have any Conditional Access policies."
    } else {
        Write-Host "Retrieved $($enhancedPolicies.Count) policies with enhanced metadata." -ForegroundColor Yellow
        $policiesRetrieved = $true
    }
    
    # Only proceed with analysis if policies were retrieved
    if ($policiesRetrieved) {
        # Step 3: Analyze policies for patterns and statistics
        Write-Host "`nStep 3: Analyzing policies for patterns and statistics..." -ForegroundColor Green
        try {
            $analysis = Get-CAPolicyAnalysis -Policies $enhancedPolicies -ErrorAction Stop
            
            # Display analysis results summary
            Write-Host "Analysis complete. Found the following policy patterns:" -ForegroundColor Yellow
            if ($null -ne $analysis.PatternSummary) {
                $analysis.PatternSummary | Format-Table -AutoSize
                $analysisCompleted = $true
            } else {
                Write-Warning "Policy analysis completed but no pattern summary was generated."
            }
        }
        catch {
            Write-Warning "Error during policy analysis: $($_.Exception.Message)"
        }
        
        # Step 4: Analyze naming conventions
        Write-Host "`nStep 4: Analyzing policy naming conventions..." -ForegroundColor Green
        try {
            $namingAnalysis = Get-CANamingAnalysis -Policies $enhancedPolicies -ErrorAction Stop
            
            # Display naming analysis summary
            Write-Host "Naming analysis complete. Results:" -ForegroundColor Yellow
            if ($null -ne $namingAnalysis.Summary) {
                $namingAnalysis.Summary | Format-Table -AutoSize
                $namingAnalysisCompleted = $true
            } else {
                Write-Warning "Naming analysis completed but no summary was generated."
            }
        }
        catch {
            Write-Warning "Error during naming analysis: $($_.Exception.Message)"
        }
        
        # Step 5: Identify security gaps
        Write-Host "`nStep 5: Identifying security gaps..." -ForegroundColor Green
        try {
            $gaps = Get-CASecurityGap -Policies $enhancedPolicies -ErrorAction Stop
            
            # Display security gaps summary
            Write-Host "Security gap analysis complete." -ForegroundColor Yellow
            if ($null -ne $gaps -and $null -ne $gaps.SecurityGaps) {
                $gapCount = ($gaps.SecurityGaps | Measure-Object).Count
                Write-Host "Found $gapCount potential security gaps:" -ForegroundColor Yellow
                
                # Convert the hashtable to a more displayable format
                $gapsTable = $gaps.SecurityGaps.GetEnumerator() | ForEach-Object {
                    [PSCustomObject]@{
                        Category = $_.Key
                        Description = $_.Value.Issue
                        Severity = $_.Value.Severity
                    }
                }
                
                if ($gapsTable) {
                    $gapsTable | Format-Table -AutoSize
                }
            } else {
                Write-Host "No security gaps were identified or the analysis didn't return expected results." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "Error during security gap analysis: $($_.Exception.Message)"
            Write-Verbose $_.ScriptStackTrace
        }
        
        # Step 6: Generate framework-based security gap report
        Write-Host "`nStep 6: Generating comprehensive security gap report with framework analysis..." -ForegroundColor Green
        try {
            $frameworkReport = New-CASecurityGapReport -Policies $enhancedPolicies -Frameworks "All" -IncludeFrameworkSummary -ErrorAction Stop
            
            # Display report generation status
            if ($frameworkReport) {
                Write-Host "Framework-based security gap report generated at: $frameworkReport" -ForegroundColor Yellow
                Write-Host "This report includes analysis based on Microsoft, NIST, PCI DSS, and MITRE ATT&CK frameworks." -ForegroundColor Yellow
                $frameworkReportGenerated = $true
            } else {
                Write-Host "Security framework report was not generated properly." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "Error generating framework security report: $($_.Exception.Message)"
            Write-Verbose $_.ScriptStackTrace
        }
        
        # Step 7: Generate YAML report
        Write-Host "`nStep 7: Generating YAML report..." -ForegroundColor Green
        try {
            $yamlPathResult = Export-CAYamlReport -Policies $enhancedPolicies -ErrorAction Stop
            
            # Handle different return types
            $yamlPath = if ($yamlPathResult -is [string]) { 
                $yamlPathResult 
            } 
            elseif ($yamlPathResult.PSObject.Properties.Name -contains "ReportPath") { 
                $yamlPathResult.ReportPath 
            }
            else {
                "analysis/markdown/ca-summary.md"  # Default path
            }
            
            Write-Host "YAML report generated at: $yamlPath" -ForegroundColor Yellow
            $yamlReportGenerated = $true
        }
        catch {
            Write-Warning "Error generating YAML report: $($_.Exception.Message)"
        }
        
        # Step 8: Generate Excel report
        Write-Host "`nStep 8: Generating Excel report..." -ForegroundColor Green
        try {
            # Only include analysis if it was successfully completed
            $excelParams = @{
                Policies = $enhancedPolicies
                ErrorAction = 'Stop'
            }
            
            if ($analysisCompleted) {
                $excelParams.Analysis = $analysis
            }
            
            $excelPath = Export-CAExcelReport @excelParams
            Write-Host "Excel report generated at: $excelPath" -ForegroundColor Yellow
        }
        catch {
            Write-Warning "Error generating Excel report: $($_.Exception.Message)"
        }
        
        # Step 9: Generate policy diagrams
        Write-Host "`nStep 9: Generating policy diagrams..." -ForegroundColor Green
        
        # Check if the Export-CADiagram function exists before trying to use it
        if (Get-Command -Name Export-CADiagram -ErrorAction SilentlyContinue) {
            try {
                $diagramsPath = Export-CADiagram -Policies $enhancedPolicies -ErrorAction Stop
                Write-Host "Policy diagrams generated at: $diagramsPath" -ForegroundColor Yellow
            }
            catch {
                Write-Warning "Error generating policy diagrams: $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning "Export-CADiagram function is not available. Diagrams will not be generated."
        }
        
        # Step 10: Converting policies to clean YAML...
        Write-Host "`nStep 10: Converting policies to clean YAML..." -ForegroundColor Green
        try {
            if ($null -eq $enhancedPolicies -or $enhancedPolicies.Count -eq 0) {
                Write-Warning "Cannot convert policies to clean YAML: No policies available."
            } else {
                # Get current config info for reference
                $config = Get-CAConfig
                Write-Host "Clean YAML will use output base path: $($config.OutputPaths.Base)"
                Write-Host "Clean YAML will use clean directory: $($config.OutputPaths.Clean)"
                Write-Host "Full clean YAML path: $(Join-Path -Path $config.OutputPaths.Base -ChildPath $config.OutputPaths.Clean)"
                
                $cleanPolicies = ConvertTo-CACleanYaml -Policies $enhancedPolicies -ErrorAction Stop
                
                if ($cleanPolicies -and $cleanPolicies.TotalCleaned -gt 0) {
                    Write-Host "Successfully converted $($cleanPolicies.TotalCleaned) policies to clean YAML format." -ForegroundColor Yellow
                    Write-Host "Clean YAML files available at: $(Join-Path -Path $config.OutputPaths.Base -ChildPath $config.OutputPaths.Clean)" -ForegroundColor Yellow
                } else {
                    Write-Warning "No policies were converted to clean YAML format."
                }
            }
        }
        catch {
            Write-Warning "Error converting policies to clean YAML: $($_.Exception.Message)"
            Write-Verbose "Error details: $($_.ScriptStackTrace)"
        }
        
        # Success message
        Write-Host "`nScript completed with some steps successful." -ForegroundColor Green
        
        # Show location of generated files if YAML report was created
        if ($yamlReportGenerated) {
            # Get the configuration to determine the base output path
            $config = Get-CAConfig
            $outputBasePath = $config.OutputPaths.Base
            
            Write-Host "`nGenerated files can be found in: $outputBasePath" -ForegroundColor Cyan
            Write-Host "The following outputs were created:" -ForegroundColor Cyan
            
            Write-Host "- Original policies: $(Join-Path -Path $outputBasePath -ChildPath $config.OutputPaths.Original)" -ForegroundColor White
            Write-Host "- Enhanced policies: $(Join-Path -Path $outputBasePath -ChildPath $config.OutputPaths.Data)" -ForegroundColor White
            Write-Host "- YAML report: $yamlPath" -ForegroundColor White
            
            if ($excelPath) {
                Write-Host "- Excel report: $excelPath" -ForegroundColor White
            }
            
            if ($diagramsPath) {
                Write-Host "- Policy diagrams: $diagramsPath" -ForegroundColor White
            }
            
            if ($frameworkReportGenerated -and $frameworkReport) {
                Write-Host "- Framework security report: $frameworkReport" -ForegroundColor White
            }
        }
    }
}
catch {
    # Error handling
    Write-Host "`nA critical error occurred during script execution:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
finally {
    # Always display completion message
    Write-Host "`nScript execution finished." -ForegroundColor Cyan
} 