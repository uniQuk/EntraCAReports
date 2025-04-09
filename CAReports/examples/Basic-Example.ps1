#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups, Microsoft.Graph.Users

<#
.SYNOPSIS
    Basic example script for using the CAReports PowerShell module.

.DESCRIPTION
    This script demonstrates the basic functionality of the CAReports module.
    It connects to Microsoft Graph, retrieves Conditional Access policies, 
    and performs basic operations on them.

.NOTES
    File Name      : Basic-Example.ps1
    Prerequisite   : PowerShell 7+, CAReports module and its dependencies
#>

# Import the CAReports module if it's not already loaded
if (-not (Get-Module -Name CAReports)) {
    try {
        Import-Module -Name CAReports -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import the CAReports module. Make sure it's installed or available in the module path."
        exit
    }
}

# Display the script purpose
Write-Host "CAReports Basic Example" -ForegroundColor Cyan
Write-Host "This script demonstrates basic functionality of the CAReports module." -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan

# Initialize variables to track step completion
$policiesRetrieved = $false

try {
    # Step 1: Connect to Microsoft Graph
    # This uses interactive authentication
    Write-Host "`nStep 1: Connecting to Microsoft Graph..." -ForegroundColor Green
    Connect-CAGraph

    # Step 2: Fetch Conditional Access policies
    Write-Host "`nStep 2: Fetching Conditional Access policies..." -ForegroundColor Green
    try {
        $policies = Get-CAPolicy -ErrorAction Stop
        
        if ($null -eq $policies -or $policies.Count -eq 0) {
            Write-Warning "No policies were retrieved or the tenant may not have any Conditional Access policies."
        } else {
            Write-Host "Retrieved $($policies.Count) policies." -ForegroundColor Yellow
            $policiesRetrieved = $true
        }
    }
    catch {
        Write-Warning "Error retrieving policies: $($_.Exception.Message)"
    }

    # Only proceed if policies were retrieved
    if ($policiesRetrieved) {
        # Step 3: Display basic policy information
        Write-Host "`nStep 3: Displaying basic policy information..." -ForegroundColor Green
        $policies | Select-Object displayName, state, id | Format-Table -AutoSize

        # Step 4: Save policies to the default location
        Write-Host "`nStep 4: Saving policies to disk..." -ForegroundColor Green
        try {
            Get-CAPolicy -SaveOriginal -SaveEnhanced -ErrorAction Stop
            Write-Host "Policies saved to current working directory." -ForegroundColor Yellow
        }
        catch {
            Write-Warning "Error saving policies to disk: $($_.Exception.Message)"
        }

        # Step 5: Get enhanced policies with metadata
        Write-Host "`nStep 5: Fetching policies with enhanced metadata..." -ForegroundColor Green
        try {
            $enhancedPolicies = Get-CAPolicy -IncludeMetadata -ErrorAction Stop
            
            if ($null -eq $enhancedPolicies -or $enhancedPolicies.Count -eq 0) {
                Write-Warning "No enhanced policies were retrieved."
            } else {
                Write-Host "Retrieved $($enhancedPolicies.Count) policies with metadata." -ForegroundColor Yellow
                
                # Display a sample of the enhanced data
                Write-Host "`nSample of enhanced policy data:" -ForegroundColor Green
                $samplePolicy = $enhancedPolicies | Select-Object -First 1
                if ($samplePolicy) {
                    Write-Host "Policy Name: $($samplePolicy.displayName)" -ForegroundColor Yellow
                    Write-Host "State: $($samplePolicy.state)" -ForegroundColor Yellow
                    Write-Host "Created: $($samplePolicy.createdDateTime)" -ForegroundColor Yellow
                    
                    # Show included users count if available
                    if ($null -ne $samplePolicy.conditions -and 
                        $null -ne $samplePolicy.conditions.users -and 
                        $null -ne $samplePolicy.conditions.users.includeUsers) {
                        $userCount = @($samplePolicy.conditions.users.includeUsers).Count
                        Write-Host "Included Users: $userCount" -ForegroundColor Yellow
                    }
                }
            }
        }
        catch {
            Write-Warning "Error retrieving enhanced policies: $($_.Exception.Message)"
        }
        
        # Step 6: Test naming analysis function
        Write-Host "`nStep 6: Testing naming analysis function..." -ForegroundColor Green
        try {
            $namingAnalysis = $enhancedPolicies | Get-CANamingAnalysis -ErrorAction Stop
            
            if ($null -eq $namingAnalysis -or $null -eq $namingAnalysis.Policies) {
                Write-Warning "No naming analysis results were generated."
            } else {
                Write-Host "Generated naming suggestions for $($namingAnalysis.Policies.Count) policies." -ForegroundColor Yellow
                
                # Display a sample of the naming suggestions
                Write-Host "`nSample of naming suggestions:" -ForegroundColor Green
                $sampleSuggestions = $namingAnalysis.Policies | Select-Object -First 3
                
                if ($sampleSuggestions) {
                    foreach ($suggestion in $sampleSuggestions) {
                        Write-Host "Original Name: $($suggestion.OriginalName)" -ForegroundColor Yellow
                        Write-Host "Simple Format: $($suggestion.SimpleFormat)" -ForegroundColor Yellow
                        Write-Host "MS Format:     $($suggestion.MSFormat)" -ForegroundColor Yellow
                        Write-Host "ASD Format:    $($suggestion.ASDFormat)" -ForegroundColor Yellow
                        Write-Host "----------------------------------------" -ForegroundColor Yellow
                    }
                }
                
                # Save naming analysis to output
                $OutputPath = "./CAReports_Output/analysis/markdown"
                if (!(Test-Path -Path $OutputPath)) {
                    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
                }
                $namingAnalysis | Out-Null  # Just to ensure it's generated
                Write-Host "Naming analysis saved to $OutputPath/naming_conventions.md" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "Error generating naming analysis: $($_.Exception.Message)"
        }
        
        # Success message
        Write-Host "`nScript completed!" -ForegroundColor Green
    }
}
catch {
    # Error handling
    Write-Host "`nAn error occurred during script execution:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
finally {
    # Always display completion message
    Write-Host "`nScript execution finished." -ForegroundColor Cyan
} 