function Get-CASecurityGap {
    <#
    .SYNOPSIS
        Identifies security gaps in Conditional Access policies and provides recommendations.
    
    .DESCRIPTION
        This function analyzes Conditional Access policies to identify potential security gaps,
        missing protections, and configuration issues that could lead to compromised security.
        It provides actionable recommendations to address these gaps.
    
    .PARAMETER Policies
        The Conditional Access policies to analyze. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy JSON files.
        
    .PARAMETER OutputPath
        The path where the security gap report will be saved. Defaults to "analysis/markdown".
    
    .PARAMETER OutputFormat
        The format of the security gap report. Can be "Markdown", "JSON", or "Table". 
        Defaults to "Markdown".
    
    .PARAMETER IncludeLowSeverity
        Switch to include low severity issues in the report. By default, only medium and high
        severity issues are included.
    
    .EXAMPLE
        Get-CAPolicy | Get-CASecurityGap -OutputPath "./reports"
    
    .EXAMPLE
        Get-CASecurityGap -Path "./policies/data" -OutputFormat "JSON" -IncludeLowSeverity
    
    .NOTES
        This is part of the CAReports PowerShell module for analyzing Conditional Access policies.
    #>
    
    [CmdletBinding(DefaultParameterSetName="FromPolicies")]
    param (
        [Parameter(Mandatory=$true, ParameterSetName="FromPolicies", ValueFromPipeline=$true)]
        [PSCustomObject[]]$Policies,
        
        [Parameter(Mandatory=$true, ParameterSetName="FromPath")]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Markdown", "JSON", "Table")]
        [string]$OutputFormat = "Markdown",
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeLowSeverity
    )
    
    begin {
        # Get the proper output path if not specified
        if ([string]::IsNullOrEmpty($OutputPath)) {
            # Get configuration to determine proper paths
            $config = Get-CAConfig
            $basePath = $config.OutputPaths.Base
            $markdownPath = $config.OutputPaths.Markdown
            $OutputPath = Join-Path -Path $basePath -ChildPath $markdownPath
            Write-Verbose "Using configured output path: $OutputPath"
        }
        
        # Initialize collections if using pipeline input
        if ($PSCmdlet.ParameterSetName -eq "FromPolicies") {
            $allPolicies = @()
        }
        
        # Create output directory if it doesn't exist
        if (![string]::IsNullOrEmpty($OutputPath)) {
            $created = New-Item -ItemType Directory -Force -Path $OutputPath
            Write-Verbose "Created/confirmed output directory: $OutputPath"
        }
        
        # Define best practices and recommendations
        $bestPractices = @{
            # High Severity
            AdminMFA = @{
                Name = "Administrator MFA Requirement"
                Description = "Ensure all administrator roles require MFA"
                Severity = "High"
                Recommendation = "Create a Conditional Access policy that requires MFA for all users with administrative roles"
            }
            AllUsersMFA = @{
                Name = "User MFA Requirement"
                Description = "Ensure all users have at least one policy requiring MFA"
                Severity = "High"
                Recommendation = "Create a baseline Conditional Access policy that requires MFA for all users"
            }
            GuestMFA = @{
                Name = "Guest MFA Requirement"
                Description = "Ensure guest/external users require MFA"
                Severity = "High"
                Recommendation = "Create a policy specifically targeting guests and external users to require MFA"
            }
            LegacyAuth = @{
                Name = "Legacy Authentication Blocking"
                Description = "Block legacy authentication protocols"
                Severity = "High"
                Recommendation = "Create a policy to block legacy authentication for all applications"
            }
            
            # Medium Severity
            AdminExclusions = @{
                Name = "Administrator Exclusions"
                Description = "Minimize administrator exclusions from security policies"
                Severity = "Medium"
                Recommendation = "Review and minimize admin exclusions; use break-glass accounts instead of excluding regular admin accounts"
            }
            BroadExclusions = @{
                Name = "Broad User Exclusions"
                Description = "Avoid broad user exclusions from security policies"
                Severity = "Medium"
                Recommendation = "Review policies with many excluded users and consider alternative approaches"
            }
            RiskBasedPolicies = @{
                Name = "Risk-Based Policies"
                Description = "Implement risk-based Conditional Access policies"
                Severity = "Medium"
                Recommendation = "Create policies that respond to sign-in and user risk levels"
            }
            DeviceCompliance = @{
                Name = "Device Compliance Requirements"
                Description = "Require compliant devices for sensitive data access"
                Severity = "Medium"
                Recommendation = "Implement device compliance requirements for applications with sensitive data"
            }
            
            # Low Severity
            ReportOnlyMode = @{
                Name = "Report-Only Policies"
                Description = "Minimize long-term use of report-only mode"
                Severity = "Low"
                Recommendation = "Review report-only policies and consider enabling them after testing"
            }
            TestPolicies = @{
                Name = "Test/Development Policies"
                Description = "Clearly label and review test policies"
                Severity = "Low"
                Recommendation = "Review and clean up test or development policies"
            }
            NamingConsistency = @{
                Name = "Naming Consistency"
                Description = "Use consistent naming conventions for policies"
                Severity = "Low"
                Recommendation = "Implement a standardized naming convention for Conditional Access policies"
            }
        }
    }
    
    process {
        # Add policies from pipeline to collection
        if ($PSCmdlet.ParameterSetName -eq "FromPolicies" -and $Policies) {
            $allPolicies += $Policies
        }
    }
    
    end {
        # Load policies from path if specified
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            $allPolicies = try {
                Get-ChildItem -Path $Path -Filter "*.json" -ErrorAction Stop | 
                ForEach-Object { 
                    try {
                        $content = Get-Content $_.FullName -Raw
                        $policy = $content | ConvertFrom-Json
                        if (!$policy.conditions -or !$policy.displayName) {
                            Write-Warning "Invalid policy format in file: $($_.Name)"
                            return
                        }
                        $policy
                    }
                    catch {
                        Write-Warning "Failed to parse policy file: $($_.Name)"
                        Write-Warning $_.Exception.Message
                        return
                    }
                }
            }
            catch {
                Write-Error "Failed to read policy files: $_"
                return
            }
        }
        
        # Initialize issues collection
        $securityGaps = @{}
        
        # Check for MFA requirements for admins
        $adminMfaPolicies = @($allPolicies | Where-Object {
            $policy = $_
            # Check if includeRoles exists and has properties
            $hasAdminRoles = ($null -ne $policy) -and
                             ($null -ne $policy.conditions) -and
                             ($null -ne $policy.conditions.users) -and
                             ($null -ne $policy.conditions.users.includeRoles) -and 
                             ($policy.conditions.users.includeRoles.PSObject.Properties.Count -gt 0)
            
            # Check if grantControls and builtInControls exist before testing
            $requiresMfa = ($null -ne $policy) -and
                           ($null -ne $policy.grantControls) -and 
                           ($null -ne $policy.grantControls.builtInControls) -and
                           ($policy.grantControls.builtInControls -contains "mfa")
            
            # Check if state exists before testing
            $isEnabled = ($null -ne $policy) -and
                         ($null -ne $policy.state) -and 
                         ($policy.state -eq "enabled")
            
            $hasAdminRoles -and $requiresMfa -and $isEnabled
        })
        
        if ($adminMfaPolicies.Count -eq 0) {
            $securityGaps["AdminMFA"] = @{
                Issue = $bestPractices.AdminMFA.Description
                Severity = $bestPractices.AdminMFA.Severity
                Recommendation = $bestPractices.AdminMFA.Recommendation
                AffectedPolicies = @()
            }
        }
        
        # Check for MFA requirements for all users
        $allUserMfaPolicies = @($allPolicies | Where-Object { 
            $policy = $_
            # Check if the conditions and users exist before checking includeUsers
            $appliesToAllUsers = ($null -ne $policy) -and
                                 ($null -ne $policy.conditions) -and 
                                 ($null -ne $policy.conditions.users) -and
                                 ($null -ne $policy.conditions.users.includeUsers) -and
                                 ($policy.conditions.users.includeUsers -contains "All")
            
            # Check if grantControls and builtInControls exist before testing
            $requiresMfa = ($null -ne $policy) -and
                           ($null -ne $policy.grantControls) -and 
                           ($null -ne $policy.grantControls.builtInControls) -and
                           ($policy.grantControls.builtInControls -contains "mfa")
            
            # Check if state exists before testing
            $isEnabled = ($null -ne $policy) -and
                         ($null -ne $policy.state) -and 
                         ($policy.state -eq "enabled")
            
            $appliesToAllUsers -and $requiresMfa -and $isEnabled
        })
        
        if ($allUserMfaPolicies.Count -eq 0) {
            $securityGaps["AllUsersMFA"] = @{
                Issue = $bestPractices.AllUsersMFA.Description
                Severity = $bestPractices.AllUsersMFA.Severity
                Recommendation = $bestPractices.AllUsersMFA.Recommendation
                AffectedPolicies = @()
            }
        }
        
        # Check for MFA requirements for guests
        $guestMfaPolicies = @($allPolicies | Where-Object { 
            $policy = $_
            # Check if guests are targeted with comprehensive null checks
            $targetsGuests = ($null -ne $policy) -and
                             ($null -ne $policy.conditions) -and 
                             ($null -ne $policy.conditions.users) -and
                             ($null -ne $policy.conditions.users.includeGuestsOrExternalUsers)
            
            # Check if MFA is required with comprehensive null checks
            $requiresMfa = ($null -ne $policy) -and
                           ($null -ne $policy.grantControls) -and 
                           ($null -ne $policy.grantControls.builtInControls) -and
                           ($policy.grantControls.builtInControls -contains "mfa")
            
            # Check if policy is enabled with comprehensive null checks
            $isEnabled = ($null -ne $policy) -and
                         ($null -ne $policy.state) -and 
                         ($policy.state -eq "enabled")
            
            $targetsGuests -and $requiresMfa -and $isEnabled
        })
        
        if ($guestMfaPolicies.Count -eq 0) {
            $securityGaps["GuestMFA"] = @{
                Issue = $bestPractices.GuestMFA.Description
                Severity = $bestPractices.GuestMFA.Severity
                Recommendation = $bestPractices.GuestMFA.Recommendation
                AffectedPolicies = @()
            }
        }
        
        # Check for legacy authentication blocking
        $legacyAuthPolicies = @($allPolicies | Where-Object { 
            $policy = $_
            # Check if legacy auth is targeted with comprehensive null checks
            $targetsLegacyAuth = ($null -ne $policy) -and
                                 ($null -ne $policy.conditions) -and 
                                 ($null -ne $policy.conditions.clientAppTypes) -and
                                 ($policy.conditions.clientAppTypes -contains "other")
            
            # Check if access is blocked with comprehensive null checks
            $blocksAccess = ($null -ne $policy) -and
                            ($null -ne $policy.grantControls) -and 
                            ($null -ne $policy.grantControls.builtInControls) -and
                            ($policy.grantControls.builtInControls -contains "block")
            
            # Check if policy is enabled with comprehensive null checks
            $isEnabled = ($null -ne $policy) -and
                         ($null -ne $policy.state) -and 
                         ($policy.state -eq "enabled")
            
            $targetsLegacyAuth -and $blocksAccess -and $isEnabled
        })
        
        if ($legacyAuthPolicies.Count -eq 0) {
            $securityGaps["LegacyAuth"] = @{
                Issue = $bestPractices.LegacyAuth.Description
                Severity = $bestPractices.LegacyAuth.Severity
                Recommendation = $bestPractices.LegacyAuth.Recommendation
                AffectedPolicies = @()
            }
        }
        
        # Check for admin exclusions
        $policiesWithAdminExclusions = @($allPolicies | Where-Object {
            $policy = $_
            $hasAdminExclusions = if ($null -ne $policy.conditions -and 
                                     $null -ne $policy.conditions.users -and 
                                     $null -ne $policy.conditions.users.excludeRoles) {
                $policy.conditions.users.excludeRoles.PSObject.Properties.Count -gt 0
            } else { $false }
            
            $hasAdminExclusions
        })
        
        if ($policiesWithAdminExclusions.Count -gt 0) {
            $securityGaps["AdminExclusions"] = @{
                Issue = $bestPractices.AdminExclusions.Description
                Severity = $bestPractices.AdminExclusions.Severity
                Recommendation = $bestPractices.AdminExclusions.Recommendation
                AffectedPolicies = $policiesWithAdminExclusions | ForEach-Object { $_.displayName }
            }
        }
        
        # Check for broad user exclusions
        $policiesWithBroadExclusions = @($allPolicies | Where-Object {
            $policy = $_
            $exclusionCount = if ($null -ne $policy.conditions -and 
                                 $null -ne $policy.conditions.users -and 
                                 $null -ne $policy.conditions.users.excludeUsers) {
                @($policy.conditions.users.excludeUsers.PSObject.Properties).Count
            } else { 0 }
            
            $exclusionCount -gt 5  # Threshold for "broad" exclusions
        })
        
        if ($policiesWithBroadExclusions.Count -gt 0) {
            $securityGaps["BroadExclusions"] = @{
                Issue = $bestPractices.BroadExclusions.Description
                Severity = $bestPractices.BroadExclusions.Severity
                Recommendation = $bestPractices.BroadExclusions.Recommendation
                AffectedPolicies = $policiesWithBroadExclusions | ForEach-Object { $_.displayName }
            }
        }
        
        # Check for risk-based policies
        $riskBasedPolicies = @($allPolicies | Where-Object {
            $policy = $_
            $hasRiskConditions = if ($null -ne $policy.conditions) {
                ($null -ne $policy.conditions.userRiskLevels -and $policy.conditions.userRiskLevels.Count -gt 0) -or 
                ($null -ne $policy.conditions.signInRiskLevels -and $policy.conditions.signInRiskLevels.Count -gt 0)
            } else { $false }
            
            $hasRiskConditions
        })
        
        if ($riskBasedPolicies.Count -eq 0) {
            $securityGaps["RiskBasedPolicies"] = @{
                Issue = $bestPractices.RiskBasedPolicies.Description
                Severity = $bestPractices.RiskBasedPolicies.Severity
                Recommendation = $bestPractices.RiskBasedPolicies.Recommendation
                AffectedPolicies = @()
            }
        }
        
        # Check for device compliance requirements
        $deviceCompliancePolicies = @($allPolicies | Where-Object {
            $policy = $_
            
            # Check if grantControls and builtInControls exist before testing with comprehensive null checks
            $requiresCompliantDevice = ($null -ne $policy) -and
                                      ($null -ne $policy.grantControls) -and 
                                      ($null -ne $policy.grantControls.builtInControls) -and
                                      ($policy.grantControls.builtInControls -contains "compliantDevice")
            
            # Check if state exists before testing with comprehensive null checks
            $isEnabled = ($null -ne $policy) -and
                         ($null -ne $policy.state) -and 
                         ($policy.state -eq "enabled")
            
            $requiresCompliantDevice -and $isEnabled
        })
        
        if ($deviceCompliancePolicies.Count -eq 0) {
            $securityGaps["DeviceCompliance"] = @{
                Issue = $bestPractices.DeviceCompliance.Description
                Severity = $bestPractices.DeviceCompliance.Severity
                Recommendation = $bestPractices.DeviceCompliance.Recommendation
                AffectedPolicies = @()
            }
        }
        
        # Check for report-only policies (low severity)
        $reportOnlyPolicies = @($allPolicies | Where-Object {
            $policy = $_
            $policy.state -eq "enabledForReportingButNotEnforced"
        })
        
        if ($reportOnlyPolicies.Count -gt 0 -and $IncludeLowSeverity) {
            $securityGaps["ReportOnlyMode"] = @{
                Issue = $bestPractices.ReportOnlyMode.Description
                Severity = $bestPractices.ReportOnlyMode.Severity
                Recommendation = $bestPractices.ReportOnlyMode.Recommendation
                AffectedPolicies = $reportOnlyPolicies | ForEach-Object { $_.displayName }
            }
        }
        
        # Check for test/development policies (low severity)
        $testPolicies = @($allPolicies | Where-Object {
            $policy = $_
            $policy.displayName -match "TEST|DEV"
        })
        
        if ($testPolicies.Count -gt 0 -and $IncludeLowSeverity) {
            $securityGaps["TestPolicies"] = @{
                Issue = $bestPractices.TestPolicies.Description
                Severity = $bestPractices.TestPolicies.Severity
                Recommendation = $bestPractices.TestPolicies.Recommendation
                AffectedPolicies = $testPolicies | ForEach-Object { $_.displayName }
            }
        }
        
        # Check for naming consistency (low severity)
        $namingPatterns = @($allPolicies | ForEach-Object {
            if ($_.displayName -match "^CA\d+|^EM\d+") {
                "Numbered"
            }
            elseif ($_.displayName -match "^[A-Z]+-[A-Z]+-") {
                "ASD"
            }
            elseif ($_.displayName -match "^(Global|Admin|Intern|Guest)") {
                "Persona"
            }
            else {
                "Inconsistent"
            }
        } | Sort-Object -Unique)
        
        if ($namingPatterns.Count -gt 1 -and $IncludeLowSeverity) {
            $securityGaps["NamingConsistency"] = @{
                Issue = $bestPractices.NamingConsistency.Description
                Severity = $bestPractices.NamingConsistency.Severity
                Recommendation = $bestPractices.NamingConsistency.Recommendation
                AffectedPolicies = @()
            }
        }
        
        # Filter out low severity issues if not requested
        if (!$IncludeLowSeverity) {
            $filteredGaps = @{}
            foreach ($entry in $securityGaps.GetEnumerator()) {
                if ($null -ne $entry.Value -and $entry.Value.Severity -ne "Low") {
                    $filteredGaps[$entry.Key] = $entry.Value
                }
            }
            $securityGaps = $filteredGaps
        }
        
        # Create report object with better null checks
        $report = @{
            TotalPolicies = $allPolicies.Count
            SecurityGaps = $securityGaps
            RecommendationSummary = @{
                HighSeverity = @($securityGaps.GetEnumerator() | Where-Object { 
                    $null -ne $_.Value -and $_.Value.Severity -eq "High" 
                }).Count
                MediumSeverity = @($securityGaps.GetEnumerator() | Where-Object { 
                    $null -ne $_.Value -and $_.Value.Severity -eq "Medium" 
                }).Count
                LowSeverity = @($securityGaps.GetEnumerator() | Where-Object { 
                    $null -ne $_.Value -and $_.Value.Severity -eq "Low" 
                }).Count
            }
        }
        
        # Generate output based on format
        switch ($OutputFormat) {
            "JSON" {
                $output = $report | ConvertTo-Json -Depth 5
                if (![string]::IsNullOrEmpty($OutputPath)) {
                    $output | Out-File -FilePath (Join-Path $OutputPath "security_gaps.json") -Encoding utf8
                }
            }
            "Table" {
                $tableOutput = $securityGaps.GetEnumerator() | Sort-Object { 
                    switch ($_.Value.Severity) {
                        "High" { 1 }
                        "Medium" { 2 }
                        "Low" { 3 }
                        default { 4 }
                    }
                } | ForEach-Object {
                    [PSCustomObject]@{
                        Issue = $bestPractices[$_.Key].Name
                        Description = $_.Value.Issue
                        Severity = $_.Value.Severity
                        Recommendation = $_.Value.Recommendation
                        AffectedPolicies = if ($_.Value.AffectedPolicies.Count -gt 0) {
                            $_.Value.AffectedPolicies -join ", "
                        } else { "N/A" }
                    }
                }
                
                if (![string]::IsNullOrEmpty($OutputPath)) {
                    $tableOutput | Export-Csv -Path (Join-Path $OutputPath "security_gaps.csv") -NoTypeInformation
                }
                
                $report.TableView = $tableOutput
            }
            "Markdown" {
                $mdOutput = @"
# Conditional Access Security Gap Analysis

## Executive Summary

Total Policies Analyzed: **$($allPolicies.Count)**

### Security Gap Severity
- 🔴 High Severity Issues: **$($report.RecommendationSummary.HighSeverity)**
- 🟠 Medium Severity Issues: **$($report.RecommendationSummary.MediumSeverity)**
- 🟡 Low Severity Issues: **$($report.RecommendationSummary.LowSeverity)**

## Security Gaps and Recommendations

$(($securityGaps.GetEnumerator() | Sort-Object { 
    switch ($_.Value.Severity) {
        "High" { 1 }
        "Medium" { 2 }
        "Low" { 3 }
        default { 4 }
    }
} | ForEach-Object {
    $key = $_.Key
    $gap = $_.Value
    $icon = switch ($gap.Severity) {
        "High" { "🔴" }
        "Medium" { "🟠" }
        "Low" { "🟡" }
        default { "⚪" }
    }
    
    $affectedPoliciesText = if ($gap.AffectedPolicies.Count -gt 0) {
        "`n### Affected Policies`n" + ($gap.AffectedPolicies | ForEach-Object { "- $_" } | Out-String)
    } else { "" }
    
    @"
### $icon $($bestPractices[$key].Name)

**Severity:** $($gap.Severity)

**Issue:** $($gap.Issue)

**Recommendation:** $($gap.Recommendation)
$affectedPoliciesText
"@
}) -join "`n`n")

## Recommendation Implementation Priority

1. Address all high severity gaps immediately
2. Address medium severity gaps in next change cycle
3. Address low severity gaps as part of routine maintenance
"@
                
                if (![string]::IsNullOrEmpty($OutputPath)) {
                    $mdOutput | Out-File -FilePath (Join-Path $OutputPath "security_gaps.md") -Encoding utf8
                }
                
                $report.MarkdownView = $mdOutput
            }
        }
        
        # Return the analysis object
        return $report
    }
}

# Export the function
Export-ModuleMember -Function Get-CASecurityGap 