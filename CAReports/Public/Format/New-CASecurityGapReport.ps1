function New-CASecurityGapReport {
    <#
    .SYNOPSIS
        Generates a report of security gaps in Conditional Access policies.

    .DESCRIPTION
        This function analyzes Conditional Access policies to identify security gaps
        and generates a report that includes findings and recommendations.
        The report includes analysis based on multiple security frameworks including
        Microsoft best practices, NIST, PCI DSS, and MITRE ATT&CK.

    .PARAMETER Policies
        The Conditional Access policies to analyze.

    .PARAMETER OutputPath
        The path where the report should be saved. If not specified, uses the default path from configuration.

    .PARAMETER Frameworks
        Optional. Specify which security frameworks to include in the report.
        Valid values: "All", "MT", "NIST", "PCI", "MITRE".
        Default: "All"

    .PARAMETER IncludeFrameworkSummary
        When enabled, includes a summary section for each framework's findings.

    .EXAMPLE
        New-CASecurityGapReport -Policies $policies -OutputPath "C:\Reports"

    .EXAMPLE
        New-CASecurityGapReport -Policies $policies -OutputPath "C:\Reports" -Frameworks "PCI","NIST"

    .NOTES
        This function is part of the CAReports module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject[]]$Policies,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "MT", "NIST", "PCI", "MITRE")]
        [string[]]$Frameworks = @("All"),
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeFrameworkSummary
    )
    
    # Get the proper output path if not specified
    if ([string]::IsNullOrEmpty($OutputPath)) {
        # Get configuration to determine proper paths
        $config = Get-CAConfig
        $basePath = $config.OutputPaths.Base
        $markdownPath = $config.OutputPaths.Markdown
        $OutputPath = Join-Path -Path $basePath -ChildPath $markdownPath
        Write-Verbose "Using configured output path: $OutputPath"
    }
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    # Initialize report sections
    $reportSections = @()
    $highSeverityIssues = @()
    $mediumSeverityIssues = @()
    $lowSeverityIssues = @()
    
    # Policy-specific issues
    $policyIssues = @{}
    
    # Policy compliance tracking
    $policyCompliance = @{}
    
    # Framework-specific findings
    $frameworkFindings = @{
        "MT" = @()
        "NIST" = @()
        "PCI" = @()
        "MITRE" = @()
        "General" = @()
    }
    
    # Analyze each policy
    foreach ($policy in $Policies) {
        # Get security issues for each selected framework
        foreach ($framework in $Frameworks) {
            $analysisResult = Get-SecurityAnalysis -Policy $policy -AllPolicies $Policies -DetailedAnalysis -Framework $framework -IncludeCompliantStatus
            
            # Handle both old and new return format
            $issues = if ($analysisResult -is [hashtable] -and $analysisResult.ContainsKey('Issues')) {
                $analysisResult.Issues
            } else {
                $analysisResult
            }
            
            # Get compliance statuses if available
            $compliances = if ($analysisResult -is [hashtable] -and $analysisResult.ContainsKey('Compliance')) {
                $analysisResult.Compliance
            } else {
                @()
            }
            
            foreach ($issue in $issues) {
                # Categorize by framework
                if ($issue -match "^NIST") {
                    $frameworkFindings["NIST"] += $issue
                } elseif ($issue -match "^PCI") {
                    $frameworkFindings["PCI"] += $issue
                } elseif ($issue -match "^MITRE") {
                    $frameworkFindings["MITRE"] += $issue
                } elseif ($issue -match "^MT\.") {
                    $frameworkFindings["MT"] += $issue
                } else {
                    $frameworkFindings["General"] += $issue
                }
                
                # Track issues by policy
                if (-not $policyIssues.ContainsKey($policy.displayName)) {
                    $policyIssues[$policy.displayName] = @()
                }
                $policyIssues[$policy.displayName] += $issue
            }
            
            # Track compliance findings
            foreach ($compliance in $compliances) {
                # Extract requirement ID from compliance message (e.g., "MT.1009:PASS" -> "MT.1009")
                if ($compliance -match "^([^:]+):PASS") {
                    $requirementId = $Matches[1]
                    
                    # Initialize tracking for this requirement if needed
                    if (-not $policyCompliance.ContainsKey($requirementId)) {
                        $policyCompliance[$requirementId] = @{
                            Requirement = $requirementId
                            Description = $compliance -replace "^[^:]+:PASS - ", ""
                            CompliantPolicies = @()
                            Framework = if ($requirementId -match "^NIST") { "NIST" }
                                       elseif ($requirementId -match "^PCI") { "PCI" }
                                       elseif ($requirementId -match "^MITRE") { "MITRE" }
                                       elseif ($requirementId -match "^MT\.") { "MT" }
                                       else { "General" }
                        }
                    }
                    
                    # Add policy to the list of compliant policies
                    $policyCompliance[$requirementId].CompliantPolicies += $policy.displayName
                }
            }
        }
    }
    
    # Define common security gaps and assign severity
    $securityGaps = @{
        # High severity gaps
        "Legacy Authentication" = @{
            RequirementId = "MT.1009"  # Map to the specific requirement ID
            Severity = "High"
            Issue = "Block legacy authentication protocols"
            Recommendation = "Create a policy to block legacy authentication for all applications"
            AffectedPolicies = @()
            Framework = "General"
        }
        "Guest MFA" = @{
            RequirementId = "MT.1016"  # Map to the specific requirement ID
            Severity = "High"
            Issue = "Ensure guest/external users require MFA"
            Recommendation = "Create a policy specifically targeting guests and external users to require MFA"
            AffectedPolicies = @()
            Framework = "General"
        }
        
        # Medium severity gaps
        "Broad User Exclusions" = @{
            RequirementId = ""  # General best practice, no specific requirement ID
            Severity = "Medium"
            Issue = "Avoid broad user exclusions from security policies"
            Recommendation = "Review policies with many excluded users and consider alternative approaches"
            AffectedPolicies = @()
            Framework = "General"
        }
        "Administrator Exclusions" = @{
            RequirementId = ""  # General best practice, no specific requirement ID
            Severity = "Medium"
            Issue = "Minimize administrator exclusions from security policies"
            Recommendation = "Review and minimize admin exclusions; use break-glass accounts instead of excluding regular admin accounts"
            AffectedPolicies = @()
            Framework = "General"
        }
        "Device Compliance" = @{
            RequirementId = "MT.1001"  # Map to the specific requirement ID
            Severity = "Medium"
            Issue = "Require compliant devices for sensitive data access"
            Recommendation = "Implement device compliance requirements for applications with sensitive data"
            AffectedPolicies = @()
            Framework = "General"
        }
        "Risk Policies" = @{
            RequirementId = "MT.1012"  # Map to the specific requirement ID
            Severity = "Medium"
            Issue = "Implement risk-based Conditional Access policies"
            Recommendation = "Create policies that respond to sign-in and user risk levels"
            AffectedPolicies = @()
            Framework = "General"
        }
        
        # Framework-specific gaps - NIST
        "NIST-Admin-Controls" = @{
            RequirementId = "NIST AC-2"  # Map to the specific requirement ID
            Severity = "High"
            Issue = "NIST AC-2: Strong controls for administrative accounts"
            Recommendation = "Ensure admin accounts have MFA, device compliance, and location restrictions"
            AffectedPolicies = @()
            Framework = "NIST"
        }
        "NIST-Risk-Response" = @{
            RequirementId = "NIST IA-5"  # Map to the specific requirement ID
            Severity = "Medium"
            Issue = "NIST IA-5: Risk-based password management"
            Recommendation = "Implement password change requirements for compromised accounts"
            AffectedPolicies = @()
            Framework = "NIST"
        }
        
        # Framework-specific gaps - PCI
        "PCI-MFA-Requirements" = @{
            RequirementId = "PCI 8.3.6"  # Map to the specific requirement ID
            Severity = "High"
            Issue = "PCI 8.3.6: MFA for sensitive applications"
            Recommendation = "Require MFA for all applications that may contain sensitive or regulated data"
            AffectedPolicies = @()
            Framework = "PCI"
        }
        "PCI-Session-Controls" = @{
            RequirementId = "PCI 8.6.1"  # Map to the specific requirement ID
            Severity = "Medium"
            Issue = "PCI 8.6.1: Session management requirements"
            Recommendation = "Implement session timeout controls for all user sessions"
            AffectedPolicies = @()
            Framework = "PCI"
        }
        
        # Framework-specific gaps - MITRE
        "MITRE-Account-Takeover" = @{
            RequirementId = "MITRE T1078"  # Map to the specific requirement ID
            Severity = "High"
            Issue = "MITRE T1078: Protection against account takeover"
            Recommendation = "Implement strong MFA and device controls to prevent valid account abuse"
            AffectedPolicies = @()
            Framework = "MITRE"
        }
        "MITRE-MFA-Strength" = @{
            RequirementId = "MITRE T1111"  # Map to the specific requirement ID
            Severity = "Medium"
            Issue = "MITRE T1111: Resistance to MFA interception"
            Recommendation = "Use phishing-resistant authentication for sensitive access"
            AffectedPolicies = @()
            Framework = "MITRE"
        }
        "MITRE-Auth-Bypass" = @{
            RequirementId = "MITRE T1556"  # Map to the specific requirement ID
            Severity = "High"
            Issue = "MITRE T1556: Vulnerable to authentication bypass"
            Recommendation = "Block legacy authentication methods to prevent authentication bypass"
            AffectedPolicies = @()
            Framework = "MITRE"
        }
    }
    
    # First, filter out gaps that are already satisfied by policies
    $activeGaps = @{}
    foreach ($gapKey in $securityGaps.Keys) {
        $gap = $securityGaps[$gapKey]
        $requirementId = $gap.RequirementId
        
        # If there's no specific requirement ID or it's not in our compliance list, keep it as a gap
        if ([string]::IsNullOrEmpty($requirementId) -or -not $policyCompliance.ContainsKey($requirementId)) {
            $activeGaps[$gapKey] = $gap
        }
    }
    
    # Map policy issues to active security gaps
    foreach ($policyName in $policyIssues.Keys) {
        foreach ($issue in $policyIssues[$policyName]) {
            # Map to legacy authentication gap if that requirement is not already satisfied
            if ($activeGaps.ContainsKey("Legacy Authentication") -and
                ($issue -match "legacy authentication" -or $issue -match "MITRE T1556")) {
                $activeGaps["Legacy Authentication"].AffectedPolicies += $policyName
            }
            
            # Map to guest MFA gap if that requirement is not already satisfied
            if ($activeGaps.ContainsKey("Guest MFA") -and
                ($issue -match "Guest users.*without MFA" -or $issue -match "guest.*MFA")) {
                $activeGaps["Guest MFA"].AffectedPolicies += $policyName
            }
            
            # Map to broad user exclusions gap
            if ($activeGaps.ContainsKey("Broad User Exclusions") -and
                $issue -match "broad user exclusions") {
                $activeGaps["Broad User Exclusions"].AffectedPolicies += $policyName
            }
            
            # Map to administrator exclusions gap
            if ($activeGaps.ContainsKey("Administrator Exclusions") -and
                ($policy.conditions.users.excludeRoles -or 
                ($issue -match "admin" -and $issue -match "exclusion"))) {
                $activeGaps["Administrator Exclusions"].AffectedPolicies += $policyName
            }
            
            # Map to device compliance gap if that requirement is not already satisfied
            if ($activeGaps.ContainsKey("Device Compliance") -and
                ($issue -match "device compliance" -or $issue -match "MT\.1001")) {
                $activeGaps["Device Compliance"].AffectedPolicies += $policyName
            }
            
            # Map to risk policies gap if that requirement is not already satisfied
            if ($activeGaps.ContainsKey("Risk Policies") -and
                ($issue -match "risk" -or $issue -match "MT\.1012" -or $issue -match "MT\.1013")) {
                $activeGaps["Risk Policies"].AffectedPolicies += $policyName
            }
            
            # Map NIST issues
            if ($activeGaps.ContainsKey("NIST-Admin-Controls") -and
                $issue -match "NIST AC-2") {
                $activeGaps["NIST-Admin-Controls"].AffectedPolicies += $policyName
            }
            
            if ($activeGaps.ContainsKey("NIST-Risk-Response") -and
                $issue -match "NIST IA-5") {
                $activeGaps["NIST-Risk-Response"].AffectedPolicies += $policyName
            }
            
            # Map PCI issues
            if ($activeGaps.ContainsKey("PCI-MFA-Requirements") -and
                $issue -match "PCI 8.3.6") {
                $activeGaps["PCI-MFA-Requirements"].AffectedPolicies += $policyName
            }
            
            if ($activeGaps.ContainsKey("PCI-Session-Controls") -and
                $issue -match "PCI 8.6.1") {
                $activeGaps["PCI-Session-Controls"].AffectedPolicies += $policyName
            }
            
            # Map MITRE issues
            if ($activeGaps.ContainsKey("MITRE-Account-Takeover") -and
                $issue -match "MITRE T1078") {
                $activeGaps["MITRE-Account-Takeover"].AffectedPolicies += $policyName
            }
            
            if ($activeGaps.ContainsKey("MITRE-MFA-Strength") -and
                $issue -match "MITRE T1111") {
                $activeGaps["MITRE-MFA-Strength"].AffectedPolicies += $policyName
            }
            
            if ($activeGaps.ContainsKey("MITRE-Auth-Bypass") -and
                $issue -match "MITRE T1556") {
                $activeGaps["MITRE-Auth-Bypass"].AffectedPolicies += $policyName
            }
        }
    }
    
    # Remove duplicate affected policies and sort gaps by severity
    $highSeverityIssues = @()
    $mediumSeverityIssues = @()
    $lowSeverityIssues = @()
    
    foreach ($gapKey in $activeGaps.Keys) {
        $gap = $activeGaps[$gapKey]
        
        # Only include gaps that have affected policies
        if ($gap.AffectedPolicies.Count -gt 0) {
            $gap.AffectedPolicies = $gap.AffectedPolicies | Select-Object -Unique | Sort-Object
            
            if ($gap.Severity -eq "High") {
                $highSeverityIssues += $gap
            } elseif ($gap.Severity -eq "Medium") {
                $mediumSeverityIssues += $gap
            } else {
                $lowSeverityIssues += $gap
            }
        }
    }
    
    # Sort issues by severity and framework
    $highSeverityIssues = $highSeverityIssues | 
        Sort-Object -Property @{Expression = {$_.Framework}; Ascending = $true}, 
                            @{Expression = {$_.Issue}; Ascending = $true}
    
    $mediumSeverityIssues = $mediumSeverityIssues | 
        Sort-Object -Property @{Expression = {$_.Framework}; Ascending = $true}, 
                            @{Expression = {$_.Issue}; Ascending = $true}
    
    $lowSeverityIssues = $lowSeverityIssues | 
        Sort-Object -Property @{Expression = {$_.Framework}; Ascending = $true}, 
                            @{Expression = {$_.Issue}; Ascending = $true}
    
    # Build report content
    $reportContent = "# Conditional Access Security Gap Analysis`n`n"
    
    # Executive summary
    $reportContent += "## Executive Summary`n`n"
    $reportContent += "Total Policies Analyzed: **$($Policies.Count)**`n`n"
    
    # Security gap severity
    $reportContent += "### Security Gap Severity`n"
    $reportContent += "- 🔴 High Severity Issues: **$($highSeverityIssues.Count)**`n"
    $reportContent += "- 🟠 Medium Severity Issues: **$($mediumSeverityIssues.Count)**`n"
    $reportContent += "- 🟡 Low Severity Issues: **$($lowSeverityIssues.Count)**`n`n"
    
    # Add compliance summary
    $reportContent += "### Security Requirements Status`n"
    $complianceCount = $policyCompliance.Count
    $reportContent += "- ✅ Requirements Met: **$complianceCount**`n"
    $reportContent += "- 🚫 Requirements with Gaps: **$($highSeverityIssues.Count + $mediumSeverityIssues.Count + $lowSeverityIssues.Count)**`n`n"
    
    # Framework summaries if requested
    if ($IncludeFrameworkSummary) {
        $reportContent += "### Framework Coverage`n"
        
        if ($Frameworks -contains "All" -or $Frameworks -contains "MT") {
            $mtCompliance = ($policyCompliance.Keys | Where-Object { $_ -match "^MT\." }).Count
            $reportContent += "- 🛡️ Microsoft Security Best Practices: **$mtCompliance** met, **$($frameworkFindings["MT"].Count)** gaps`n"
        }
        
        if ($Frameworks -contains "All" -or $Frameworks -contains "NIST") {
            $nistCompliance = ($policyCompliance.Keys | Where-Object { $_ -match "^NIST" }).Count
            $reportContent += "- 📋 NIST 800-53 Controls: **$nistCompliance** met, **$($frameworkFindings["NIST"].Count)** gaps`n"
        }
        
        if ($Frameworks -contains "All" -or $Frameworks -contains "PCI") {
            $pciCompliance = ($policyCompliance.Keys | Where-Object { $_ -match "^PCI" }).Count
            $reportContent += "- 💳 PCI DSS 4.0 Requirements: **$pciCompliance** met, **$($frameworkFindings["PCI"].Count)** gaps`n"
        }
        
        if ($Frameworks -contains "All" -or $Frameworks -contains "MITRE") {
            $mitreCompliance = ($policyCompliance.Keys | Where-Object { $_ -match "^MITRE" }).Count
            $reportContent += "- 🔍 MITRE ATT&CK Mitigations: **$mitreCompliance** met, **$($frameworkFindings["MITRE"].Count)** gaps`n"
        }
        
        $reportContent += "`n"
    }
    
    # Requirements met section
    $reportContent += "## Security Requirements Met`n`n"
    
    # Group compliance by framework
    $complianceByFramework = @{
        "MT" = @()
        "NIST" = @()
        "PCI" = @()
        "MITRE" = @()
        "General" = @()
    }
    
    foreach ($item in $policyCompliance.Values) {
        $framework = $item.Framework
        $complianceByFramework[$framework] += $item
    }
    
    # Microsoft Security Best Practices compliance
    if ($complianceByFramework["MT"].Count -gt 0) {
        $reportContent += "### Microsoft Security Best Practices`n`n"
        foreach ($item in $complianceByFramework["MT"] | Sort-Object -Property Requirement) {
            # De-duplicate policy names
            $uniquePolicies = $item.CompliantPolicies | Select-Object -Unique | Sort-Object
            
            # Find the most specific/dedicated policy as the primary one
            $primaryPolicy = ""
            
            # Determine the primary policy based on the requirement
            switch -Regex ($item.Requirement) {
                "MT\.1009" { # Legacy authentication
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*Block legacy*" } | Select-Object -First 1
                }
                "MT\.1006" { # Admin MFA
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*admin*" -and $_ -like "*MFA*" } | Select-Object -First 1
                }
                "MT\.1015" { # Block unknown platforms
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*device platform*" -or $_ -like "*unsupported device*" } | Select-Object -First 1
                }
                "MT\.1017" { # Non-persistent browser
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*persistent*" -or $_ -like "*browser*session*" } | Select-Object -First 1
                }
                "MT\.1019" { # Application enforced restrictions
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*application*restrict*" -or $_ -like "*app*enforc*" } | Select-Object -First 1
                }
                "MT\.1001" { # Device compliance
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*compliant*device*" } | Select-Object -First 1
                }
                "MT\.1007" { # User MFA
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*MFA*" -and $_ -like "*all users*" } | Select-Object -First 1
                }
                default {
                    # Generic matching for other requirements
                    if ($uniquePolicies -like "*Block legacy authentication*") {
                        $primaryPolicy = ($uniquePolicies -like "*Block legacy authentication*")[0]
                    } elseif ($uniquePolicies -like "*Require compliant*") {
                        $primaryPolicy = ($uniquePolicies -like "*Require compliant*")[0]
                    } elseif ($uniquePolicies -like "*MFA*") {
                        $primaryPolicy = ($uniquePolicies -like "*MFA*")[0]
                    }
                }
            }
            
            # Fallback if no match found
            if ([string]::IsNullOrEmpty($primaryPolicy) -and $uniquePolicies.Count -gt 0) {
                $primaryPolicy = $uniquePolicies[0]
            } elseif ([string]::IsNullOrEmpty($primaryPolicy)) {
                $primaryPolicy = "Unknown Policy"
            }
            
            $reportContent += "#### ✅ $($item.Requirement): $($item.Description)`n`n"
            $reportContent += "**Primary Policy:** $primaryPolicy`n`n"
            
            # Only show additional policies if there are 5 or fewer, otherwise summarize
            if ($uniquePolicies.Count -gt 1 -and $uniquePolicies.Count -le 6) {
                $reportContent += "**Additional Policies:**`n"
                foreach ($policy in $uniquePolicies | Where-Object { $_ -ne $primaryPolicy } | Select-Object -First 5) {
                    $reportContent += "- $policy`n"
                }
                $reportContent += "`n"
            } elseif ($uniquePolicies.Count -gt 6) {
                $otherCount = $uniquePolicies.Count - 1
                $reportContent += "**Additional Policies:** $otherCount other policies also satisfy this requirement`n`n"
            }
        }
    }
    
    # NIST compliance
    if ($complianceByFramework["NIST"].Count -gt 0) {
        $reportContent += "### NIST 800-53 Controls`n`n"
        foreach ($item in $complianceByFramework["NIST"] | Sort-Object -Property Requirement) {
            # De-duplicate policy names
            $uniquePolicies = $item.CompliantPolicies | Select-Object -Unique | Sort-Object
            
            # Find the most specific/dedicated policy as the primary one
            $primaryPolicy = ""
            
            # Determine the primary policy based on the requirement
            switch -Regex ($item.Requirement) {
                "NIST AC-2" { # Admin account management
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*admin*" -and ($_ -like "*MFA*" -or $_ -like "*compliant*") } | Select-Object -First 1
                }
                "NIST IA-2" { # Admin MFA
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*admin*" -and $_ -like "*MFA*" } | Select-Object -First 1
                }
                default {
                    # Generic matching for other requirements
                    if ($uniquePolicies -like "*admin*" -or $uniquePolicies -like "*privile*") {
                        $primaryPolicy = ($uniquePolicies | Where-Object { $_ -like "*admin*" -or $_ -like "*privile*" } | Select-Object -First 1)
                    } elseif ($uniquePolicies -like "*MFA*") {
                        $primaryPolicy = ($uniquePolicies -like "*MFA*")[0]
                    }
                }
            }
            
            # Fallback if no match found
            if ([string]::IsNullOrEmpty($primaryPolicy) -and $uniquePolicies.Count -gt 0) {
                $primaryPolicy = $uniquePolicies[0]
            } elseif ([string]::IsNullOrEmpty($primaryPolicy)) {
                $primaryPolicy = "Unknown Policy"
            }
            
            $reportContent += "#### ✅ $($item.Requirement): $($item.Description)`n`n"
            $reportContent += "**Primary Policy:** $primaryPolicy`n`n"
            
            # Only show additional policies if there are 5 or fewer, otherwise summarize
            if ($uniquePolicies.Count -gt 1 -and $uniquePolicies.Count -le 6) {
                $reportContent += "**Additional Policies:**`n"
                foreach ($policy in $uniquePolicies | Where-Object { $_ -ne $primaryPolicy } | Select-Object -First 5) {
                    $reportContent += "- $policy`n"
                }
                $reportContent += "`n"
            } elseif ($uniquePolicies.Count -gt 6) {
                $otherCount = $uniquePolicies.Count - 1
                $reportContent += "**Additional Policies:** $otherCount other policies also satisfy this requirement`n`n"
            }
        }
    }
    
    # PCI compliance
    if ($complianceByFramework["PCI"].Count -gt 0) {
        $reportContent += "### PCI DSS 4.0 Requirements`n`n"
        foreach ($item in $complianceByFramework["PCI"] | Sort-Object -Property Requirement) {
            # De-duplicate policy names
            $uniquePolicies = $item.CompliantPolicies | Select-Object -Unique | Sort-Object
            
            # Find the most specific/dedicated policy as the primary one
            $primaryPolicy = ""
            
            # Determine the primary policy based on the requirement
            switch -Regex ($item.Requirement) {
                "PCI 8.6.1" { # Session timeout
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*session*" -or $_ -like "*persistent*" -or $_ -like "*timeout*" } | Select-Object -First 1
                }
                "PCI 8.3.6" { # MFA for sensitive applications
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*MFA*" -and ($_ -like "*sensitive*" -or $_ -like "*all*") } | Select-Object -First 1
                }
                default {
                    # Generic matching for other requirements
                    if ($uniquePolicies -like "*session*" -or $uniquePolicies -like "*timeout*") {
                        $primaryPolicy = ($uniquePolicies | Where-Object { $_ -like "*session*" -or $_ -like "*timeout*" } | Select-Object -First 1)
                    } elseif ($uniquePolicies -like "*MFA*") {
                        $primaryPolicy = ($uniquePolicies -like "*MFA*")[0]
                    }
                }
            }
            
            # Fallback if no match found
            if ([string]::IsNullOrEmpty($primaryPolicy) -and $uniquePolicies.Count -gt 0) {
                $primaryPolicy = $uniquePolicies[0]
            } elseif ([string]::IsNullOrEmpty($primaryPolicy)) {
                $primaryPolicy = "Unknown Policy"
            }
            
            $reportContent += "#### ✅ $($item.Requirement): $($item.Description)`n`n"
            $reportContent += "**Primary Policy:** $primaryPolicy`n`n"
            
            # Only show additional policies if there are 5 or fewer, otherwise summarize
            if ($uniquePolicies.Count -gt 1 -and $uniquePolicies.Count -le 6) {
                $reportContent += "**Additional Policies:**`n"
                foreach ($policy in $uniquePolicies | Where-Object { $_ -ne $primaryPolicy } | Select-Object -First 5) {
                    $reportContent += "- $policy`n"
                }
                $reportContent += "`n"
            } elseif ($uniquePolicies.Count -gt 6) {
                $otherCount = $uniquePolicies.Count - 1
                $reportContent += "**Additional Policies:** $otherCount other policies also satisfy this requirement`n`n"
            }
        }
    }
    
    # MITRE compliance
    if ($complianceByFramework["MITRE"].Count -gt 0) {
        $reportContent += "### MITRE ATT&CK Mitigations`n`n"
        foreach ($item in $complianceByFramework["MITRE"] | Sort-Object -Property Requirement) {
            # De-duplicate policy names
            $uniquePolicies = $item.CompliantPolicies | Select-Object -Unique | Sort-Object
            
            # Find the most specific/dedicated policy as the primary one
            $primaryPolicy = ""
            
            # Determine the primary policy based on the requirement
            switch -Regex ($item.Requirement) {
                "MITRE T1556" { # Authentication Bypass
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*Block legacy*" -or $_ -like "*authentication*bypass*" } | Select-Object -First 1
                }
                "MITRE T1078" { # Valid Accounts
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*MFA*" -and $_ -like "*all users*" } | Select-Object -First 1
                }
                "MITRE T1111" { # MFA Interception
                    $primaryPolicy = $uniquePolicies | Where-Object { $_ -like "*phishing*" -or $_ -like "*resistant*" } | Select-Object -First 1
                }
                default {
                    # Generic matching for other requirements
                    if ($uniquePolicies -like "*Block legacy*") {
                        $primaryPolicy = ($uniquePolicies -like "*Block legacy*")[0]
                    } elseif ($uniquePolicies -like "*MFA*") {
                        $primaryPolicy = ($uniquePolicies -like "*MFA*")[0]
                    }
                }
            }
            
            # Fallback if no match found
            if ([string]::IsNullOrEmpty($primaryPolicy) -and $uniquePolicies.Count -gt 0) {
                $primaryPolicy = $uniquePolicies[0]
            } elseif ([string]::IsNullOrEmpty($primaryPolicy)) {
                $primaryPolicy = "Unknown Policy"
            }
            
            $reportContent += "#### ✅ $($item.Requirement): $($item.Description)`n`n"
            $reportContent += "**Primary Policy:** $primaryPolicy`n`n"
            
            # Only show additional policies if there are 5 or fewer, otherwise summarize
            if ($uniquePolicies.Count -gt 1 -and $uniquePolicies.Count -le 6) {
                $reportContent += "**Additional Policies:**`n"
                foreach ($policy in $uniquePolicies | Where-Object { $_ -ne $primaryPolicy } | Select-Object -First 5) {
                    $reportContent += "- $policy`n"
                }
                $reportContent += "`n"
            } elseif ($uniquePolicies.Count -gt 6) {
                $otherCount = $uniquePolicies.Count - 1
                $reportContent += "**Additional Policies:** $otherCount other policies also satisfy this requirement`n`n"
            }
        }
    }
    
    # Security gaps and recommendations
    $reportContent += "## Security Gaps and Recommendations`n`n"
    
    # High severity issues
    foreach ($issue in $highSeverityIssues) {
        $frameworkPrefix = if ($issue.Framework -ne "General") { "[$($issue.Framework)] " } else { "" }
        
        $reportContent += "### 🔴 $frameworkPrefix$($issue.Issue)`n`n"
        $reportContent += "**Severity:** High`n`n"
        $reportContent += "**Issue:** $($issue.Issue)`n`n"
        $reportContent += "**Recommendation:** $($issue.Recommendation)`n`n"
        
        # Only show affected policies if they are 5 or fewer, otherwise summarize the count
        if ($issue.AffectedPolicies.Count -gt 0) {
            # If this is about administrator exclusions, just show a summary count
            if ($issue.Issue -match "administrator exclusions" -or $issue.AffectedPolicies.Count > 5) {
                $reportContent += "**Note:** Found in $($issue.AffectedPolicies.Count) policies that have admin role exclusions`n`n"
            } else {
                $reportContent += "### Affected Policies`n"
                foreach ($policy in $issue.AffectedPolicies) {
                    $reportContent += "- $policy`n"
                }
                $reportContent += "`n"
            }
        }
    }
    
    # Medium severity issues
    foreach ($issue in $mediumSeverityIssues) {
        $frameworkPrefix = if ($issue.Framework -ne "General") { "[$($issue.Framework)] " } else { "" }
        
        $reportContent += "### 🟠 $frameworkPrefix$($issue.Issue)`n`n"
        $reportContent += "**Severity:** Medium`n`n"
        $reportContent += "**Issue:** $($issue.Issue)`n`n"
        $reportContent += "**Recommendation:** $($issue.Recommendation)`n`n"
        
        # Only show affected policies if they are 5 or fewer, otherwise summarize the count
        if ($issue.AffectedPolicies.Count -gt 0) {
            # If this is about administrator exclusions, just show a summary count
            if ($issue.Issue -match "administrator exclusions" -or $issue.AffectedPolicies.Count > 5) {
                $reportContent += "**Note:** Found in $($issue.AffectedPolicies.Count) policies that have admin role exclusions`n`n"
            } else {
                $reportContent += "### Affected Policies`n"
                foreach ($policy in $issue.AffectedPolicies) {
                    $reportContent += "- $policy`n"
                }
                $reportContent += "`n"
            }
        }
    }
    
    # Low severity issues
    foreach ($issue in $lowSeverityIssues) {
        $frameworkPrefix = if ($issue.Framework -ne "General") { "[$($issue.Framework)] " } else { "" }
        
        $reportContent += "### 🟡 $frameworkPrefix$($issue.Issue)`n`n"
        $reportContent += "**Severity:** Low`n`n"
        $reportContent += "**Issue:** $($issue.Issue)`n`n"
        $reportContent += "**Recommendation:** $($issue.Recommendation)`n`n"
        
        # Only show affected policies if they are 5 or fewer, otherwise summarize the count
        if ($issue.AffectedPolicies.Count -gt 0) {
            # If this is about administrator exclusions, just show a summary count
            if ($issue.Issue -match "administrator exclusions" -or $issue.AffectedPolicies.Count > 5) {
                $reportContent += "**Note:** Found in $($issue.AffectedPolicies.Count) policies that have admin role exclusions`n`n"
            } else {
                $reportContent += "### Affected Policies`n"
                foreach ($policy in $issue.AffectedPolicies) {
                    $reportContent += "- $policy`n"
                }
                $reportContent += "`n"
            }
        }
    }
    
    # Recommendation implementation priority
    $reportContent += "## Recommendation Implementation Priority`n`n"
    $reportContent += "1. Address all high severity gaps immediately`n"
    $reportContent += "2. Address medium severity gaps in next change cycle`n"
    $reportContent += "3. Address low severity gaps as part of routine maintenance`n"
    
    # Write report to file
    $reportPath = Join-Path -Path $OutputPath -ChildPath "security_framework_analysis.md"
    $reportContent | Out-File -FilePath $reportPath -Encoding utf8 -Force
    
    Write-Verbose "Security framework report created at $reportPath"
    return $reportPath
} 