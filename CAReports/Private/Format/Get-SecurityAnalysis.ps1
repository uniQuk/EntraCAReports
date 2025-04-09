function Get-SecurityAnalysis {
    <#
    .SYNOPSIS
        Identifies potential security issues in Conditional Access policies.
    
    .DESCRIPTION
        This function analyzes a Conditional Access policy to identify potential security issues,
        including broad exclusions, test policies, weak controls, and report-only mode settings.
        It also checks for compliance with common security frameworks and best practices.
    
    .PARAMETER Policy
        The Conditional Access policy to analyze.
    
    .PARAMETER DetailedAnalysis
        When enabled, provides more detailed information about each security issue.
    
    .PARAMETER AllPolicies
        Collection of all Conditional Access policies for cross-policy analysis.
    
    .PARAMETER Framework
        Optional. Specify which security framework to check against.
        Valid values: "All", "MT", "NIST", "PCI", "MITRE".
        Default: "All"
    
    .PARAMETER IncludeCompliantStatus
        When enabled, includes information about requirements that are satisfied by existing policies.
    
    .EXAMPLE
        $issues = Get-SecurityAnalysis -Policy $policy
    
    .EXAMPLE
        $detailedIssues = Get-SecurityAnalysis -Policy $policy -DetailedAnalysis
    
    .EXAMPLE
        $allIssues = Get-SecurityAnalysis -Policy $policy -AllPolicies $policies -DetailedAnalysis
    
    .EXAMPLE
        $pcissues = Get-SecurityAnalysis -Policy $policy -Framework "PCI"
    
    .NOTES
        This is an internal helper function used by the CAReports module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$Policy,
        
        [Parameter(Mandatory = $false)]
        [switch]$DetailedAnalysis,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$AllPolicies,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "MT", "NIST", "PCI", "MITRE")]
        [string]$Framework = "All",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCompliantStatus
    )
    
    $issues = @()
    $compliances = @()

    # Basic checks - always run
    
    # Check for broad exclusions
    if ($Policy.conditions.users.excludeUsers -and 
        ($Policy.conditions.users.excludeUsers.Count -gt 3 -or 
         $Policy.conditions.users.excludeUsers.PSObject.Properties.Count -gt 3)) {
        
        $count = if ($Policy.conditions.users.excludeUsers.PSObject.Properties) {
            $Policy.conditions.users.excludeUsers.PSObject.Properties.Count
        } else {
            $Policy.conditions.users.excludeUsers.Count
        }
        
        if ($DetailedAnalysis) {
            $issues += "Has broad user exclusions ($count users) - Large exclusion lists may create security gaps"
        } else {
            $issues += "Has broad user exclusions ($count users)"
        }
    }

    # Check for broad group exclusions
    if ($Policy.conditions.users.excludeGroups -and 
        ($Policy.conditions.users.excludeGroups.Count -gt 2 -or 
         $Policy.conditions.users.excludeGroups.PSObject.Properties.Count -gt 2)) {
        
        $count = if ($Policy.conditions.users.excludeGroups.PSObject.Properties) {
            $Policy.conditions.users.excludeGroups.PSObject.Properties.Count
        } else {
            $Policy.conditions.users.excludeGroups.Count
        }
        
        if ($DetailedAnalysis) {
            $issues += "Has broad group exclusions ($count groups) - Multiple group exclusions increase complexity and risk"
        } else {
            $issues += "Has broad group exclusions ($count groups)"
        }
    }

    # Check for test policies
    if ($Policy.displayName -match "TEST|DEV|PILOT|TEMP") {
        if ($DetailedAnalysis) {
            $issues += "Test/Development policy - Naming indicates this is not a production policy"
        } else {
            $issues += "Test/Development policy"
        }
    }

    # Check weak controls
    if ((!$Policy.grantControls -or !$Policy.grantControls.builtInControls) -and 
        (!$Policy.sessionControls -or 
         (!$Policy.sessionControls.applicationEnforcedRestrictions.isEnabled -and
          !$Policy.sessionControls.cloudAppSecurity.isEnabled -and
          !$Policy.sessionControls.signInFrequency.isEnabled -and
          !$Policy.sessionControls.persistentBrowser.isEnabled))) {
        
        if ($DetailedAnalysis) {
            $issues += "No security controls defined - Policy does not apply any security restrictions"
        } else {
            $issues += "No security controls defined"
        }
    }

    # Check state
    if ($Policy.state -eq "enabledForReportingButNotEnforced") {
        if ($DetailedAnalysis) {
            $issues += "Policy in report-only mode - Policy is not actively enforcing controls"
        } else {
            $issues += "Policy in report-only mode"
        }
    } elseif ($Policy.state -eq "disabled") {
        if ($DetailedAnalysis) {
            $issues += "Policy is disabled - No security enforcement is occurring"
        } else {
            $issues += "Policy is disabled"
        }
    }

    # Check for broad application scope without controls
    if ($Policy.conditions.applications.includeApplications -contains "All" -and 
        (!$Policy.grantControls -or !$Policy.grantControls.builtInControls -or 
         ($Policy.grantControls.builtInControls -notcontains "mfa" -and 
          $Policy.grantControls.builtInControls -notcontains "compliantDevice" -and
          $Policy.grantControls.builtInControls -notcontains "domainJoinedDevice"))) {
        
        if ($DetailedAnalysis) {
            $issues += "Broad application scope (All) with weak controls - All applications covered without strong authentication requirements"
        } else {
            $issues += "Broad application scope with weak controls"
        }
    }

    # MT Framework checks
    if ($Framework -eq "All" -or $Framework -eq "MT") {
        # MT.1001 - Device compliance check
        if ($Policy.grantControls.builtInControls -contains "compliantDevice") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1001:PASS - Policy implements device compliance requirement"
            }
        }

        # MT.1003/MT.1004 - All cloud apps coverage
        if ($Policy.conditions.applications.includeApplications -contains "All") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1003:PASS - Policy includes all cloud applications"
            }
            
            # MT.1004 - Check if All Users are included
            if ($Policy.conditions.users.includeUsers -contains "All" -or 
                $Policy.conditions.users.includeGroups -contains "All") {
                if ($IncludeCompliantStatus) {
                    $compliances += "MT.1004:PASS - Policy covers all cloud apps and all users"
                }
            }
        }

        # MT.1006 - MFA for admin roles
        if ($Policy.conditions.users.includeRoles -and 
            $Policy.grantControls.builtInControls -contains "mfa") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1006:PASS - Policy requires MFA for administrative roles"
            }
        }

        # MT.1007 - MFA for all users
        if (($Policy.conditions.users.includeUsers -contains "All" -or 
             $Policy.conditions.users.includeGroups -contains "All") -and
            $Policy.grantControls.builtInControls -contains "mfa") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1007:PASS - Policy requires MFA for all users"
            }
        }

        # MT.1009 - Block legacy authentication
        if ($Policy.conditions.clientAppTypes -contains "exchangeActiveSync" -and
            $Policy.conditions.clientAppTypes -contains "other" -and
            $Policy.grantControls.builtInControls -contains "block") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1009:PASS - Policy blocks legacy authentication"
            }
        } elseif ($Policy.displayName -match "Block legacy authentication" -and 
                 $Policy.state -eq "enabled" -and
                 $Policy.grantControls.builtInControls -contains "block") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1009:PASS - Dedicated policy blocks legacy authentication"
            }
        }

        # MT.1013 - Password change for high risk users
        if ($Policy.conditions.userRiskLevels -contains "high" -and
            $Policy.grantControls.builtInControls -contains "passwordChange") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1013:PASS - Policy requires password change for high-risk users"
            }
        }

        # MT.1015 - Block unknown/unsupported device platforms
        if ($Policy.conditions.platforms.excludePlatforms -and
            $Policy.conditions.platforms.includePlatforms -contains "all" -and
            $Policy.grantControls.builtInControls -contains "block") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1015:PASS - Policy blocks unknown/unsupported device platforms"
            }
        }

        # MT.1016 - MFA for guest users
        if ($Policy.conditions.users.includeGuestsOrExternalUsers -and
            $Policy.grantControls.builtInControls -contains "mfa") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1016:PASS - Policy requires MFA for guest/external users"
            }
        } else {
            # Check if there's a guest-specific policy with MFA
            $guestPolicy = $false
            if ($Policy.conditions.users.includeGuestsOrExternalUsers) {
                if ($Policy.grantControls.builtInControls -notcontains "mfa") {
                    if ($DetailedAnalysis) {
                        $issues += "Guest users included without MFA requirement - External users should be required to use strong authentication"
                    } else {
                        $issues += "Guest users included without MFA requirement"
                    }
                }
            }
        }

        # MT.1017 - Non-persistent browser session
        if ($Policy.sessionControls.persistentBrowser.isEnabled -and
            $Policy.sessionControls.persistentBrowser.mode -eq "never") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1017:PASS - Policy enforces non-persistent browser sessions"
            }
        }

        # MT.1019 - Application enforced restrictions
        if ($Policy.sessionControls.applicationEnforcedRestrictions.isEnabled) {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1019:PASS - Policy enables application enforced restrictions"
            }
        }
        
        # MT.1038 - Check for deleted groups (would require additional API calls)
        # This would need integration with Microsoft Graph to verify group existence
        
        # MT.1052 - Device Code flow
        if ($Policy.conditions.clientAppTypes -contains "deviceCode") {
            if ($IncludeCompliantStatus) {
                $compliances += "MT.1052:PASS - Policy targets device code authentication flow"
            }
        }
    }
    
    # NIST Framework checks
    if ($Framework -eq "All" -or $Framework -eq "NIST") {
        # NIST 800-53 AC-2: Account Management
        # Check if policy properly limits/restricts privileged accounts
        if ($Policy.conditions.users.includeRoles -and 
            ($Policy.grantControls.builtInControls -notcontains "mfa" -or
             $Policy.conditions.locations.includeLocations -contains "All")) {
            if ($DetailedAnalysis) {
                $issues += "NIST AC-2: Admin roles without sufficient restrictions - NIST recommends strong access controls for privileged accounts"
            } else {
                $issues += "NIST AC-2: Admin roles without sufficient restrictions"
            }
        } elseif ($Policy.conditions.users.includeRoles -and
                 $Policy.grantControls.builtInControls -contains "mfa" -and
                 ($Policy.conditions.locations.includeLocations -notcontains "All" -or 
                  $Policy.conditions.locations.excludeLocations)) {
            if ($IncludeCompliantStatus) {
                $compliances += "NIST AC-2:PASS - Policy implements strong access controls for privileged accounts"
            }
        }
        
        # NIST 800-53 IA-2: Identification and Authentication
        # Check for MFA requirements for privileged access
        if ($Policy.conditions.users.includeRoles -and 
            $Policy.grantControls.builtInControls -notcontains "mfa") {
            if ($DetailedAnalysis) {
                $issues += "NIST IA-2: Missing MFA for privileged access - NIST requires multi-factor authentication for privileged accounts"
            } else {
                $issues += "NIST IA-2: Missing MFA for privileged access"
            }
        } elseif ($Policy.conditions.users.includeRoles -and
                 $Policy.grantControls.builtInControls -contains "mfa") {
            if ($IncludeCompliantStatus) {
                $compliances += "NIST IA-2:PASS - Policy requires MFA for privileged accounts"
            }
        }
        
        # NIST 800-53 IA-5: Authenticator Management
        # Check for policies that enforce password changes for compromised accounts
        if ($Policy.conditions.userRiskLevels -and 
            $Policy.grantControls.builtInControls -notcontains "passwordChange") {
            if ($DetailedAnalysis) {
                $issues += "NIST IA-5: Risk detection without password change - NIST recommends password changes for potentially compromised accounts"
            } else {
                $issues += "NIST IA-5: Risk detection without password change"
            }
        } elseif ($Policy.conditions.userRiskLevels -and
                 $Policy.grantControls.builtInControls -contains "passwordChange") {
            if ($IncludeCompliantStatus) {
                $compliances += "NIST IA-5:PASS - Policy enforces password changes for potentially compromised accounts"
            }
        }
    }
    
    # PCI DSS Framework checks
    if ($Framework -eq "All" -or $Framework -eq "PCI") {
        # PCI DSS 4.0 Requirement 8.3.6: MFA for all non-console access
        $sensitiveApps = @("Office 365 Exchange Online", "SharePoint Online", "Microsoft Graph")
        $hasSensitiveApps = $false
        
        foreach ($app in $sensitiveApps) {
            if ($Policy.conditions.applications.includeApplications -contains $app) {
                $hasSensitiveApps = $true
                break
            }
        }
        
        if ($hasSensitiveApps -and $Policy.grantControls.builtInControls -notcontains "mfa") {
            if ($DetailedAnalysis) {
                $issues += "PCI 8.3.6: Missing MFA for sensitive applications - PCI DSS requires MFA for all non-console access to sensitive systems"
            } else {
                $issues += "PCI 8.3.6: Missing MFA for sensitive applications"
            }
        } elseif ($hasSensitiveApps -and $Policy.grantControls.builtInControls -contains "mfa") {
            if ($IncludeCompliantStatus) {
                $compliances += "PCI 8.3.6:PASS - Policy requires MFA for sensitive applications"
            }
        }
        
        # PCI DSS 4.0 Requirement 8.3.7: MFA for all access to cardholder data
        # This would require knowledge of which apps contain cardholder data
        
        # PCI DSS 4.0 Requirement 8.6.1: Session management
        if ($Policy.conditions.applications.includeApplications -contains "All" -and
            (!$Policy.sessionControls -or !$Policy.sessionControls.signInFrequency.isEnabled)) {
            if ($DetailedAnalysis) {
                $issues += "PCI 8.6.1: No session timeout controls - PCI DSS requires session timeout for inactive sessions"
            } else {
                $issues += "PCI 8.6.1: No session timeout controls"
            }
        } elseif ($Policy.conditions.applications.includeApplications -contains "All" -and
                 $Policy.sessionControls -and $Policy.sessionControls.signInFrequency.isEnabled) {
            if ($IncludeCompliantStatus) {
                $compliances += "PCI 8.6.1:PASS - Policy implements session timeout controls"
            }
        }
    }
    
    # MITRE ATT&CK Framework checks
    if ($Framework -eq "All" -or $Framework -eq "MITRE") {
        # T1078: Valid Accounts
        # Check for policies that don't enforce MFA or device compliance
        if ($Policy.conditions.applications.includeApplications -contains "All" -and
            $Policy.grantControls.builtInControls -notcontains "mfa" -and
            $Policy.grantControls.builtInControls -notcontains "compliantDevice") {
            if ($DetailedAnalysis) {
                $issues += "MITRE T1078: Vulnerable to Valid Accounts technique - Consider requiring MFA or device compliance to prevent account takeover"
            } else {
                $issues += "MITRE T1078: Vulnerable to Valid Accounts technique"
            }
        } elseif ($Policy.conditions.applications.includeApplications -contains "All" -and
                 ($Policy.grantControls.builtInControls -contains "mfa" -or
                  $Policy.grantControls.builtInControls -contains "compliantDevice")) {
            if ($IncludeCompliantStatus) {
                $compliances += "MITRE T1078:PASS - Policy mitigates account takeover risk through MFA or device compliance"
            }
        }
        
        # T1111: Multi-factor Authentication Interception
        # Check for policies using weaker forms of MFA without phishing resistance
        if ($Policy.grantControls.builtInControls -contains "mfa" -and
            (!$Policy.conditions.authenticationStrength -or 
             $Policy.conditions.authenticationStrength.authenticationStrength -ne "phishingResistant")) {
            if ($DetailedAnalysis) {
                $issues += "MITRE T1111: Vulnerable to MFA Interception - Consider requiring phishing-resistant authentication methods"
            } else {
                $issues += "MITRE T1111: Vulnerable to MFA Interception"
            }
        } elseif ($Policy.grantControls.builtInControls -contains "mfa" -and
                 $Policy.conditions.authenticationStrength -and
                 $Policy.conditions.authenticationStrength.authenticationStrength -eq "phishingResistant") {
            if ($IncludeCompliantStatus) {
                $compliances += "MITRE T1111:PASS - Policy requires phishing-resistant authentication"
            }
        }
        
        # T1556: Modify Authentication Process
        # Check for policies that allow legacy authentication
        if (!$Policy.conditions.clientAppTypes -or
            $Policy.conditions.clientAppTypes -notcontains "other" -or
            $Policy.grantControls.builtInControls -notcontains "block") {
            if ($DetailedAnalysis) {
                $issues += "MITRE T1556: Vulnerable to authentication bypass - Consider blocking legacy authentication methods"
            } else {
                $issues += "MITRE T1556: Vulnerable to authentication bypass"
            }
        } elseif ($Policy.conditions.clientAppTypes -contains "other" -and
                 $Policy.grantControls.builtInControls -contains "block" -or
                 ($Policy.displayName -match "Block legacy authentication" -and 
                  $Policy.state -eq "enabled" -and
                  $Policy.grantControls.builtInControls -contains "block")) {
            if ($IncludeCompliantStatus) {
                $compliances += "MITRE T1556:PASS - Policy blocks legacy authentication methods"
            }
        }
    }

    # If AllPolicies is provided, perform cross-policy checks
    if ($AllPolicies) {
        # MT.1005 - Emergency account exclusions
        $emergencyAccountsExcluded = $false
        # This requires knowledge of which accounts are emergency accounts
        # For now, we'll just check if there are consistent exclusions across policies
        
        # MT.1035 - Protected security groups
        # This requires knowledge of which groups are protected by RMAU
        # For implementation in a future version
        
        # MT.1036 - Check for exclusion gaps
        # This requires detailed cross-policy analysis
        # For implementation in a future version
        
        # MT.1049 - Sign-in risk and user risk in separate policies
        if ($Policy.conditions.signInRiskLevels -and $Policy.conditions.userRiskLevels) {
            if ($DetailedAnalysis) {
                $issues += "Both sign-in risk and user risk conditions in same policy - These should be separate policies for better granularity"
            } else {
                $issues += "Both sign-in risk and user risk conditions in same policy"
            }
        }
    }

    # Return both issues and compliance statuses
    if ($IncludeCompliantStatus) {
        return @{
            Issues = $issues
            Compliance = $compliances
        }
    } else {
        return $issues
    }
} 