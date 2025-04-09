function Get-PolicyPattern {
    <#
    .SYNOPSIS
        Classifies a Conditional Access policy by its pattern.
    
    .DESCRIPTION
        The Get-PolicyPattern function analyzes a Conditional Access policy
        and classifies it according to its application scope, platform
        coverage, client types, and implemented controls. This provides
        a foundation for pattern-based analysis across policies.
    
    .PARAMETER Policy
        The Conditional Access policy object to analyze.
    
    .EXAMPLE
        Get-PolicyPattern -Policy $caPolicy
        
        Returns a pattern object classifying the given policy.
    
    .OUTPUTS
        Returns a hashtable with the following properties:
        - apps: Application coverage ("All Apps" or "Specific Apps")
        - platform: Platform coverage ("All Platforms" or "Specific Platforms")
        - clientTypes: Client type coverage ("All Clients" or "Specific Clients")
        - controls: Array of control types implemented (e.g., "MFA", "App Restrictions", etc.)
    
    .NOTES
        This function is used internally by the Get-CAPolicyAnalysis function
        to categorize policies for pattern-based reporting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias("InputObject")]
        [PSCustomObject]$Policy
    )
    
    # Initialize the pattern object
    $pattern = @{
        apps = "Specific Apps"
        platform = "Specific Platforms"
        controls = @()
        clientTypes = "Specific Clients"
        locations = "No Location Context"
        userRisk = "No User Risk Context"
        signInRisk = "No Sign-in Risk Context"
        deviceFilters = "No Device Filters"
    }

    # Determine application scope
    if ($Policy.conditions.applications.includeApplications -eq "All") {
        $pattern.apps = "All Apps"
    } elseif ($Policy.conditions.applications.includeUserActions.Count -gt 0) {
        $pattern.apps = "User Actions"
        # Add specific user action if recognized
        $action = $Policy.conditions.applications.includeUserActions[0]
        switch ($action) {
            "urn:user:registerdevice" { $pattern.apps = "User Action: Register Device" }
            "urn:user:registersecurityinfo" { $pattern.apps = "User Action: Register Security Info" }
            default { $pattern.apps = "User Action: $action" }
        }
    }

    # Determine platform scope
    if (!$Policy.conditions.platforms -or 
        !$Policy.conditions.platforms.includePlatforms -or
        $Policy.conditions.platforms.includePlatforms -eq "All" -or
        $Policy.conditions.platforms.includePlatforms -contains "All") {
        $pattern.platform = "All Platforms"
    } elseif ($Policy.conditions.platforms.includePlatforms.Count -gt 0) {
        $platformList = @($Policy.conditions.platforms.includePlatforms)
        if ($platformList.Count -le 2) {
            $pattern.platform = "Platforms: $($platformList -join ', ')"
        } else {
            $pattern.platform = "Platforms: Multiple ($($platformList.Count))"
        }
    }

    # Determine client types
    if ($Policy.conditions.clientAppTypes -contains "all") {
        $pattern.clientTypes = "All Clients"
    } elseif ($Policy.conditions.clientAppTypes.Count -gt 0) {
        if ($Policy.conditions.clientAppTypes.Count -eq 1) {
            $pattern.clientTypes = "Client: $($Policy.conditions.clientAppTypes[0])"
        } else {
            $pattern.clientTypes = "Clients: Multiple ($($Policy.conditions.clientAppTypes.Count))"
        }
    }

    # Determine location context
    if ($Policy.conditions.locations) {
        if ($Policy.conditions.locations.includeLocations -contains "All") {
            if ($Policy.conditions.locations.excludeLocations.Count -gt 0) {
                $pattern.locations = "All Locations Except Some"
            } else {
                $pattern.locations = "All Locations"
            }
        } elseif ($Policy.conditions.locations.includeLocations.Count -gt 0) {
            $pattern.locations = "Specific Locations"
        }
    }

    # Determine user risk context
    if ($Policy.conditions.userRiskLevels -and $Policy.conditions.userRiskLevels.Count -gt 0) {
        $pattern.userRisk = "User Risk: $($Policy.conditions.userRiskLevels -join ', ')"
    }

    # Determine sign-in risk context
    if ($Policy.conditions.signInRiskLevels -and $Policy.conditions.signInRiskLevels.Count -gt 0) {
        $pattern.signInRisk = "Sign-in Risk: $($Policy.conditions.signInRiskLevels -join ', ')"
    }

    # Determine device filters
    if ($Policy.conditions.devices -and $Policy.conditions.devices.deviceFilter) {
        $pattern.deviceFilters = "Has Device Filters"
    }

    # Determine controls
    # Grant controls
    if ($Policy.grantControls) {
        if ($Policy.grantControls.builtInControls -contains "block") {
            $pattern.controls += "Block"
        } elseif ($Policy.grantControls.builtInControls -contains "mfa") {
            $pattern.controls += "MFA"
        }
        
        if ($Policy.grantControls.builtInControls -contains "compliantDevice") {
            $pattern.controls += "Compliant Device"
        }
        
        if ($Policy.grantControls.builtInControls -contains "domainJoinedDevice") {
            $pattern.controls += "Domain Joined Device"
        }
        
        if ($Policy.grantControls.builtInControls -contains "approvedApplication") {
            $pattern.controls += "Approved Application"
        }
        
        if ($Policy.grantControls.builtInControls -contains "passwordChange") {
            $pattern.controls += "Password Change"
        }
        
        if ($Policy.grantControls.authenticationStrength) {
            $pattern.controls += "Authentication Strength"
        }
        
        if ($Policy.grantControls.operator -eq "AND") {
            # Only add if there are multiple conditions to be ANDed together
            if ($Policy.grantControls.builtInControls.Count -gt 1 -or 
                ($Policy.grantControls.builtInControls.Count -ge 1 -and $Policy.grantControls.authenticationStrength)) {
                $pattern.controls += "All Controls Required"
            }
        } elseif ($Policy.grantControls.operator -eq "OR") {
            # Only add if there are multiple conditions to be ORed together
            if ($Policy.grantControls.builtInControls.Count -gt 1 -or 
                ($Policy.grantControls.builtInControls.Count -ge 1 -and $Policy.grantControls.authenticationStrength)) {
                $pattern.controls += "Any Control Sufficient"
            }
        }
    }
    
    # Session controls
    if ($Policy.sessionControls) {
        if ($Policy.sessionControls.applicationEnforcedRestrictions.isEnabled) {
            $pattern.controls += "App Restrictions"
        }
        
        if ($Policy.sessionControls.cloudAppSecurity.isEnabled) {
            $pattern.controls += "MCAS"
        }
        
        if ($Policy.sessionControls.signInFrequency.isEnabled) {
            $pattern.controls += "Sign-in Frequency"
        }
        
        if ($Policy.sessionControls.persistentBrowser.isEnabled) {
            $pattern.controls += "Persistent Browser"
        }
    }
    
    # If no specific controls have been identified, mark as "No Controls"
    if ($pattern.controls.Count -eq 0) {
        $pattern.controls += "No Controls"
    }

    return $pattern
} 