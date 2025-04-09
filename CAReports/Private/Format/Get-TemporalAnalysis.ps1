function Get-TemporalAnalysis {
    <#
    .SYNOPSIS
        Analyzes the temporal aspects of Conditional Access policies.
    
    .DESCRIPTION
        This function analyzes the creation and modification dates of Conditional Access policies
        to identify new policies and recent changes within a specified timeframe (default 30 days).
    
    .PARAMETER Policies
        Array of Conditional Access policy objects to analyze.
    
    .PARAMETER DaysThreshold
        Number of days to consider for "recent" changes and additions. Default is 30.
    
    .EXAMPLE
        $temporal = Get-TemporalAnalysis -Policies $policies
    
    .NOTES
        This is an internal helper function used by the CAReports module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject[]]$Policies,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysThreshold = 30
    )
    
    $temporal = @{
        NewPolicies = @()
        RecentChanges = @()
    }
    
    # Get the threshold date
    $thresholdDate = (Get-Date).AddDays(-$DaysThreshold)
    
    # Analyze each policy's temporal aspects
    foreach ($policy in $Policies) {
        # Safely parse dates with error handling
        $created = $null
        $modified = $null
        
        if (![string]::IsNullOrEmpty($policy.createdDateTime)) {
            try {
                $created = [DateTime]::Parse($policy.createdDateTime)
            } catch {
                Write-Warning "Could not parse creation date for policy: $($policy.displayName)"
                continue
            }
        } else {
            Write-Warning "No creation date found for policy: $($policy.displayName)"
            continue
        }

        if (![string]::IsNullOrEmpty($policy.modifiedDateTime)) {
            try {
                $modified = [DateTime]::Parse($policy.modifiedDateTime)
            } catch {
                # If modified date is invalid, use created date
                $modified = $created
                Write-Warning "Using creation date as modification date for policy: $($policy.displayName)"
            }
        } else {
            # If no modified date exists, use created date
            $modified = $created
        }
        
        # Track new policies
        if ($created -gt $thresholdDate) {
            $temporal.NewPolicies += @{
                Policy = $policy.displayName
                Created = $created
                DaysOld = [Math]::Floor((New-TimeSpan -Start $created -End (Get-Date)).TotalDays)
            }
        }
        
        # Track recent modifications
        if ($modified -gt $thresholdDate -and $modified -ne $created) {
            $temporal.RecentChanges += @{
                Policy = $policy.displayName
                Modified = $modified
                DaysSinceChange = [Math]::Floor((New-TimeSpan -Start $modified -End (Get-Date)).TotalDays)
            }
        }
    }
    
    return $temporal
} 