function Get-CAPolicyAnalysis {
    <#
    .SYNOPSIS
        Analyzes Conditional Access policies to identify patterns, statistics, and potential issues.
    
    .DESCRIPTION
        This function analyzes Conditional Access policies to generate comprehensive reports,
        including policy patterns, statistics, temporal analysis, and detailed information
        about each policy.
    
    .PARAMETER Policies
        The Conditional Access policies to analyze. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy JSON files.
        
    .PARAMETER OutputPath
        The path where analysis reports will be saved. Defaults to "analysis/markdown".
    
    .PARAMETER OutputFormat
        The format of the analysis output. Can be "Markdown" or "JSON". Defaults to "Markdown".
    
    .EXAMPLE
        Get-CAPolicy | Get-CAPolicyAnalysis -OutputPath "./reports" -OutputFormat "Markdown"
    
    .EXAMPLE
        Get-CAPolicyAnalysis -Path "./policies/data" -OutputFormat "JSON"
    
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
        [ValidateSet("Markdown", "JSON")]
        [string]$OutputFormat = "Markdown"
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
        
        # Perform analysis
        $analysis = @{
            patterns = @{}
            stats = @{
                totalPolicies = $allPolicies.Count
                byState = @{}
                byControl = @{}
            }
        }
        
        # Initialize the pattern summary object
        $analysis.PatternSummary = @()
        
        # Analyze patterns and collect statistics
        foreach ($policy in $allPolicies) {
            # Get pattern - use the fully qualified function name to avoid recursion
            # IMPORTANT: Don't call the local Get-PolicyPattern function to avoid recursion
            $pattern = & (Get-Command -Name Get-PolicyPattern -Module CAReports) -Policy $policy
            $patternKey = "$($pattern.apps) - $($pattern.controls -join '+') - $($pattern.platform) - $($pattern.clientTypes)"
            
            if (!$analysis.patterns[$patternKey]) {
                $analysis.patterns[$patternKey] = @()
            }
            $analysis.patterns[$patternKey] += $policy.displayName
        
            # Update stats
            if (-not $analysis.stats.byState[$policy.state]) {
                $analysis.stats.byState[$policy.state] = 0
            }
            $analysis.stats.byState[$policy.state]++
            
            foreach ($control in $pattern.controls) {
                if (-not $analysis.stats.byControl[$control]) {
                    $analysis.stats.byControl[$control] = 0
                }
                $analysis.stats.byControl[$control]++
            }
        }
        
        # Add pattern summary for easier consumption
        $analysis.PatternSummary = $analysis.patterns.Keys | ForEach-Object {
            [PSCustomObject]@{
                Pattern = $_
                Count = $analysis.patterns[$_].Count
                Policies = $analysis.patterns[$_] -join ", "
            }
        }
        
        # Generate temporal analysis
        # Skip this for now as it's not clear what the actual implementation is
        $analysis.temporal = @{
            recentChanges = @()
            oldestPolicies = @()
            newestPolicies = @()
        }
        
        # Generate security analysis (simplified for now)
        $securityIssues = @{}
        
        # Generate output based on format
        if ($OutputFormat -eq "JSON") {
            $output = $analysis | ConvertTo-Json -Depth 10
            if (![string]::IsNullOrEmpty($OutputPath)) {
                $output | Out-File (Join-Path $OutputPath "analysis_report.json")
            }
        }
        else { # Markdown format
            $output = Get-PolicyAnalysisReport -policies $allPolicies
            if (![string]::IsNullOrEmpty($OutputPath)) {
                $output | Out-File (Join-Path $OutputPath "policy_analysis.md")
            }
        }
        
        # Return the analysis object
        return $analysis
    }
}

# Do not include the local helper functions in this file - they're already in Private folder 

# Add these helper functions back to the file to restore the detailed report generation

# Function to generate emoji indicators for policy state
function Get-StateEmoji {
    param($state)
    switch ($state) {
        "enabled" { "✅" }
        "enabledForReportingButNotEnforced" { "🔄" }
        "disabled" { "❌" }
        default { "❓" }
    }
}

# Function to generate emoji indicators for user scope
function Get-UserScopeEmoji {
    param($policy)
    
    $parts = @()
    
    # Handle Users
    $includeUsers = if ($policy.conditions.users.includeUsers -contains "All") { 
        "All"
    } else {
        $count = if ($policy.conditions.users.includeUsers) {
            @($policy.conditions.users.includeUsers | Where-Object { $_ -ne "All" }).Count
        } else { 0 }
        $count.ToString()
    }
    $excludeUsers = if ($policy.conditions.users.excludeUsers) {
        @($policy.conditions.users.excludeUsers.PSObject.Properties).Count
    } else { 0 }
    if ($includeUsers -ne "0" -or $excludeUsers -gt 0) {
        $parts += "👤 ($includeUsers, $excludeUsers)"
    }
    
    # Handle Groups
    $includeGroups = if ($policy.conditions.users.includeGroups) {
        @($policy.conditions.users.includeGroups.PSObject.Properties).Count
    } else { 0 }
    $excludeGroups = if ($policy.conditions.users.excludeGroups) {
        @($policy.conditions.users.excludeGroups.PSObject.Properties).Count
    } else { 0 }
    if ($includeGroups -gt 0 -or $excludeGroups -gt 0) {
        $parts += "👥 ($includeGroups, $excludeGroups)"
    }
    
    # Handle Roles
    $includeRoles = if ($policy.conditions.users.includeRoles) {
        @($policy.conditions.users.includeRoles.PSObject.Properties).Count
    } else { 0 }
    $excludeRoles = if ($policy.conditions.users.excludeRoles) {
        @($policy.conditions.users.excludeRoles.PSObject.Properties).Count
    } else { 0 }
    if ($includeRoles -gt 0 -or $excludeRoles -gt 0) {
        $parts += "🎯 ($includeRoles, $excludeRoles)"
    }

    # Handle Guests/External Users
    if ($null -ne $policy.conditions.users.includeGuestsOrExternalUsers -or 
        $null -ne $policy.conditions.users.excludeGuestsOrExternalUsers) {
        $includeGuests = if ($policy.conditions.users.includeGuestsOrExternalUsers) { "1" } else { "0" }
        $excludeGuests = if ($policy.conditions.users.excludeGuestsOrExternalUsers) { "1" } else { "0" }
        $parts += "🥷 ($includeGuests, $excludeGuests)"
    }
    
    if ($parts.Count -eq 0) {
        return "👤 (0, 0)"
    }
    
    return ($parts -join ", ")
}

# Function to generate emoji indicators for app scope
function Get-AppScopeEmoji {
    param($policy)
    
    # Handle User Actions separately
    if ($policy.conditions.applications.includeUserActions.Count -gt 0) {
        $action = switch ($policy.conditions.applications.includeUserActions[0]) {
            "urn:user:registerdevice" { "Register Device" }
            "urn:user:registersecurityinfo" { "Register Security Info" }
            default { $_ }
        }
        return "📱 User Action: $action"
    }

    # Get counts and names for included apps
    $includeApps = if ($policy.conditions.applications.includeApplications -is [Array]) {
        @($policy.conditions.applications.includeApplications)
    } else {
        @($policy.conditions.applications.includeApplications.PSObject.Properties)
    }

    # Get counts and names for excluded apps
    $excludeApps = if ($policy.conditions.applications.excludeApplications) {
        if ($policy.conditions.applications.excludeApplications -is [Array]) {
            @($policy.conditions.applications.excludeApplications)
        } else {
            @($policy.conditions.applications.excludeApplications.PSObject.Properties)
        }
    } else {
        @()
    }
    
    # Format the include/exclude display
    if ($includeApps -contains "All") {
        if ($excludeApps.Count -eq 1) {
            $excludeName = if ($excludeApps[0].Value.displayName) {
                $excludeApps[0].Value.displayName
            } else {
                $excludeApps[0]
            }
            return "🌐 (All, $excludeName)"
        }
        return "🌐 (All, $($excludeApps.Count))"
    }
    
    # Handle object-style includeApplications
    if ($includeApps.Count -eq 1) {
        if ($includeApps[0].Value.displayName) {
            return "🌐 ($($includeApps[0].Value.displayName), $($excludeApps.Count))"
        }
        elseif ($includeApps[0] -and $includeApps[0] -ne "All") {
            return "🌐 ($($includeApps[0]), $($excludeApps.Count))"
        }
    }
    
    return "🌐 ($($includeApps.Count), $($excludeApps.Count))"
}

# Function to generate emoji indicators for controls
function Get-ControlsEmoji {
    param($policy)
    $controls = @()
    
    # Handle grant controls
    if ($policy.grantControls.builtInControls) {
        if ($policy.grantControls.builtInControls -contains "mfa") {
            $controls += "🔐 MFA"
        }
        if ($policy.grantControls.builtInControls -contains "compliantDevice") {
            $controls += "📱 Compliant"
        }
        if ($policy.grantControls.builtInControls -contains "domainJoinedDevice") {
            $controls += "💻 Domain Joined"
        }
    }

    # Handle session controls
    if ($policy.sessionControls.applicationEnforcedRestrictions.isEnabled) {
        $controls += "🔒 App Enforced"
    }
    if ($policy.sessionControls.cloudAppSecurity.isEnabled) {
        $controls += "✨ MCAS"
    }
    if ($policy.sessionControls.persistentBrowser.isEnabled) {
        $controls += "🌐 No Persist"
    }
    if ($policy.sessionControls.signInFrequency.isEnabled) {
        $freq = "$($policy.sessionControls.signInFrequency.value) $($policy.sessionControls.signInFrequency.frequencyInterval)"
        $controls += "⏱️ Sign-in: $freq"
    }

    if ($controls.Count -eq 0) {
        $controls += "⚪ None"
    }

    # Add operator if multiple grant controls
    if ($policy.grantControls.builtInControls -and 
        $policy.grantControls.builtInControls.Count -gt 1) {
        $controls += "($($policy.grantControls.operator))"
    }

    return ($controls -join ", ")
}

# Function to get key conditions
function Get-KeyConditions {
    param($policy)
    $conditions = @()
    if ($policy.conditions.locations) {
        $conditions += "🏢 Location Based"
    }
    if ($policy.conditions.platforms -or $policy.conditions.devices.deviceFilter) {
        $conditions += "💻 Platform/Device Requirements"
    }
    # Add Client App Types condition
    if ($policy.conditions.clientAppTypes -and 
        $policy.conditions.clientAppTypes -notcontains "all") {
        $conditions += "📱 Client Apps: $($policy.conditions.clientAppTypes -join ', ')"
    }
    if ($conditions.Count -eq 0) {
        return "None"
    }
    return ($conditions -join ", ")
}

# Function for temporal analysis
function Get-TemporalAnalysis {
    param($policies)
    
    $now = Get-Date
    $lastMonth = $now.AddDays(-30)
    
    # Get recent changes
    $recentChanges = $policies | Where-Object { 
        $null -ne $_.modifiedDateTime -and [DateTime]$_.modifiedDateTime -ge $lastMonth 
    } | ForEach-Object {
        $modified = [DateTime]$_.modifiedDateTime
        $daysSince = [math]::Round(($now - $modified).TotalDays, 1)
        [PSCustomObject]@{
            Policy = $_.displayName
            Modified = $modified
            DaysSinceChange = $daysSince
        }
    }
    
    # Get recently created policies
    $newPolicies = $policies | Where-Object { 
        $null -ne $_.createdDateTime -and [DateTime]$_.createdDateTime -ge $lastMonth 
    } | ForEach-Object {
        $created = [DateTime]$_.createdDateTime
        $daysOld = [math]::Round(($now - $created).TotalDays, 1)
        [PSCustomObject]@{
            Policy = $_.displayName
            Created = $created
            DaysOld = $daysOld
        }
    }
    
    # Get oldest policies
    $oldestPolicies = $policies | Where-Object { 
        $null -ne $_.createdDateTime 
    } | Sort-Object { [DateTime]$_.createdDateTime } | Select-Object -First 5 | ForEach-Object {
        $created = [DateTime]$_.createdDateTime
        $daysOld = [math]::Round(($now - $created).TotalDays, 1)
        [PSCustomObject]@{
            Policy = $_.displayName
            Created = $created
            DaysOld = $daysOld
        }
    }
    
    # Get newest policies
    $newestPolicies = $policies | Where-Object { 
        $null -ne $_.createdDateTime 
    } | Sort-Object { [DateTime]$_.createdDateTime } -Descending | Select-Object -First 5 | ForEach-Object {
        $created = [DateTime]$_.createdDateTime
        $daysOld = [math]::Round(($now - $created).TotalDays, 1)
        [PSCustomObject]@{
            Policy = $_.displayName
            Created = $created
            DaysOld = $daysOld
        }
    }
    
    return [PSCustomObject]@{
        RecentChanges = $recentChanges
        NewPolicies = $newPolicies
        OldestPolicies = $oldestPolicies
        NewestPolicies = $newestPolicies
    }
}

# Function to format table rows
function Get-FormattedTableRow {
    param($policy)
    $state = Get-StateEmoji -state $policy.state
    $users = Get-UserScopeEmoji -policy $policy
    $apps = Get-AppScopeEmoji -policy $policy
    $controls = Get-ControlsEmoji -policy $policy
    $conditions = Get-KeyConditions -policy $policy
    
    # Create link to policy section using policy name as anchor
    $policyLink = $policy.displayName -replace '[^a-zA-Z0-9\s-]', '' -replace '\s+', '-'
    "| [$($policy.displayName)](#$($policyLink.ToLower())) | $state | $users | $apps | $controls | $conditions |"
}

# Function to get non-empty conditions
function Get-NonEmptyConditions {
    param($policy)
    
    $conditions = @{}

    # User Configuration
    $userConfig = @{}
    if ($policy.conditions.users.includeUsers) {
        $userConfig['Include Users'] = $policy.conditions.users.includeUsers -contains "All" ? 
            "All Users" : (Get-CleanValue $policy.conditions.users.includeUsers "users")
    }
    if ($policy.conditions.users.excludeUsers.PSObject.Properties.Count -gt 0) {
        $userConfig['Exclude Users'] = Get-CleanValue $policy.conditions.users.excludeUsers "users"
    }
    if ($policy.conditions.users.includeGroups.PSObject.Properties.Count -gt 0) {
        $userConfig['Include Groups'] = Get-CleanValue $policy.conditions.users.includeGroups "groups"
    }
    if ($policy.conditions.users.excludeGroups.PSObject.Properties.Count -gt 0) {
        $userConfig['Exclude Groups'] = Get-CleanValue $policy.conditions.users.excludeGroups "groups"
    }
    if ($policy.conditions.users.includeRoles.PSObject.Properties.Count -gt 0) {
        $userConfig['Include Roles'] = Get-CleanValue $policy.conditions.users.includeRoles "roles"
    }
    if ($policy.conditions.users.excludeRoles.PSObject.Properties.Count -gt 0) {
        $userConfig['Exclude Roles'] = Get-CleanValue $policy.conditions.users.excludeRoles "roles"
    }
    if ($userConfig.Count -gt 0) {
        $conditions['User Configuration'] = $userConfig
    }

    # Application Configuration
    $appConfig = @{}
    if ($policy.conditions.applications.includeApplications) {
        $appConfig['Include Apps'] = $policy.conditions.applications.includeApplications -contains "All" ? 
            "All Applications" : (Get-CleanValue $policy.conditions.applications.includeApplications "apps")
    }
    if ($policy.conditions.applications.excludeApplications.PSObject.Properties.Count -gt 0) {
        $appConfig['Exclude Apps'] = Get-CleanValue $policy.conditions.applications.excludeApplications "apps"
    }
    if ($policy.conditions.applications.includeUserActions) {
        $appConfig['User Actions'] = $policy.conditions.applications.includeUserActions -join ", "
    }
    if ($appConfig.Count -gt 0) {
        $conditions['Application Configuration'] = $appConfig
    }

    # Properly get client app types
    if ($policy.conditions.clientAppTypes) {
        $conditions['Client App Types'] = $policy.conditions.clientAppTypes
    }

    # Platform Requirements
    if ($policy.conditions.platforms) {
        $platformConfig = @{}
        if ($policy.conditions.platforms.includePlatforms) {
            $platformConfig['Include Platforms'] = $policy.conditions.platforms.includePlatforms -contains "all" ? 
                "All Platforms" : ($policy.conditions.platforms.includePlatforms | ForEach-Object { 
                    if ($_.Length -gt 0) {
                        try { $_.Substring(0,1).ToUpper() + $_.Substring(1) } 
                        catch { $_ } 
                    } else { $_ }
                })
        }
        if ($policy.conditions.platforms.excludePlatforms) {
            $platformConfig['Exclude Platforms'] = $policy.conditions.platforms.excludePlatforms | ForEach-Object { 
                if ($_.Length -gt 0) {
                    try { $_.Substring(0,1).ToUpper() + $_.Substring(1) } 
                    catch { $_ } 
                } else { $_ }
            }
        }
        if ($platformConfig.Count -gt 0) {
            $conditions['Platform Requirements'] = $platformConfig
        }
    }

    # Location Conditions
    if ($policy.conditions.locations) {
        $locationConfig = @{}
        if ($policy.conditions.locations.includeLocations) {
            $locationConfig['Include Locations'] = $policy.conditions.locations.includeLocations
        }
        if ($policy.conditions.locations.excludeLocations) {
            $locationConfig['Exclude Locations'] = $policy.conditions.locations.excludeLocations
        }
        if ($locationConfig.Count -gt 0) {
            $conditions['Location Configuration'] = $locationConfig
        }
    }

    # Access Controls
    $controls = @()
    if ($policy.grantControls.builtInControls) {
        $controls += "Grant Controls: $($policy.grantControls.builtInControls -join ', ')"
    }
    if ($policy.sessionControls.applicationEnforcedRestrictions.isEnabled) {
        $controls += "Session Controls: Application Enforced Restrictions"
    }
    if ($controls.Count -gt 0) {
        $conditions['Access Controls'] = $controls
    }

    # State
    if ($policy.state) {
        $conditions['State'] = $policy.state
    }

    return $conditions
}

# Function for cleaning values
function Get-CleanValue {
    param(
        $value,
        [string]$type = "default"
    )
    
    if ($value -is [array]) {
        return "$($value.Count) items: $($value -join ', ')"
    }
    
    if ($value.PSObject.Properties) {
        $count = @($value.PSObject.Properties).Count
        $sampleNames = @($value.PSObject.Properties | Select-Object -First 3 | ForEach-Object {
            if ($null -ne $_.Value.displayName) { $_.Value.displayName } else { $_.Name }
        })
        $namesText = if ($sampleNames.Count -gt 0) { " ($($sampleNames -join ', ')...)" } else { "" }
        
        switch ($type) {
            "users" { return "$count users$namesText" }
            "groups" { return "$count groups$namesText" }
            "roles" { return "$count roles$namesText" }
            "apps" { return "$count applications$namesText" }
            default { return "$count items$namesText" }
        }
    }
    
    return $value
}

# Function to format markdown sections
function Format-MarkdownSection {
    param($title, $content)
    @"

#### $title
$content
"@
}

# Function to generate policy analysis report
function Get-PolicyAnalysisReport {
    param($policies)
    
    # Calculate pattern counts with all required fields
    $patternCounts = @{
        blockPolicies = @($policies | Where-Object { 
            $null -ne $_.grantControls -and 
            $null -ne $_.grantControls.builtInControls -and 
            $_.grantControls.builtInControls -contains "block" 
        }).Count
        allowPolicies = @($policies | Where-Object { 
            $null -eq $_.grantControls -or
            $null -eq $_.grantControls.builtInControls -or
            $_.grantControls.builtInControls -notcontains "block" 
        }).Count
        active = @($policies | Where-Object { $_.state -eq "enabled" }).Count
        reportOnly = @($policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count
        disabled = @($policies | Where-Object { $_.state -eq "disabled" }).Count
        mfaPolicies = @($policies | Where-Object { 
            $null -ne $_.grantControls -and 
            $null -ne $_.grantControls.builtInControls -and 
            $_.grantControls.builtInControls -contains "mfa" 
        }).Count
        compliantDevice = @($policies | Where-Object { 
            $null -ne $_.grantControls -and 
            $null -ne $_.grantControls.builtInControls -and 
            $_.grantControls.builtInControls -contains "compliantDevice" 
        }).Count
        domainJoined = @($policies | Where-Object { 
            $null -ne $_.grantControls -and 
            $null -ne $_.grantControls.builtInControls -and 
            $_.grantControls.builtInControls -contains "domainJoinedDevice" 
        }).Count
        mcasControls = @($policies | Where-Object { 
            $null -ne $_.sessionControls -and 
            $null -ne $_.sessionControls.cloudAppSecurity -and 
            $_.sessionControls.cloudAppSecurity.isEnabled 
        }).Count
        deviceFilters = @($policies | Where-Object { 
            $null -ne $_.conditions -and 
            $null -ne $_.conditions.devices -and 
            $null -ne $_.conditions.devices.deviceFilter 
        }).Count
        allApps = @($policies | Where-Object { 
            $null -ne $_.conditions -and 
            $null -ne $_.conditions.applications -and 
            $null -ne $_.conditions.applications.includeApplications -and 
            $_.conditions.applications.includeApplications -contains "All" 
        }).Count
        locationBased = @($policies | Where-Object { $null -ne $_.conditions.locations }).Count
        signInFrequency = @($policies | Where-Object { 
            $null -ne $_.sessionControls -and 
            $null -ne $_.sessionControls.signInFrequency -and 
            $_.sessionControls.signInFrequency.isEnabled 
        }).Count
        persistentBrowser = @($policies | Where-Object { 
            $null -ne $_.sessionControls -and 
            $null -ne $_.sessionControls.persistentBrowser -and 
            $_.sessionControls.persistentBrowser.isEnabled 
        }).Count
    }

    # Build sections
    $headerSection = @"
# Conditional Access Policy Analysis

## Legend
- ✅ Active Policy
- 🔄 Report-Only Policy
- ❌ Disabled Policy
- 👤 Users (included, excluded)
- 👥 Groups (included, excluded)
- 🎯 Roles (included, excluded)
- 🥷 Guests (included, excluded)
- 🌐 Applications (included, excluded)
- 📱 User Actions, Client Apps & Device Compliance
- 💻 Domain Joined Devices & Platform Requirements
- 🔐 MFA Required
- 🔒 App Enforced Restrictions
- ✨ MCAS Controls
- ⏱️ Sign-in Frequency
- ⚪ No Controls
- 🏢 Location Based

## Policy Overview
| Policy Name | State | Users | Apps | Controls | Key Conditions |
|-------------|-------|-------|------|----------|----------------|
"@

    $tableSection = ($policies | ForEach-Object { Get-FormattedTableRow -policy $_ }) -join "`n"

    $patternsSection = @"

## Policy Patterns Found

Total Policies: $($policies.Count)

Policy States:
- Active policies: $($patternCounts.active) policies
- Report-only mode: $($patternCounts.reportOnly) policies
- Disabled: $($patternCounts.disabled) policies

Access Controls:
- Allow Access: $($patternCounts.allowPolicies) policies
- Block Access: $($patternCounts.blockPolicies) policies
- MFA required: $($patternCounts.mfaPolicies) policies
- Compliant device required: $($patternCounts.compliantDevice) policies
- Domain joined device required: $($patternCounts.domainJoined) policies

Session Controls:
- MCAS monitoring: $($patternCounts.mcasControls) policies
- Sign-in frequency set: $($patternCounts.signInFrequency) policies
- Browser persistence configured: $($patternCounts.persistentBrowser) policies

Conditions:
- All applications: $($patternCounts.allApps) policies
- Location-based conditions: $($patternCounts.locationBased) policies
- Device filters: $($patternCounts.deviceFilters) policies

"@

    # Fix formatting in detailed conditions section
    $detailsSection = ($policies | ForEach-Object {
        $conditions = Get-NonEmptyConditions -policy $_
        $policyLink = $_.displayName -replace '[^a-zA-Z0-9\s-]', '' -replace '\s+', '-'
        $policyDetails = "`n### [$($_.displayName)](#$($policyLink.ToLower()))"
        foreach ($section in $conditions.Keys) {
            $content = if ($conditions[$section] -is [array]) {
                ($conditions[$section] | ForEach-Object { "- $_" }) -join "`n"
            }
            elseif ($conditions[$section] -is [hashtable]) {
                ($conditions[$section].GetEnumerator() | ForEach-Object { 
                    "- $($_.Key): $($_.Value)" 
                }) -join "`n"
            }
            else {
                "- $($conditions[$section])"
            }
            $policyDetails += (Format-MarkdownSection -title $section -content $content)
        }
        $policyDetails
    }) -join "`n"

    # Get temporal analysis
    $temporal = Get-TemporalAnalysis -policies $policies
    $temporalSection = @"

## Temporal Analysis

### Policy State Distribution
| State | Count | Percentage |
|-------|-------|------------|
| Enabled | $($patternCounts.active) | $([math]::Round($patternCounts.active/$policies.Count * 100, 1))% |
| Report-Only | $($patternCounts.reportOnly) | $([math]::Round($patternCounts.reportOnly/$policies.Count * 100, 1))% |
| Disabled | $($patternCounts.disabled) | $([math]::Round($patternCounts.disabled/$policies.Count * 100, 1))% |

### Recent Policy Changes
"@
    if ($temporal.RecentChanges) {
        $temporalSection += @"

| Policy Name | Days Since Change | Last Modified |
|-------------|------------------|---------------|
"@
        $temporal.RecentChanges | Sort-Object DaysSinceChange | ForEach-Object {
            $temporalSection += "`n| $($_.Policy) | $($_.DaysSinceChange) | $($_.Modified.ToString('yyyy-MM-dd')) |"
        }
    } else {
        $temporalSection += "`n- No recent changes detected in the last 30 days"
    }

    $temporalSection += @"

### New Policies (Last 30 Days)
"@
    if ($temporal.NewPolicies) {
        $temporalSection += @"

| Policy Name | Days Old | Created Date |
|-------------|----------|--------------|
"@
        $temporal.NewPolicies | Sort-Object DaysOld | ForEach-Object {
            $temporalSection += "`n| $($_.Policy) | $($_.DaysOld) | $($_.Created.ToString('yyyy-MM-dd')) |"
        }
    } else {
        $temporalSection += "`n- No new policies created in the last 30 days"
    }

    # Combine all sections
    $sections = @(
        $headerSection,
        $tableSection,
        $patternsSection,
        $detailsSection,
        $temporalSection
    )

    return ($sections -join "`n")
} 