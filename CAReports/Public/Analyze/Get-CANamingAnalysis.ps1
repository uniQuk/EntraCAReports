function Get-CANamingAnalysis {
    <#
    .SYNOPSIS
        Analyzes Conditional Access policies and suggests various naming conventions.
    
    .DESCRIPTION
        This function analyzes Conditional Access policies and suggests naming conventions
        based on different formats (Simple, Microsoft, and ASD). It helps standardize
        naming across the organization.
    
    .PARAMETER Policies
        The Conditional Access policies to analyze. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy JSON files.
        
    .PARAMETER ConfigPath
        The path to the naming rules configuration file. If not specified, uses the default
        configuration from the module's config directory.
        
    .PARAMETER OutputPath
        The path where the naming report will be saved. Defaults to "analysis/markdown".
    
    .PARAMETER OutputFormat
        The format of the naming report. Currently only supports "Markdown".
    
    .EXAMPLE
        Get-CAPolicy | Get-CANamingAnalysis -OutputPath "./reports"
    
    .EXAMPLE
        Get-CANamingAnalysis -Path "./policies/data" -ConfigPath "./config/custom-naming-rules.json"
    
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
        [string]$ConfigPath,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Markdown")]
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
        
        # Load naming rules configuration
        if ([string]::IsNullOrEmpty($ConfigPath)) {
            # Use default configuration
            $modulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
            $ConfigPath = Join-Path $modulePath "config/naming-rules.json"
        }
        
        # Check if config file exists
        if (!(Test-Path $ConfigPath)) {
            Write-Error "Configuration file not found at '$ConfigPath'. Please provide a valid path."
            return
        }
        
        # Load config
        $script:config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        
        # Add default values for missing configuration sections
        if (-not $script:config.asdTypes) {
            $script:config | Add-Member -MemberType NoteProperty -Name "asdTypes" -Value ([PSCustomObject]@{
                admin = "ADM"
                device = "DEV"
                guest = "GST"
                location = "LOC"
                default = "USR"
            })
        }
        
        if (-not $script:config.asdPurposes) {
            $script:config | Add-Member -MemberType NoteProperty -Name "asdPurposes" -Value ([PSCustomObject]@{
                admin = [PSCustomObject]@{
                    session = "SessionControls"
                    compliantDevice = "RequireCompliantDevice"
                    mfa = "RequireMFA"
                    block = "Block"
                }
                device = [PSCustomObject]@{
                    compliantDevice = "RequireCompliantDevice"
                    mfa = "RequireMFA"
                    block = "Block"
                }
                user = [PSCustomObject]@{
                    block = [PSCustomObject]@{
                        legacy = "BlockLegacyAuth"
                        risk = "BlockHighRisk"
                        default = "BlockAccess"
                    }
                    session = "SessionControls"
                    mfa = "RequireMFA"
                    compliantDevice = "RequireCompliantDevice"
                }
                guest = [PSCustomObject]@{
                    block = "BlockGuests"
                    session = "GuestSessionControls"
                    mfa = "GuestMFA"
                }
                location = [PSCustomObject]@{
                    block = "BlockUntrustedLocation"
                    mfa = "MFAFromUntrustedLocation"
                }
            })
        }
        
        # Create output directory if it doesn't exist
        if (![string]::IsNullOrEmpty($OutputPath)) {
            New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
        }
        
        # Initialize sequence counters
        $script:sequenceCounters = @{}
        $script:sequenceCounters["Simple"] = @{
            admin = 10
            device = 20
            default = 1
            emergency = 1
        }
        $script:sequenceCounters["MS"] = @{
            Global = 1
            Admins = 100
            Internals = 200
            GuestUsers = 400
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
        
        # Reset sequence counters before processing
        $script:sequenceCounters["Simple"].admin = 10
        $script:sequenceCounters["Simple"].device = 20
        $script:sequenceCounters["Simple"].default = 1
        $script:sequenceCounters["Simple"].emergency = 1
        $script:sequenceCounters["MS"].Global = 1
        $script:sequenceCounters["MS"].Admins = 100
        $script:sequenceCounters["MS"].Internals = 200
        $script:sequenceCounters["MS"].GuestUsers = 400
        
        # Generate different naming conventions
        $namedPolicies = $allPolicies | ForEach-Object {
            $policy = $_
            
            # Simple MS Format
            $seqNum = Get-SimpleSequenceNumber $policy
            $apps = Get-PolicyTarget $policy
            $response = Get-SimpleResponse $policy
            $users = Get-SimpleUsers $policy
            $conditions = Get-SimpleConditions $policy
            
            # Create Simple format with proper handling of empty components
            $conditionsPart = if ([string]::IsNullOrEmpty($conditions) -or $conditions -eq "NoConditions") { "" } else { "-$conditions" }
            $simpleFormat = "$seqNum-$apps-$response-$users$conditionsPart"
            
            # MS Format
            $persona = Get-PolicyPersona $policy
            $policyNumber = Get-PolicyNumber $persona  # Store policy number first
            $policyType = "BaseProtection"  # Could be enhanced based on policy analysis
            $target = Get-PolicyTarget $policy
            $platforms = Get-PolicyPlatforms $policy
            $controls = Get-PolicyControls $policy
            
            # Create MS format with proper handling of empty components
            $platformPart = if ([string]::IsNullOrEmpty($platforms)) { "" } else { "-$platforms" }
            $controlsPart = if ([string]::IsNullOrEmpty($controls)) { "" } else { "-$controls" }
            $msFormat = "$policyNumber-$persona-$policyType-$target$platformPart$controlsPart"
            
            # ASD Format
            $asdType = Get-ASDType $policy
            $asdAction = Get-ASDAction $policy
            $asdPurpose = Get-ASDPurpose $policy
            $asdFormat = "$asdType-$asdAction-$asdPurpose"
            
            @{
                OriginalName = $policy.displayName
                SimpleFormat = $simpleFormat
                MSFormat = $msFormat
                ASDFormat = $asdFormat
                Policy = $policy
            }
        }
        
        # Create report as a custom object for further processing
        $analysis = @{
            Policies = $namedPolicies
            SequenceCounters = $script:sequenceCounters
        }
        
        # Generate output based on format
        if ($OutputFormat -eq "Markdown") {
            $report = @"
# Conditional Access Policy Naming Conventions

## Policy Names Comparison

| Original Name | Simple Format | MS Format | ASD Format |
|--------------|---------------|-----------|------------|
$(($namedPolicies | ForEach-Object { 
    $originalName = $_.OriginalName
    $simpleFormat = $_.SimpleFormat
    $msFormat = $_.MSFormat
    $asdFormat = $_.ASDFormat
    "| $originalName | $simpleFormat | $msFormat | $asdFormat |"
}) -join "`n")

## Naming Convention Rules

### Simple MS Format: SequenceNumber-Apps-Response-Users[-Conditions]
- SequenceNumber: CA01-99 for regular policies, EM01-99 for emergency policies
- Apps: Target applications (AllApps, O365, etc.)
- Response: Policy action (Block, RequireMFA, etc.)
- Users: Target users (AllUsers, Admins, etc.)
- Conditions: Access conditions (ExternalAccess, Platforms, etc.) - optional

### MS Format: Persona-PolicyType-Target[-Platform][-Controls]
- Persona: Identifies the main user group (Global, Admins, Internals)
- PolicyType: The type of policy (BaseProtection, etc.)
- Target: The applications being targeted (AllApps or specific apps)
- Platform: Device platform requirements (optional)
- Controls: The policy controls (block, mfa, compliantDevice, etc.) (optional)

### ASD Format: Type-Action-Purpose
- Type: 
  - ADM: Policies related to administrative users
  - APP: Policies related to applications
  - DEV: Policies related to devices
  - GST: Policies related to guest users
  - LOC: Policies related to locations
  - OTH: Policies that don't fit other categories
  - USR: Policies related to users
  - WKL: Policies related to workload identities
- Action: 
  - B: Block access
  - S: Apply session controls
  - G: Grant access with conditions
- Purpose: Brief description of policy intent (e.g., "Limit admin sessions", "Block high-risk users")

Examples:
- ADM-S-Limit admin sessions: Time-box administrative web sessions
- APP-G-Strong auth for MS365: Require MFA for Microsoft 365 applications
- DEV-B-Block unapproved devices: Prevent access from unauthorized device types
- GST-B-Block guests: Block all guest access to tenant resources
- LOC-B-Block access from unapproved countries: Prevent access from non-allowed countries
- USR-G-Require strong auth: Enforce phishing-resistant MFA for all users
- WKL-G-Workload identity authentication: Control authentication for service principals

## Persona Definitions

- **Global**: Policies that apply to all users or don't target specific groups
- **Admins**: Users with administrative roles
- **Internals**: Standard employees and end-users
"@

            if (![string]::IsNullOrEmpty($OutputPath)) {
                $report | Out-File -FilePath (Join-Path $OutputPath "naming_conventions.md") -Encoding utf8
            }
        }
        
        # Initialize patterns tracking if not already done
        if ($null -eq $patterns) {
            $patterns = @{}
        }

        # Track patterns in policies with null checks
        foreach ($policy in $allPolicies) {
            # Skip null policies
            if ($null -eq $policy) {
                continue
            }
            
            # Ensure displayName exists
            if ($null -eq $policy.displayName) {
                $policy | Add-Member -MemberType NoteProperty -Name "displayName" -Value "Unnamed Policy" -Force
            }
            
            # Determine pattern name with null-safe operations
            $patternName = if ($policy.displayName -match '^CA\d+') {
                'Numbered'
            } elseif ($policy.displayName -match '^[A-Z]+-[A-Z]+-') {
                'ASD Format'
            } elseif ($policy.displayName -match '^(Global|Admin|Intern|Guest)') {
                'Persona Format'
            } else {
                'No Standard Format'
            }
            
            # Initialize array for this pattern if it doesn't exist
            if (-not $patterns.ContainsKey($patternName)) {
                $patterns[$patternName] = @()
            }
            
            # Add the display name to the pattern
            $patterns[$patternName] += $policy.displayName
        }

        # Generate summary with improved null checks - replace the existing code
        $summary = @()
        if ($null -ne $patterns -and $patterns.Count -gt 0) {
            foreach ($pattern in $patterns.Keys) {
                if ($null -ne $pattern -and $null -ne $patterns[$pattern]) {
                    $patternCount = $patterns[$pattern].Count
                    $patternExamples = if ($patternCount -gt 0) {
                        ($patterns[$pattern] | Select-Object -First 3) -join ", "
                    } else {
                        "No examples"
                    }
                    
                    $percentage = if ($allPolicies.Count -gt 0) {
                        [math]::Round(($patternCount / $allPolicies.Count) * 100, 1)
                    } else {
                        0
                    }
                    
                    $summary += [PSCustomObject]@{
                        Pattern = $pattern
                        Count = $patternCount
                        Examples = $patternExamples
                        Percentage = $percentage
                    }
                }
            }
        }

        # Sort by count descending - make sure summary exists before sorting
        if ($null -ne $summary -and $summary.Count -gt 0) {
            $analysis.Summary = $summary | Sort-Object -Property Count -Descending
        } else {
            # Create a default summary if none exists
            $analysis.Summary = @([PSCustomObject]@{
                Pattern = "No patterns detected"
                Count = 0
                Examples = "N/A"
                Percentage = 0
            })
        }
        
        # Return the analysis object
        return $analysis
    }
}

# Helper function to get next sequence number
function Get-NextNumber {
    param(
        [string]$category,
        [string]$type
    )
    
    if ($null -eq $script:sequenceCounters -or 
        $null -eq $script:sequenceCounters[$category] -or 
        $null -eq $script:sequenceCounters[$category][$type]) {
        Write-Warning "Unable to find counter for $category.$type, using default value of 1"
        return 1
    }
    
    $currentNumber = $script:sequenceCounters[$category][$type]
    $script:sequenceCounters[$category][$type] = $currentNumber + 1
    return $currentNumber
}

function Get-PolicyPersona {
    param($policy)
    
    if ($policy.conditions.users.includeRoles -and
        $policy.conditions.users.includeRoles.PSObject -and
        $policy.conditions.users.includeRoles.PSObject.Properties.Count -gt 0) {
        return "Admins"
    }
    if ($policy.conditions.users.includeUsers -contains "All") {
        return "Global"
    }
    return "Internals"
}

function Get-PolicyControls {
    param($policy)
    
    $controls = @()
    if ($policy.grantControls.builtInControls) {
        $controls += $policy.grantControls.builtInControls
    }
    return ($controls -join "+")
}

function Get-AppDisplayName {
    param($appId)
    
    if ([string]::IsNullOrEmpty($appId)) {
        return "Selected"
    }

    $appId = $appId.ToString()
    # Check if the app exists in our mappings
    foreach ($prop in $script:config.appMappings.PSObject.Properties) {
        if ($prop.Name -eq $appId) {
            return $prop.Value
        }
    }

    return "Selected"
}

function Get-PolicyTarget {
    param($policy)
    
    if (!$policy.conditions -or !$policy.conditions.applications) {
        return "Selected"
    }

    $apps = $policy.conditions.applications.includeApplications
    
    if (!$apps -or $apps.Count -eq 0) {
        return "Selected"
    }
    
    if ($apps -contains "All") { 
        return "AllApps" 
    }
    
    if ($apps.Count -gt 1) {
        return "Selected"
    }
    
    $appId = $apps[0]
    if ([string]::IsNullOrEmpty($appId)) {
        return "Selected"
    }
    
    return Get-AppDisplayName $appId
}

function Get-PolicyPlatforms {
    param($policy)
    
    if (!$policy.conditions.platforms) { return "" }
    $platforms = $policy.conditions.platforms.includePlatforms
    if ($platforms -contains "all" -or $platforms.Count -eq 0) { return "" }
    return ($platforms -join "+")
}

function Get-ASDType {
    param($policy)
    
    # Initialize score tracking for each category
    $scores = @{
        "ADM" = 0  # Administrative users
        "APP" = 0  # Applications
        "DEV" = 0  # Devices
        "GST" = 0  # Guest users
        "LOC" = 0  # Locations
        "USR" = 0  # Regular users
        "WKL" = 0  # Workload identities
        "OTH" = 0  # Others/miscellaneous
    }
    
    # Check for admin roles - strong indicator for ADM
    if ($policy.conditions.users.includeRoles -and 
        $policy.conditions.users.includeRoles.PSObject -and
        $policy.conditions.users.includeRoles.PSObject.Properties.Count -gt 0) {
        $scores["ADM"] += 10
    }
    
    # Check application targeting - indicator for APP
    if ($policy.conditions.applications) {
        # Specifically targeting certain apps (not "All")
        if ($policy.conditions.applications.includeApplications -and 
            $policy.conditions.applications.includeApplications -notcontains "All" -and
            $policy.conditions.applications.includeApplications.Count -gt 0) {
            $scores["APP"] += 8
        }
        
        # Specifically excluding certain apps
        if ($policy.conditions.applications.excludeApplications -and 
            $policy.conditions.applications.excludeApplications.Count -gt 0) {
            $scores["APP"] += 3
        }
        
        # Application filters present
        if ($policy.conditions.applications.applicationFilter) {
            $scores["APP"] += 5
        }
    }
    
    # Check platform conditions - indicator for DEV
    if ($policy.conditions.platforms) {
        # Targeting specific platforms
        if ($policy.conditions.platforms.includePlatforms -and 
            $policy.conditions.platforms.includePlatforms -notcontains "all" -and
            $policy.conditions.platforms.includePlatforms.Count -gt 0) {
            $scores["DEV"] += 8
        }
        
        # Excluding specific platforms
        if ($policy.conditions.platforms.excludePlatforms -and 
            $policy.conditions.platforms.excludePlatforms.Count -gt 0) {
            $scores["DEV"] += 3
        }
    }
    
    # Check for device state requirements
    if ($policy.conditions.devices -and $policy.conditions.devices.deviceState) {
        $scores["DEV"] += 7
    }
    
    # Device controls in grant controls
    if ($policy.grantControls.builtInControls -contains "compliantDevice" -or
        $policy.grantControls.builtInControls -contains "domainJoinedDevice") {
        $scores["DEV"] += 6
    }
    
    # Check for guests/external users - strong indicator for GST
    if ($policy.conditions.users.includeGuestsOrExternalUsers -or
        ($policy.displayName -match "guest" -or $policy.displayName -match "external")) {
        $scores["GST"] += 10
    }
    
    # Check for location conditions - strong indicator for LOC
    if ($policy.conditions.locations) {
        if ($policy.conditions.locations.includeLocations -or $policy.conditions.locations.excludeLocations) {
            $scores["LOC"] += 9
        }
    }
    
    # Check for workload identities
    if ($policy.conditions.clientApplications -and 
        $policy.conditions.clientApplications.servicePrincipals -and 
        $policy.conditions.clientApplications.servicePrincipals.Count -gt 0) {
        $scores["WKL"] += 10
    }
    
    # Check for general user targeting
    if ($policy.conditions.users) {
        # All users
        if ($policy.conditions.users.includeUsers -contains "All") {
            $scores["USR"] += 3
        }
        
        # Specific users or groups
        if (($policy.conditions.users.includeUsers -and 
             $policy.conditions.users.includeUsers -ne "All" -and
             $policy.conditions.users.includeUsers.Count -gt 0) -or
            ($policy.conditions.users.includeGroups -and 
             $policy.conditions.users.includeGroups.Count -gt 0)) {
            $scores["USR"] += 7
        }
    }
    
    # Scan display name for additional clues
    if ($policy.displayName -match "admin|privileged|role|global") {
        $scores["ADM"] += 3
    }
    if ($policy.displayName -match "app|application|office|microsoft|teams|sharepoint|exchange") {
        $scores["APP"] += 2
    }
    if ($policy.displayName -match "device|mobile|phone|iphone|android|windows|macos") {
        $scores["DEV"] += 2
    }
    if ($policy.displayName -match "guest|external|partner|b2b") {
        $scores["GST"] += 2
    }
    if ($policy.displayName -match "location|country|region|network|ip") {
        $scores["LOC"] += 2
    }
    if ($policy.displayName -match "user|employee|staff") {
        $scores["USR"] += 2
    }
    if ($policy.displayName -match "workload|service|principal|daemon|background") {
        $scores["WKL"] += 2
    }
    
    # Find highest score
    $highestScore = 0
    $highestCategory = "USR" # Default if all scores are 0
    
    foreach ($category in $scores.Keys) {
        if ($scores[$category] -gt $highestScore) {
            $highestScore = $scores[$category]
            $highestCategory = $category
        }
    }
    
    # If no clear category (score 0 or very low), use OTH
    if ($highestScore -lt 2) {
        return "OTH"
    }
    
    return $highestCategory
}

function Get-ASDAction {
    param($policy)
    
    if ($policy.grantControls.builtInControls -contains "block") {
        return "B"
    }
    if ($policy.sessionControls) {
        return "S"
    }
    return "G"
}

function Get-ASDPurpose {
    param($policy)
    
    # Get base type and action
    $type = Get-ASDType $policy
    $action = Get-ASDAction $policy
    
    # Get specific controls and conditions
    $hasLegacyAuth = $policy.conditions.clientAppTypes -contains "other"
    $hasRiskLevels = ($policy.conditions.userRiskLevels -and $policy.conditions.userRiskLevels.Count -gt 0) -or 
                     ($policy.conditions.signInRiskLevels -and $policy.conditions.signInRiskLevels.Count -gt 0)
    $hasMFA = $policy.grantControls.builtInControls -contains "mfa"
    $hasCompliantDevice = $policy.grantControls.builtInControls -contains "compliantDevice"
    $hasDomainJoinedDevice = $policy.grantControls.builtInControls -contains "domainJoinedDevice"
    $hasSession = $null -ne $policy.sessionControls
    $hasAppRestriction = $policy.conditions.applications.includeApplications -and 
                         $policy.conditions.applications.includeApplications -notcontains "All" -and
                         $policy.conditions.applications.includeApplications.Count -gt 0
    
    # Target apps information
    $target = Get-PolicyTarget $policy
    $isSpecificApps = $target -ne "AllApps"
    $appName = if ($isSpecificApps -and $target -ne "Selected") { $target } else { "" }
    
    # More detailed platform information
    $platforms = @()
    if ($policy.conditions.platforms -and $policy.conditions.platforms.includePlatforms) {
        $platforms = $policy.conditions.platforms.includePlatforms
    }
    $hasPlatformRestrictions = $platforms.Count -gt 0 -and -not ($platforms -contains "all")
    
    # Session controls details
    $signInFrequency = $null -ne $policy.sessionControls.signInFrequency
    $persistentBrowser = $null -ne $policy.sessionControls.persistentBrowser
    $appEnforcedRestrictions = $null -ne $policy.sessionControls.applicationEnforcedRestrictions
    $cloudAppSecurity = $null -ne $policy.sessionControls.cloudAppSecurity
    
    # Get purpose based on type, action, and conditions
    $purpose = switch ($type) {
        "ADM" {
            if ($signInFrequency) { "Limit admin sessions" }
            elseif ($hasSession) { 
                if ($appEnforcedRestrictions) { "App enforced restrictions" }
                else { "Session controls" }
            }
            elseif ($hasCompliantDevice -and $hasDomainJoinedDevice) { "Require compliant device" }
            elseif ($hasCompliantDevice) { "Require compliant device" }
            elseif ($hasDomainJoinedDevice) { "Require domain joined device" }
            elseif ($hasMFA) { "Require strong auth" }
            elseif ($action -eq "B") { "Block admin access" }
            else { "Admin access controls" }
        }
        "APP" {
            if ($action -eq "B") {
                if ($appName) { "Block access to $appName" }
                else { "Block application access" }
            }
            elseif ($cloudAppSecurity) { "Application CASB controls" }
            elseif ($appEnforcedRestrictions) { "App enforced restrictions" }
            elseif ($hasMFA) { 
                if ($appName) { "Strong auth for $appName" }
                else { "Application with strong auth" }
            }
            elseif ($hasSession) { "Application session controls" }
            else { "Application access controls" }
        }
        "DEV" {
            if ($hasPlatformRestrictions) { "Block unapproved devices" }
            elseif ($hasCompliantDevice) { "Compliant devices" }
            elseif ($hasMFA -and $hasCompliantDevice) { "Compliant devices with MFA" }
            elseif ($hasMFA) { "Intune enrolment with strong auth" }
            elseif ($action -eq "B") { "Block access from unapproved devices" }
            else { "Device access controls" }
        }
        "GST" {
            if ($isSpecificApps -and $hasMFA) { 
                if ($appName) { "$appName access with strong auth" }
                else { "Application access with strong auth" }
            }
            elseif ($isSpecificApps) { 
                if ($appName) { "$appName access" }
                else { "Selected application access" }
            }
            elseif ($action -eq "B") { "Block guests" }
            elseif ($hasMFA) { "Guest access with strong auth" }
            else { "Guest access controls" }
        }
        "LOC" {
            if ($action -eq "B") { "Block access from unapproved countries" }
            elseif ($hasMFA) { "MFA from untrusted locations" }
            else { "Location based controls" }
        }
        "USR" {
            if ($action -eq "B") {
                if ($hasLegacyAuth) { "Block access via legacy auth" }
                elseif ($hasRiskLevels -and $policy.conditions.userRiskLevels -contains "high") { "Block high-risk users" }
                elseif ($hasRiskLevels) { "Block high-risk sign-ins" }
                elseif ($policy.displayName -match "insider" -or $policy.displayName -match "risk") { "Block users with elevated insider risk" }
                elseif ($isSpecificApps) {
                    if ($appName) { "Block access to $appName" } 
                    else { "Block access to selected apps" }
                }
                else { "Block user access" }
            }
            elseif ($signInFrequency) { "Limit user sessions" }
            elseif ($policy.displayName -match "terms" -or $policy.displayName -match "agreement") { "Agreement to terms of use" }
            elseif ($hasMFA -and $policy.displayName -match "security" -and $policy.displayName -match "info|information") { "Register security info with strong auth" }
            elseif ($hasMFA -and $hasRiskLevels) { "Risky sign-ins with strong auth" }
            elseif ($hasMFA) { "Require strong auth" }
            elseif ($hasCompliantDevice) { "Require compliant device" }
            elseif ($hasSession) { 
                if ($persistentBrowser) { "No persistent browser" }
                elseif ($appEnforcedRestrictions) { "App enforced restrictions" }
                else { "Session controls" }
            }
            else { "User access controls" }
        }
        "WKL" {
            if ($action -eq "B") { "Block workload access" }
            elseif ($hasMFA) { "Workload identity authentication" }
            else { "Workload access controls" }
        }
        "OTH" {
            if ($action -eq "B") { "Block access" }
            elseif ($hasRiskLevels) { "Risk-based controls" }
            elseif ($hasSession) { "Session controls" }
            elseif ($hasMFA) { "Require authentication" }
            else { "Access controls" }
        }
        default { "Access controls" }
    }
    
    return $purpose
}

function Get-PolicyNumber {
    param($persona)
    
    $number = Get-NextNumber "MS" $persona
    return "CA$($number.ToString('000'))"
}

function Get-SimpleSequenceNumber {
    param($policy)
    
    if ($policy.displayName -match "EMERGENCY|EM\d+") {
        $number = Get-NextNumber "Simple" "emergency"
        return "EM$($number.ToString('00'))"
    }
    
    if ($policy.conditions.users.includeRoles -and $policy.conditions.users.includeRoles.Count -gt 0) {
        $number = Get-NextNumber "Simple" "admin"
        return "CA$($number.ToString('00'))"
    }
    if ($policy.conditions.platforms) {
        $number = Get-NextNumber "Simple" "device"
        return "CA$($number.ToString('00'))"
    }
    
    $number = Get-NextNumber "Simple" "default"
    return "CA$($number.ToString('00'))"
}

function Get-SimpleResponse {
    param($policy)
    
    if ($policy.grantControls.builtInControls -contains "block") {
        return "Block"
    }
    if ($policy.grantControls.builtInControls -contains "mfa") {
        return "RequireMFA"
    }
    if ($policy.grantControls.builtInControls -contains "compliantDevice") {
        return "RequireCompliant"
    }
    if ($policy.sessionControls) {
        return "AllowSession"
    }
    return "Grant"
}

function Get-SimpleUsers {
    param($policy)
    
    if ($policy.conditions.users.includeRoles -and $policy.conditions.users.includeRoles.Count -gt 0) {
        return "Admins"
    }
    if ($policy.conditions.users.includeUsers -contains "All") {
        return "AllUsers"
    }
    return "SelectedUsers"
}

function Get-SimpleConditions {
    param($policy)
    
    $conditions = @()
    
    if ($policy.conditions.locations) {
        $conditions += "ExternalAccess"
    }
    if ($policy.conditions.platforms) {
        if ($policy.conditions.platforms.includePlatforms -contains "all") {
            $conditions += "AllPlatforms"
        } else {
            $platformList = $policy.conditions.platforms.includePlatforms -join "And"
            if (-not [string]::IsNullOrEmpty($platformList)) {
                $conditions += $platformList
            }
        }
    }
    
    # Return empty string if no conditions rather than "NoConditions"
    if ($conditions.Count -eq 0) {
        return ""
    }
    
    return ($conditions -join "-")
}

# Export the function
Export-ModuleMember -Function Get-CANamingAnalysis 