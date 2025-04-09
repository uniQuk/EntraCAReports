function Export-CADiagram {
    <#
    .SYNOPSIS
        Generates Mermaid diagrams for Conditional Access policies.
    
    .DESCRIPTION
        This function generates visual diagrams of Conditional Access policies using Mermaid syntax.
        The diagrams visualize policy conditions, exclusions, and controls in a flowchart format.
    
    .PARAMETER Policies
        The Conditional Access policies to include in the diagrams. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy JSON files.
        
    .PARAMETER OutputPath
        The path where the diagram files will be saved. If not specified, uses the configured diagrams path.
        
    .PARAMETER DiagramType
        The type of diagram to generate. Currently only "Mermaid" is supported.
        
    .PARAMETER CombineDiagrams
        Switch to combine all policies into a single diagram file.
        
    .PARAMETER OutputFormat
        The output format for the diagram files. Can be "md" or "html". Defaults to "md".
    
    .EXAMPLE
        Export-CADiagram -Path "./policies/data" -OutputPath "./diagrams"
    
    .EXAMPLE
        Get-CAPolicy | Export-CADiagram -OutputPath "./diagrams" -CombineDiagrams
    
    .NOTES
        This function generates Mermaid diagram syntax which can be rendered by GitHub, VS Code with 
        the Markdown Preview Mermaid extension, or other Markdown viewers that support Mermaid.
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
        [ValidateSet("Mermaid")]
        [string]$DiagramType = "Mermaid",
        
        [Parameter(Mandatory=$false)]
        [switch]$CombineDiagrams,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("md", "html")]
        [string]$OutputFormat = "md"
    )
    
    begin {
        # Local helper function for safe filenames
        function Get-LocalSafeFilename {
            param(
                [Parameter(Mandatory=$true)]
                [string]$DisplayName,
                [string]$DefaultName = "unnamed_policy"
            )
            
            # Return default name if input is null or empty
            if ([string]::IsNullOrWhiteSpace($DisplayName)) {
                return $DefaultName
            }

            # Get invalid characters
            $invalids = [System.IO.Path]::GetInvalidFileNameChars()
            $replacement = '_'
            
            # Replace invalid chars and control chars
            $safeName = [RegEx]::Replace($DisplayName, "[$([RegEx]::Escape(-join $invalids))]", $replacement)
            
            # Replace spaces with underscores
            $safeName = $safeName -replace '\s+', '_'
            
            # Replace multiple consecutive underscores with single underscore
            $safeName = $safeName -replace '_{2,}', '_'
            
            # Trim underscores from start and end
            $safeName = $safeName.Trim('_')
            
            # Return default name if result is empty
            if ([string]::IsNullOrWhiteSpace($safeName)) {
                return $DefaultName
            }
            
            # Truncate if too long (Windows max path is 260, leave room for path and extension)
            $maxLength = 200
            if ($safeName.Length -gt $maxLength) {
                $safeName = $safeName.Substring(0, $maxLength)
                $safeName = $safeName.TrimEnd('_')
            }
            
            # Ensure name doesn't end with a period (can cause issues on Windows)
            $safeName = $safeName -replace '\.$', '_'
            
            return $safeName
        }
        
        # Get config paths if OutputPath not specified
        if ([string]::IsNullOrEmpty($OutputPath)) {
            $config = Get-CAConfig
            $OutputPath = Join-Path -Path $config.OutputPaths.Base -ChildPath $config.OutputPaths.Diagrams
        }
        
        # Initialize collections if using pipeline input
        if ($PSCmdlet.ParameterSetName -eq "FromPolicies") {
            $allPolicies = @()
        }
        
        # Create output directory if it doesn't exist
        if (![string]::IsNullOrEmpty($OutputPath)) {
            New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
        }
    }
    
    process {
        # Add policies from pipeline to collection
        if ($PSCmdlet.ParameterSetName -eq "FromPolicies" -and $Policies) {
            $allPolicies += $Policies
        }
    }
    
    end {
        # Load policies from JSON files if specified
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            $allPolicies = try {
                Get-ChildItem -Path $Path -Filter "*.json" -ErrorAction Stop | 
                ForEach-Object { 
                    try {
                        $content = Get-Content $_.FullName -Raw
                        $policy = $content | ConvertFrom-Json
                        if (!($policy.displayName -and $policy.conditions)) {
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
                Write-CAError -ErrorRecord $_ -Message "Failed to read policy files" -ErrorLevel 'Error' -LogToFile
                return
            }
        }
        
        if (!$allPolicies -or $allPolicies.Count -eq 0) {
            Write-Warning "No valid policies found to process"
            return $OutputPath
        }
        
        try {
            if ($CombineDiagrams) {
                # Generate a single diagram file for all policies
                $combinedMermaid = @()
                $combinedMermaid += "# Conditional Access Policy Diagrams`n"
                
                foreach ($policy in $allPolicies) {
                    $combinedMermaid += "## $($policy.displayName)`n"
                    $combinedMermaid += '```mermaid'
                    $combinedMermaid += Get-PolicyMermaidDiagram -Policy $policy -Name $policy.displayName
                    $combinedMermaid += '```'
                    $combinedMermaid += "`n"
                }
                
                $outputFileName = "combined_diagrams.$OutputFormat"
                $outputFilePath = Join-Path -Path $OutputPath -ChildPath $outputFileName
                $combinedMermaid | Out-File -FilePath $outputFilePath -Encoding utf8
            }
            else {
                # Generate individual diagram files for each policy
                foreach ($policy in $allPolicies) {
                    try {
                        $mermaidDiagram = Get-PolicyMermaidDiagram -Policy $policy -Name $policy.displayName
                        
                        # Create safe filename using local function to avoid parameter issues
                        $safeFilename = Get-LocalSafeFilename -DisplayName $policy.displayName
                        $outputFileName = "$safeFilename.$OutputFormat"
                        $outputFilePath = Join-Path -Path $OutputPath -ChildPath $outputFileName
                        
                        # Create content based on output format
                        $content = @()
                        $content += "# $($policy.displayName)`n"
                        $content += '```mermaid'
                        $content += $mermaidDiagram
                        $content += '```'
                        
                        # Write to file
                        $content | Out-File -FilePath $outputFilePath -Encoding utf8
                    }
                    catch {
                        Write-Warning "Failed to generate diagram for policy '$($policy.displayName)': $_"
                    }
                }
            }
            
            Write-Output $OutputPath
        }
        catch {
            Write-CAError -ErrorRecord $_ -Message "Failed to generate diagrams" -ErrorLevel 'Error' -LogToFile
            return $OutputPath
        }
    }
}

function Get-PolicyMermaidDiagram {
    <#
    .SYNOPSIS
        Generates a Mermaid diagram for a single policy.
    
    .DESCRIPTION
        This function generates a Mermaid flowchart diagram for a given Conditional Access policy.
    
    .PARAMETER Policy
        The policy object to create a diagram for.
        
    .PARAMETER Name
        The display name to use for the policy in the diagram.
    
    .EXAMPLE
        Get-PolicyMermaidDiagram -Policy $policy -Name "My Policy"
        
    .NOTES
        This is an internal helper function used by Export-CADiagram.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Policy,
        
        [Parameter(Mandatory=$false)]
        [string]$Name = $null
    )
    
    # Use provided name or default to policy displayName
    if ([string]::IsNullOrEmpty($Name)) {
        $Name = $Policy.displayName
    }
    
    # Generate unique node IDs based on policy ID
    $policyIdShort = ($Policy.id -replace '-', '').Substring(0, 8)
    $nodePrefix = "p$($policyIdShort)_"
    
    # Start the flowchart
    $diagram = @()
    $diagram += "flowchart TD"
    
    # Policy name and state
    $stateColor = switch ($Policy.state) {
        "enabled" { "green" }
        "enabledForReportingButNotEnforced" { "yellow" }
        "disabled" { "red" }
        default { "gray" }
    }
    
    $stateLabel = switch ($Policy.state) {
        "enabled" { "Enabled" }
        "enabledForReportingButNotEnforced" { "Report-only" }
        "disabled" { "Disabled" }
        default { $Policy.state }
    }
    
    $diagram += "    ${nodePrefix}start[""$Name""]:::$stateColor"
    $diagram += "    ${nodePrefix}state[""State: $stateLabel""]:::$stateColor"
    $diagram += "    ${nodePrefix}start --> ${nodePrefix}state"
    
    # Applications
    $diagram += "    ${nodePrefix}apps[""Applications""]"
    $diagram += "    ${nodePrefix}state --> ${nodePrefix}apps"
    
    # Helper function to get count safely
    $getCount = {
        param($obj)
        if ($null -eq $obj) { return 0 }
        if ($obj -is [string]) { return 1 }
        if ($obj -is [Array]) { return $obj.Count }
        if ($obj -is [System.Collections.ICollection]) { return $obj.Count }
        if ($obj.PSObject.Properties) { return ($obj.PSObject.Properties | Measure-Object).Count }
        return 0
    }
    
    # Handle applications section
    if ($Policy.conditions.applications.includeApplications -contains "All" -or 
        $Policy.conditions.applications.includeApplications -eq "All") {
        $diagram += "    ${nodePrefix}apps_inc[""Include: All applications""]"
        $diagram += "    ${nodePrefix}apps --> ${nodePrefix}apps_inc"
    }
    elseif ($Policy.conditions.applications.includeApplications) {
        $appCount = & $getCount $Policy.conditions.applications.includeApplications
        $diagram += "    ${nodePrefix}apps_inc[""Include: $appCount application(s)""]"
        $diagram += "    ${nodePrefix}apps --> ${nodePrefix}apps_inc"
    }
    
    if ($Policy.conditions.applications.excludeApplications) {
        $excludeAppCount = & $getCount $Policy.conditions.applications.excludeApplications
        if ($excludeAppCount -gt 0) {
            $diagram += "    ${nodePrefix}apps_exc[""Exclude: $excludeAppCount application(s)""]"
            $diagram += "    ${nodePrefix}apps --> ${nodePrefix}apps_exc"
        }
    }
    
    if ($Policy.conditions.applications.includeUserActions) {
        $actions = $Policy.conditions.applications.includeUserActions
        if ($actions -is [Array]) {
            $actionText = $actions -join ', '
        } else {
            $actionText = $actions
        }
        $diagram += "    ${nodePrefix}user_actions[""User Actions: $actionText""]"
        $diagram += "    ${nodePrefix}apps --> ${nodePrefix}user_actions"
    }
    
    # Users
    $diagram += "    ${nodePrefix}users[""Users & Groups""]"
    $diagram += "    ${nodePrefix}apps --> ${nodePrefix}users"
    
    # Handle users section
    if (($Policy.conditions.users.includeUsers -contains "All") -or
        ($Policy.conditions.users.includeUsers -eq "All")) {
        $diagram += "    ${nodePrefix}users_inc[""Include: All users""]"
        $diagram += "    ${nodePrefix}users --> ${nodePrefix}users_inc"
    }
    elseif ($Policy.conditions.users.includeUsers) {
        $userCount = & $getCount $Policy.conditions.users.includeUsers
        $diagram += "    ${nodePrefix}users_inc[""Include: $userCount user(s)""]"
        $diagram += "    ${nodePrefix}users --> ${nodePrefix}users_inc"
    }
    
    if ($Policy.conditions.users.includeGroups) {
        $groupCount = & $getCount $Policy.conditions.users.includeGroups
        $diagram += "    ${nodePrefix}groups_inc[""Include: $groupCount group(s)""]"
        $diagram += "    ${nodePrefix}users --> ${nodePrefix}groups_inc"
    }
    
    if ($Policy.conditions.users.includeRoles) {
        $roleCount = & $getCount $Policy.conditions.users.includeRoles
        $diagram += "    ${nodePrefix}roles_inc[""Include: $roleCount role(s)""]"
        $diagram += "    ${nodePrefix}users --> ${nodePrefix}roles_inc"
    }
    
    if ($Policy.conditions.users.excludeUsers) {
        $excludeUserCount = & $getCount $Policy.conditions.users.excludeUsers
        if ($excludeUserCount -gt 0) {
            $diagram += "    ${nodePrefix}users_exc[""Exclude: $excludeUserCount user(s)""]"
            $diagram += "    ${nodePrefix}users --> ${nodePrefix}users_exc"
        }
    }
    
    if ($Policy.conditions.users.excludeGroups) {
        $excludeGroupCount = & $getCount $Policy.conditions.users.excludeGroups
        if ($excludeGroupCount -gt 0) {
            $diagram += "    ${nodePrefix}groups_exc[""Exclude: $excludeGroupCount group(s)""]"
            $diagram += "    ${nodePrefix}users --> ${nodePrefix}groups_exc"
        }
    }
    
    # Conditions
    $diagram += "    ${nodePrefix}conditions[""Conditions""]"
    $diagram += "    ${nodePrefix}users --> ${nodePrefix}conditions"
    
    if ($Policy.conditions.clientAppTypes) {
        $appTypes = $Policy.conditions.clientAppTypes
        if ($appTypes -is [Array]) {
            $appTypesText = $appTypes -join ', '
        } else {
            $appTypesText = $appTypes
        }
        $diagram += "    ${nodePrefix}client_apps[""Client Apps: $appTypesText""]"
        $diagram += "    ${nodePrefix}conditions --> ${nodePrefix}client_apps"
    }
    
    if ($Policy.conditions.platforms -and $Policy.conditions.platforms.includePlatforms) {
        $platforms = $Policy.conditions.platforms.includePlatforms
        if ($platforms -is [Array]) {
            $platformsText = $platforms -join ', '
        } else {
            $platformsText = $platforms
        }
        $diagram += "    ${nodePrefix}platforms[""Platforms: $platformsText""]"
        $diagram += "    ${nodePrefix}conditions --> ${nodePrefix}platforms"
    }
    
    if ($Policy.conditions.locations) {
        $diagram += "    ${nodePrefix}locations[""Locations""]"
        $diagram += "    ${nodePrefix}conditions --> ${nodePrefix}locations"
        
        # Handle include locations
        if ($Policy.conditions.locations.includeLocations) {
            $locations = $Policy.conditions.locations.includeLocations
            $locationText = if ($locations -is [Array]) {
                $locations -join ', '
            } else {
                $locations
            }
            $diagram += "    ${nodePrefix}locations_inc[""Include: $locationText""]"
            $diagram += "    ${nodePrefix}locations --> ${nodePrefix}locations_inc"
        }
        
        # Handle exclude locations
        if ($Policy.conditions.locations.excludeLocations) {
            $locations = $Policy.conditions.locations.excludeLocations
            $locationText = if ($locations -is [Array]) {
                $locations -join ', '
            } else {
                $locations
            }
            $diagram += "    ${nodePrefix}locations_exc[""Exclude: $locationText""]"
            $diagram += "    ${nodePrefix}locations --> ${nodePrefix}locations_exc"
        }
    }
    
    if ($Policy.conditions.userRiskLevels -or $Policy.conditions.signInRiskLevels) {
        $riskText = ""
        if ($Policy.conditions.userRiskLevels) {
            $riskLevels = $Policy.conditions.userRiskLevels
            $userRiskText = if ($riskLevels -is [Array]) {
                $riskLevels -join ', '
            } else {
                $riskLevels.ToString()
            }
            $riskText += "User Risk: $userRiskText"
        }
        if ($Policy.conditions.signInRiskLevels) {
            if ($riskText) { $riskText += "<br>" }
            $riskLevels = $Policy.conditions.signInRiskLevels
            $signInRiskText = if ($riskLevels -is [Array]) {
                $riskLevels -join ', '
            } else {
                $riskLevels.ToString()
            }
            $riskText += "Sign-in Risk: $signInRiskText"
        }
        
        $diagram += "    ${nodePrefix}risk[""$riskText""]"
        $diagram += "    ${nodePrefix}conditions --> ${nodePrefix}risk"
    }
    
    # Access controls
    $diagram += "    ${nodePrefix}controls[""Access Controls""]"
    $diagram += "    ${nodePrefix}conditions --> ${nodePrefix}controls"
    
    if ($Policy.grantControls) {
        $grantText = "Grant: "
        if ($Policy.grantControls.builtInControls -contains "block" -or 
            $Policy.grantControls.builtInControls -eq "block") {
            $grantText += "Block access"
        }
        else {
            $controls = $Policy.grantControls.builtInControls
            $controlsText = if ($controls -is [Array]) {
                $controls -join ' ' + $Policy.grantControls.operator + ' '
            } else {
                $controls
            }
            $grantText += $controlsText
        }
        
        $diagram += "    ${nodePrefix}grant[""$grantText""]"
        $diagram += "    ${nodePrefix}controls --> ${nodePrefix}grant"
    }
    
    if ($Policy.sessionControls) {
        $sessionText = "Session: "
        $sessionControls = @()
        
        if ($Policy.sessionControls.applicationEnforcedRestrictions.isEnabled) {
            $sessionControls += "App enforced restrictions"
        }
        if ($Policy.sessionControls.cloudAppSecurity.isEnabled) {
            $sessionControls += "Cloud App Security"
        }
        if ($Policy.sessionControls.signInFrequency.isEnabled) {
            $sessionControls += "Sign-in frequency"
        }
        if ($Policy.sessionControls.persistentBrowser.isEnabled) {
            $sessionControls += "Persistent browser"
        }
        
        if ($sessionControls.Count -gt 0) {
            $sessionText += $sessionControls -join ', '
            $diagram += "    ${nodePrefix}session[""$sessionText""]"
            $diagram += "    ${nodePrefix}controls --> ${nodePrefix}session"
        }
    }
    
    # Add style classes
    $diagram += "    classDef green fill:#9f9,stroke:#484,stroke-width:2px"
    $diagram += "    classDef yellow fill:#ff9,stroke:#880,stroke-width:2px"
    $diagram += "    classDef red fill:#f99,stroke:#844,stroke-width:2px"
    $diagram += "    classDef gray fill:#eee,stroke:#888,stroke-width:2px"
    
    return $diagram -join "`n"
}

# Export the public function
Export-ModuleMember -Function Export-CADiagram 