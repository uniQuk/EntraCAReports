function Export-CAExcelReport {
    <#
    .SYNOPSIS
        Generates an Excel report for Conditional Access policies.
    
    .DESCRIPTION
        This function generates a detailed Excel report for Conditional Access policies,
        including all policy settings, conditions, and controls. The report includes
        conditional formatting for policy states and customized column widths.
    
    .PARAMETER Policies
        The Conditional Access policies to include in the report. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy JSON files.
        
    .PARAMETER OutputPath
        The path where the Excel report will be saved. Defaults to "analysis/excel".
        
    .PARAMETER FileName
        The filename for the generated Excel report. Defaults to "CA_Policies_Analysis.xlsx".
        
    .PARAMETER IncludeGroupMembers
        Switch to include group membership details in the report. This can make the report larger.
        
    .PARAMETER Force
        Switch to bypass confirmation prompt when overwriting an existing file.
    
    .PARAMETER Analysis
        The analysis object containing statistics and patterns.
    
    .EXAMPLE
        Export-CAExcelReport -Path "./policies/data" -OutputPath "./reports"
    
    .EXAMPLE
        Get-CAPolicy | Export-CAExcelReport -OutputPath "./reports" -FileName "DetailedReport.xlsx"
    
    .NOTES
        This function requires the ImportExcel module to be installed.
        You can install it with: Install-Module ImportExcel -Scope CurrentUser
    #>
    
    [CmdletBinding(DefaultParameterSetName="FromPolicies", SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName="FromPolicies", ValueFromPipeline=$true)]
        [PSCustomObject[]]$Policies,
        
        [Parameter(Mandatory=$true, ParameterSetName="FromPath")]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$FileName = "CA_Policies_Analysis.xlsx",
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeGroupMembers,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$Analysis
    )
    
    begin {
        # Check if ImportExcel module is available
        if (-not (Get-Module -ListAvailable -Name 'ImportExcel')) {
            Write-Error "The ImportExcel module is required for this function. Please install it with: Install-Module ImportExcel -Scope CurrentUser"
            return
        }
        
        # Import the module
        try {
            Import-Module 'ImportExcel' -ErrorAction Stop
        }
        catch {
            Write-CAError -ErrorRecord $_ -Message "Failed to import the ImportExcel module" -ErrorLevel 'Terminal'
            return
        }
        
        # Get the proper output path if not specified
        if ([string]::IsNullOrEmpty($OutputPath)) {
            # Get configuration to determine proper paths
            $config = Get-CAConfig
            $basePath = $config.OutputPaths.Base
            $excelPath = $config.OutputPaths.Excel
            $OutputPath = Join-Path -Path $basePath -ChildPath $excelPath
            Write-Verbose "Using configured output path: $OutputPath"
        }
        
        # Initialize collections if using pipeline input
        if ($PSCmdlet.ParameterSetName -eq "FromPolicies") {
            $allPolicies = @()
        }
        
        # Create output directory if it doesn't exist
        if (![string]::IsNullOrEmpty($OutputPath)) {
            if ($PSCmdlet.ShouldProcess($OutputPath, "Create directory")) {
                $created = New-Item -ItemType Directory -Force -Path $OutputPath
                Write-Verbose "Created/confirmed output directory: $OutputPath"
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
        # Load policies from JSON files if specified
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            $allPolicies = try {
                Get-ChildItem -Path $Path -Filter "*.json" -ErrorAction Stop | 
                ForEach-Object { 
                    try {
                        $content = Get-Content $_.FullName -Raw
                        $policy = $content | ConvertFrom-Json
                        if (!(Test-PolicyStructure $policy)) {
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
        
        if ($allPolicies.Count -eq 0) {
            Write-Error "No valid policies found to process"
            return
        }
        
        # Create expanded overview data with all settings
        $overviewData = $allPolicies | Select-Object @{N='Policy Name';E={$_.displayName}}, 
            @{N='State';E={Format-PolicyState $_.state}},
            @{N='Created';E={$_.createdDateTime}},
            @{N='Modified';E={$_.modifiedDateTime}},
            @{N='Include Users';E={
                # Handle special case for includeUsers
                if ($_.conditions.users.includeUsers -eq "All" -or 
                    ($_.conditions.users.includeUsers -is [hashtable] -and 
                     $_.conditions.users.includeUsers.ContainsKey('All'))) {
                    return "All"
                }
                elseif ($_.conditions.users.includeUsers -eq "None" -or 
                       ($_.conditions.users.includeUsers -is [hashtable] -and 
                        $_.conditions.users.includeUsers.ContainsKey('None'))) {
                    return "None"
                }
                else {
                    Format-ArrayForExcel $_.conditions.users.includeUsers
                }
            }},
            @{N='Include Groups';E={
                Format-ArrayForExcel ($_.conditions.users.includeGroups.PSObject.Properties.Value.displayName)
            }},
            @{N='Included Group Members';E={
                $members = @()
                foreach ($group in $_.conditions.users.includeGroups.PSObject.Properties.Value) {
                    if ($group.members) {
                        $groupMembers = $group.members.PSObject.Properties.Value.userPrincipalName
                        if ($groupMembers) {
                            $members += "$($group.displayName):`n  $(($groupMembers | Sort-Object) -join "`n  ")"
                        }
                    }
                }
                Format-ArrayForExcel $members
            }},
            @{N='Include Roles';E={
                # Special handling for roles that might be hashtables
                if ($null -eq $_.conditions.users.includeRoles) {
                    return $null
                }
                elseif ($_.conditions.users.includeRoles -is [hashtable] -or 
                        $_.conditions.users.includeRoles -is [System.Collections.IDictionary]) {
                    # Extract role objects from hashtable
                    $roles = @()
                    foreach ($key in $_.conditions.users.includeRoles.Keys) {
                        $role = $_.conditions.users.includeRoles[$key]
                        if ($null -ne $role -and $role.PSObject.Properties.Name -contains 'displayName') {
                            $roles += $role.displayName
                        }
                        else {
                            # If no display name, try to use the key if it looks like a role name
                            if ($key -match 'Administrator' -or $key -match 'Reader' -or $key -match 'Operator') {
                                $roles += $key
                            }
                        }
                    }
                    return ($roles | Sort-Object) -join "`n"
                }
                else {
                    # Original extraction for array-based roles
                    Format-ArrayForExcel ($_.conditions.users.includeRoles.PSObject.Properties.Value.displayName | Sort-Object)
                }
            }},
            @{N='Include Guest/External';E={$_.conditions.users.includeGuestsOrExternalUsers}},
            @{N='Exclude Users';E={
                $users = @()
                foreach ($user in $_.conditions.users.excludeUsers.PSObject.Properties.Value) {
                    if ($user.userPrincipalName) { 
                        $users += $user.userPrincipalName
                    }
                }
                Format-ArrayForExcel ($users | Sort-Object)
            }},
            @{N='Exclude Groups';E={
                Format-ArrayForExcel ($_.conditions.users.excludeGroups.PSObject.Properties.Value.displayName | Sort-Object)
            }},
            @{N='Excluded Group Members';E={
                $members = @()
                foreach ($group in $_.conditions.users.excludeGroups.PSObject.Properties.Value) {
                    if ($group.members) {
                        $groupMembers = $group.members.PSObject.Properties.Value.userPrincipalName
                        if ($groupMembers) {
                            $members += "$($group.displayName):`n  $(($groupMembers | Sort-Object) -join "`n  ")"
                        }
                    }
                }
                Format-ArrayForExcel $members
            }},
            @{N='Exclude Roles';E={
                Format-ArrayForExcel ($_.conditions.users.excludeRoles.PSObject.Properties.Value.displayName | Sort-Object)
            }},
            @{N='Exclude Guest/External';E={$_.conditions.users.excludeGuestsOrExternalUsers}},
            @{N='Applications';E={
                # Handle special case for "All" applications
                if ($_.conditions.applications.includeApplications -eq "All") { 
                    return "All" 
                }
                elseif ($_.conditions.applications.includeApplications -is [hashtable] -and
                        $_.conditions.applications.includeApplications.ContainsKey('All')) {
                    return "All"
                }
                else {
                    # Extract application names from either array or hashtable
                    if ($_.conditions.applications.includeApplications -is [hashtable]) {
                        $apps = @()
                        foreach ($key in $_.conditions.applications.includeApplications.Keys) {
                            $app = $_.conditions.applications.includeApplications[$key]
                            if ($null -ne $app -and $app.PSObject.Properties.Name -contains 'displayName') {
                                $apps += $app.displayName
                            }
                        }
                        return ($apps | Sort-Object) -join "`n"
                    }
                    else {
                        Format-ArrayForExcel ($_.conditions.applications.includeApplications.PSObject.Properties.Value.displayName | Sort-Object)
                    }
                }
            }},
            @{N='Exclude Applications';E={
                Format-ArrayForExcel ($_.conditions.applications.excludeApplications.PSObject.Properties.Value.displayName | Sort-Object)
            }},
            @{N='User Actions';E={Format-ArrayForExcel $_.conditions.applications.includeUserActions}},
            @{N='Authentication Context';E={Format-ArrayForExcel $_.conditions.applications.includeAuthenticationContextClassReferences}},
            @{N='Client App Types';E={
                # Extract client app types from either array or hashtable
                if ($_.conditions.clientAppTypes -is [hashtable]) {
                    $appTypes = @()
                    foreach ($key in $_.conditions.clientAppTypes.Keys) {
                        $appTypes += $key
                    }
                    return ($appTypes | Sort-Object) -join "`n"
                }
                else {
                    Format-ArrayForExcel $_.conditions.clientAppTypes
                }
            }},
            @{N='Device Platforms';E={
                if ($_.conditions.platforms) {
                    Format-ArrayForExcel $_.conditions.platforms.includePlatforms
                }
            }},
            @{N='Exclude Platforms';E={
                if ($_.conditions.platforms) {
                    Format-ArrayForExcel $_.conditions.platforms.excludePlatforms
                }
            }},
            @{N='Device State';E={
                if ($_.conditions.devices.deviceFilter) {
                    $_.conditions.devices.deviceFilter.rule
                }
            }},
            @{N='Locations';E={
                if ($_.conditions.locations) {
                    Format-ArrayForExcel $_.conditions.locations.includeLocations
                }
            }},
            @{N='Exclude Locations';E={
                if ($_.conditions.locations) {
                    Format-ArrayForExcel $_.conditions.locations.excludeLocations
                }
            }},
            @{N='User Risk Levels';E={Format-ArrayForExcel $_.conditions.userRiskLevels}},
            @{N='Sign-in Risk Levels';E={Format-ArrayForExcel $_.conditions.signInRiskLevels}},
            @{N='Grant Controls';E={Format-ArrayForExcel $_.grantControls.builtInControls}},
            @{N='Grant Operator';E={$_.grantControls.operator}},
            @{N='Session Controls';E={
                if ($_.sessionControls) {
                    $controls = @()
                    foreach ($control in $_.sessionControls.PSObject.Properties) {
                        if ($null -ne $control.Value) {
                            $controls += "$($control.Name): $($control.Value.isEnabled)"
                        }
                    }
                    Format-ArrayForExcel $controls
                }
            }}

        # Calculate full path for Excel file
        $excelPath = Join-Path -Path $OutputPath -ChildPath $FileName
        
        # Confirm file creation or overwrite
        $shouldContinue = $true
        if (Test-Path -Path $excelPath) {
            if (-not $Force) {
                $shouldContinue = $PSCmdlet.ShouldProcess($excelPath, "Overwrite existing Excel report")
            }
        } else {
            $shouldContinue = $PSCmdlet.ShouldProcess($excelPath, "Create Excel report")
        }
        
        if ($shouldContinue) {
            try {
                # Define conditional formatting rules for states
                $conditionalFormats = @(
                    New-ConditionalText -Text "Enabled" -BackgroundColor LightGreen
                    New-ConditionalText -Text "ReportOnly" -BackgroundColor LightYellow
                    New-ConditionalText -Text "Disabled" -BackgroundColor LightGray
                )
                
                # Define column widths based on content type - this is key to formatting
                $columnWidths = @{
                    'Policy Name' = 50          # Wider for policy names
                    'State' = 15                # Fixed width for states
                    'Created' = 20              # DateTime columns
                    'Modified' = 20             # DateTime columns
                    'Include Users' = 30        # User lists
                    'Include Groups' = 30       # Group lists
                    'Include Roles' = 40        # Role lists can be long
                    'Applications' = 35         # Application names
                    'Grant Controls' = 25       # Control lists
                    'Device State' = 40         # Device filter rules can be long
                    'Default' = 25              # Default width for other columns
                }
                
                # IMPORTANT: Create fresh policy data exactly matching the original script columns and order
                $overviewData = $allPolicies | Select-Object @{N='Policy Name';E={$_.displayName}}, 
                    @{N='State';E={Format-PolicyState $_.state}},
                    @{N='Created';E={$_.createdDateTime}},
                    @{N='Modified';E={$_.modifiedDateTime}},
                    @{N='Include Users';E={
                        # Handle special case for includeUsers
                        if ($_.conditions.users.includeUsers -eq "All" -or 
                            ($_.conditions.users.includeUsers -is [hashtable] -and 
                             $_.conditions.users.includeUsers.ContainsKey('All'))) {
                            return "All"
                        }
                        elseif ($_.conditions.users.includeUsers -eq "None" -or 
                               ($_.conditions.users.includeUsers -is [hashtable] -and 
                                $_.conditions.users.includeUsers.ContainsKey('None'))) {
                            return "None"
                        }
                        else {
                            Format-ArrayForExcel $_.conditions.users.includeUsers
                        }
                    }},
                    @{N='Include Groups';E={
                        Format-ArrayForExcel ($_.conditions.users.includeGroups.PSObject.Properties.Value.displayName)
                    }},
                    @{N='Included Group Members';E={
                        $members = @()
                        foreach ($group in $_.conditions.users.includeGroups.PSObject.Properties.Value) {
                            if ($group.members) {
                                $groupMembers = $group.members.PSObject.Properties.Value.userPrincipalName
                                if ($groupMembers) {
                                    $members += "$($group.displayName):`n  $(($groupMembers | Sort-Object) -join "`n  ")"
                                }
                            }
                        }
                        Format-ArrayForExcel $members
                    }},
                    @{N='Include Roles';E={
                        # Special handling for roles that might be hashtables
                        if ($null -eq $_.conditions.users.includeRoles) {
                            return $null
                        }
                        elseif ($_.conditions.users.includeRoles -is [hashtable] -or 
                                $_.conditions.users.includeRoles -is [System.Collections.IDictionary]) {
                            # Extract role objects from hashtable
                            $roles = @()
                            foreach ($key in $_.conditions.users.includeRoles.Keys) {
                                $role = $_.conditions.users.includeRoles[$key]
                                if ($null -ne $role -and $role.PSObject.Properties.Name -contains 'displayName') {
                                    $roles += $role.displayName
                                }
                                else {
                                    # If no display name, try to use the key if it looks like a role name
                                    if ($key -match 'Administrator' -or $key -match 'Reader' -or $key -match 'Operator') {
                                        $roles += $key
                                    }
                                }
                            }
                            return ($roles | Sort-Object) -join "`n"
                        }
                        else {
                            # Original extraction for array-based roles
                            Format-ArrayForExcel ($_.conditions.users.includeRoles.PSObject.Properties.Value.displayName | Sort-Object)
                        }
                    }},
                    @{N='Include Guest/External';E={$_.conditions.users.includeGuestsOrExternalUsers}},
                    @{N='Exclude Users';E={
                        $users = @()
                        foreach ($user in $_.conditions.users.excludeUsers.PSObject.Properties.Value) {
                            if ($user.userPrincipalName) { 
                                $users += $user.userPrincipalName
                            }
                        }
                        Format-ArrayForExcel ($users | Sort-Object)
                    }},
                    @{N='Exclude Groups';E={
                        Format-ArrayForExcel ($_.conditions.users.excludeGroups.PSObject.Properties.Value.displayName | Sort-Object)
                    }},
                    @{N='Excluded Group Members';E={
                        $members = @()
                        foreach ($group in $_.conditions.users.excludeGroups.PSObject.Properties.Value) {
                            if ($group.members) {
                                $groupMembers = $group.members.PSObject.Properties.Value.userPrincipalName
                                if ($groupMembers) {
                                    $members += "$($group.displayName):`n  $(($groupMembers | Sort-Object) -join "`n  ")"
                                }
                            }
                        }
                        Format-ArrayForExcel $members
                    }},
                    @{N='Exclude Roles';E={
                        Format-ArrayForExcel ($_.conditions.users.excludeRoles.PSObject.Properties.Value.displayName | Sort-Object)
                    }},
                    @{N='Exclude Guest/External';E={$_.conditions.users.excludeGuestsOrExternalUsers}},
                    @{N='Applications';E={
                        # Handle special case for "All" applications
                        if ($_.conditions.applications.includeApplications -eq "All") { 
                            return "All" 
                        }
                        elseif ($_.conditions.applications.includeApplications -is [hashtable] -and
                                $_.conditions.applications.includeApplications.ContainsKey('All')) {
                            return "All"
                        }
                        else {
                            # Extract application names from either array or hashtable
                            if ($_.conditions.applications.includeApplications -is [hashtable]) {
                                $apps = @()
                                foreach ($key in $_.conditions.applications.includeApplications.Keys) {
                                    $app = $_.conditions.applications.includeApplications[$key]
                                    if ($null -ne $app -and $app.PSObject.Properties.Name -contains 'displayName') {
                                        $apps += $app.displayName
                                    }
                                }
                                return ($apps | Sort-Object) -join "`n"
                            }
                            else {
                                Format-ArrayForExcel ($_.conditions.applications.includeApplications.PSObject.Properties.Value.displayName | Sort-Object)
                            }
                        }
                    }},
                    @{N='Exclude Applications';E={
                        Format-ArrayForExcel ($_.conditions.applications.excludeApplications.PSObject.Properties.Value.displayName | Sort-Object)
                    }},
                    @{N='User Actions';E={Format-ArrayForExcel $_.conditions.applications.includeUserActions}},
                    @{N='Authentication Context';E={Format-ArrayForExcel $_.conditions.applications.includeAuthenticationContextClassReferences}},
                    @{N='Client App Types';E={
                        # Extract client app types from either array or hashtable
                        if ($_.conditions.clientAppTypes -is [hashtable]) {
                            $appTypes = @()
                            foreach ($key in $_.conditions.clientAppTypes.Keys) {
                                $appTypes += $key
                            }
                            return ($appTypes | Sort-Object) -join "`n"
                        }
                        else {
                            Format-ArrayForExcel $_.conditions.clientAppTypes
                        }
                    }},
                    @{N='Device Platforms';E={
                        if ($_.conditions.platforms) {
                            Format-ArrayForExcel $_.conditions.platforms.includePlatforms
                        }
                    }},
                    @{N='Exclude Platforms';E={
                        if ($_.conditions.platforms) {
                            Format-ArrayForExcel $_.conditions.platforms.excludePlatforms
                        }
                    }},
                    @{N='Device State';E={
                        if ($_.conditions.devices.deviceFilter) {
                            $_.conditions.devices.deviceFilter.rule
                        }
                    }},
                    @{N='Locations';E={
                        if ($_.conditions.locations) {
                            Format-ArrayForExcel $_.conditions.locations.includeLocations
                        }
                    }},
                    @{N='Exclude Locations';E={
                        if ($_.conditions.locations) {
                            Format-ArrayForExcel $_.conditions.locations.excludeLocations
                        }
                    }},
                    @{N='User Risk Levels';E={Format-ArrayForExcel $_.conditions.userRiskLevels}},
                    @{N='Sign-in Risk Levels';E={Format-ArrayForExcel $_.conditions.signInRiskLevels}},
                    @{N='Grant Controls';E={Format-ArrayForExcel $_.grantControls.builtInControls}},
                    @{N='Grant Operator';E={$_.grantControls.operator}},
                    @{N='Session Controls';E={
                        if ($_.sessionControls) {
                            $controls = @()
                            foreach ($control in $_.sessionControls.PSObject.Properties) {
                                if ($null -ne $control.Value) {
                                    $controls += "$($control.Name): $($control.Value.isEnabled)"
                                }
                            }
                            Format-ArrayForExcel $controls
                        }
                    }}
                
                # Create a simpler export parameters set - matching the original script
                $excelParams = @{
                    Path = $excelPath
                    FreezeTopRow = $true
                    BoldTopRow = $true
                    AutoFilter = $true
                    WorksheetName = "Policies"  # IMPORTANT: Using the exact name from the original script
                    ConditionalText = $conditionalFormats
                }
                
                # Check if file exists and remove it to avoid conflicts
                if (Test-Path -Path $excelPath) {
                    Remove-Item -Path $excelPath -Force
                    Write-Verbose "Removed existing Excel file to avoid worksheet conflicts"
                }
                
                # First create a simple export with just the overview data
                $overviewData | Export-Excel @excelParams
                
                # Then open the created package to modify column widths
                $excel = Open-ExcelPackage -Path $excelPath
                $ws = $excel.Workbook.Worksheets["Policies"]
                
                # Set column widths - this is key for readability
                if ($null -ne $ws -and $null -ne $ws.Dimension) {
                    1..$ws.Dimension.End.Column | ForEach-Object {
                        $col = $_
                        $headerText = $ws.Cells[1, $col].Text
                        $width = $columnWidths[$headerText]
                        if (-not $width) { $width = $columnWidths['Default'] }
                        $ws.Column($col).Width = $width
                    }
                }
                
                # Create a second sheet for controls if needed
                try {
                    # Add a simple controls summary sheet
                    $controlsSheet = $excel.Workbook.Worksheets.Add("Controls Summary")
                    
                    # Add headers
                    $controlsSheet.Cells[1, 1].Value = "Policy Name"
                    $controlsSheet.Cells[1, 2].Value = "State"
                    $controlsSheet.Cells[1, 3].Value = "MFA Required"
                    $controlsSheet.Cells[1, 4].Value = "Compliant Device" 
                    $controlsSheet.Cells[1, 5].Value = "Domain Joined"
                    $controlsSheet.Cells[1, 6].Value = "Session Controls"
                    
                    # Format the header row
                    1..6 | ForEach-Object {
                        $controlsSheet.Cells[1, $_].Style.Font.Bold = $true
                    }
                    
                    # Add data rows
                    $row = 2
                    foreach ($policy in $allPolicies) {
                        $controlsSheet.Cells[$row, 1].Value = $policy.displayName
                        $controlsSheet.Cells[$row, 2].Value = Format-PolicyState $policy.state
                        
                        # Add MFA status with specific formatting
                        $hasMfa = $null -ne $policy.grantControls -and 
                                 $null -ne $policy.grantControls.builtInControls -and 
                                 $policy.grantControls.builtInControls -contains "mfa"
                        $controlsSheet.Cells[$row, 3].Value = $hasMfa
                        
                        # Add Compliant Device status
                        $hasCompliantDevice = $null -ne $policy.grantControls -and 
                                            $null -ne $policy.grantControls.builtInControls -and 
                                            $policy.grantControls.builtInControls -contains "compliantDevice"
                        $controlsSheet.Cells[$row, 4].Value = $hasCompliantDevice
                        
                        # Add Domain Joined status
                        $hasDomainJoined = $null -ne $policy.grantControls -and 
                                          $null -ne $policy.grantControls.builtInControls -and 
                                          $policy.grantControls.builtInControls -contains "domainJoinedDevice"
                        $controlsSheet.Cells[$row, 5].Value = $hasDomainJoined
                        
                        # Add session controls if any
                        $sessionControlsText = ""
                        if ($null -ne $policy.sessionControls) {
                            $controls = @()
                            foreach ($control in $policy.sessionControls.PSObject.Properties) {
                                if ($null -ne $control.Value -and $control.Value.PSObject.Properties.Name -contains 'isEnabled') {
                                    if ($control.Value.isEnabled -eq $true) {
                                        $controls += $control.Name
                                    }
                                }
                            }
                            $sessionControlsText = $controls -join ", "
                        }
                        $controlsSheet.Cells[$row, 6].Value = $sessionControlsText
                        
                        $row++
                    }
                    
                    # Auto-fit the columns
                    $controlsSheet.Cells.AutoFitColumns()
                } 
                catch {
                    Write-Warning "Could not create Controls Summary sheet: $($_.Exception.Message)"
                }
                
                # Finally, close the package to save changes
                try {
                    Close-ExcelPackage $excel
                    
                    # Verify the Excel file exists and return the path
                    if (Test-Path -Path $excelPath) {
                        Write-Output $excelPath
                    } else {
                        Write-Warning "Failed to create Excel file at $excelPath"
                    }
                }
                catch {
                    Write-Warning "Error closing Excel package: $($_.Exception.Message)"
                }
            }
            catch {
                Write-Warning "Failed to create Excel report: $($_.Exception.Message)"
                
                # Try one final simple export if everything else fails
                try {
                    $overviewData | Export-Excel -Path $excelPath -WorksheetName "Basic" -AutoSize
                    if (Test-Path -Path $excelPath) {
                        Write-Output $excelPath
                    }
                } catch {
                    Write-Warning "All attempts to create Excel report have failed"
                }
            }
        }
    }
}

function Test-PolicyStructure {
    <#
    .SYNOPSIS
        Validates the structure of a Conditional Access policy.
    
    .DESCRIPTION
        This function validates that a Conditional Access policy object has all
        the required properties and structure.
    
    .PARAMETER Policy
        The policy object to validate.
    
    .EXAMPLE
        Test-PolicyStructure -Policy $policy
        
    .NOTES
        This is an internal helper function used by Export-CAExcelReport.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$policy
    )
    
    try {
        $requiredProperties = @('displayName', 'conditions', 'state')
        foreach ($prop in $requiredProperties) {
            if ($null -eq $policy.$prop) {
                Write-Warning "Policy '$($policy.displayName)' is missing required property: $prop"
                return $false
            }
        }
        return $true
    }
    catch {
        Write-Warning "Error validating policy structure: $_"
        return $false
    }
}

function Format-PolicyState {
    <#
    .SYNOPSIS
        Formats a policy state for display in the report.
    
    .DESCRIPTION
        This function formats a policy state value for consistent display in the report.
    
    .PARAMETER State
        The policy state value to format.
    
    .EXAMPLE
        Format-PolicyState -State "enabledForReportingButNotEnforced"
        
    .NOTES
        This is an internal helper function used by Export-CAExcelReport.
    #>
    
    param(
        [string]$state
    )
    
    switch ($state) {
        "enabled" { "Enabled" }
        "enabledForReportingButNotEnforced" { "ReportOnly" }
        "disabled" { "Disabled" }
        default { $state }
    }
}

function Format-ArrayForExcel {
    <#
    .SYNOPSIS
        Formats an array for display in Excel.
    
    .DESCRIPTION
        This function formats an array of values for proper display in an Excel cell,
        joining the values with newlines and removing any empty values.
    
    .PARAMETER Array
        The array to format.
    
    .EXAMPLE
        Format-ArrayForExcel -Array $policy.conditions.clientAppTypes
        
    .NOTES
        This is an internal helper function used by Export-CAExcelReport.
    #>
    
    param($array)
    
    # Handle null or empty collections
    if ($null -eq $array) { return $null }
    if ($array -is [array] -and $array.Count -eq 0) { return $null }
    
    # Handle hashtables specifically 
    if ($array -is [hashtable] -or $array -is [System.Collections.IDictionary]) {
        $values = @()
        foreach ($key in $array.Keys) {
            $item = $array[$key]
            # Try to get the most meaningful property
            if ($item.PSObject.Properties.Name -contains 'displayName' -and ![string]::IsNullOrWhiteSpace($item.displayName)) {
                $values += $item.displayName
            }
            elseif ($item.PSObject.Properties.Name -contains 'userPrincipalName' -and ![string]::IsNullOrWhiteSpace($item.userPrincipalName)) {
                $values += $item.userPrincipalName
            }
            elseif ($key -ne 'PSObject' -and $key -ne 'PSBase' -and $key -ne 'PSTypeNames') {
                # Use the key itself if it's meaningful
                if ($key -eq 'All' -or $key -eq 'None') {
                    $values += $key
                }
                elseif (![string]::IsNullOrWhiteSpace($key)) {
                    $values += $key
                }
            }
        }
        
        if ($values.Count -gt 0) {
            return ($values | Where-Object { ![string]::IsNullOrWhiteSpace($_) }) -join "`n"
        }
        elseif ($array.Count -gt 0) {
            # Special case for "All" value which might be a key in the hashtable
            if ($array.ContainsKey('All')) {
                return "All"
            }
            # Return the first key as a last resort
            return $array.Keys | Select-Object -First 1
        }
        
        return $null
    }
    
    # Handle PSObject properties
    if ($array.PSObject.Properties.Name -contains 'Keys' -and 
        $array.PSObject.Properties.Name -contains 'Values') {
        # This is likely a hashtable or dictionary-like object
        $values = @()
        foreach ($key in $array.Keys) {
            $item = $array[$key]
            if ($null -ne $item -and $item.PSObject.Properties.Name -contains 'displayName') {
                $values += $item.displayName
            }
            elseif ($null -ne $item -and $item.PSObject.Properties.Name -contains 'userPrincipalName') {
                $values += $item.userPrincipalName
            }
            else {
                $values += $key
            }
        }
        
        if ($values.Count -gt 0) {
            return ($values | Where-Object { ![string]::IsNullOrWhiteSpace($_) }) -join "`n"
        }
    }
    
    # Extract displayNames for complex objects
    if ($array -is [array]) {
        $result = @()
        foreach ($item in $array) {
            if ($item -is [string]) {
                $result += $item
            }
            elseif ($null -ne $item -and $item.PSObject.Properties.Name -contains 'displayName') {
                $result += $item.displayName
            }
            elseif ($null -ne $item -and $item.PSObject.Properties.Name -contains 'userPrincipalName') {
                $result += $item.userPrincipalName
            }
            else {
                $result += $item.ToString()
            }
        }
        $array = $result
    }
    
    # Special case for single string "All"
    if ($array -eq "All") {
        return "All"
    }
    
    # Handle PSObject directly - might be a collection
    if ($null -ne $array -and $array.PSObject.Properties.Name -contains 'displayName') {
        return $array.displayName
    }
    
    # Filter non-empty values and join with newlines
    if ($array -is [array]) {
        return ($array | Where-Object { ![string]::IsNullOrWhiteSpace($_) }) -join "`n"
    }
    
    # Last resort: just convert to string
    return $array.ToString()
}

# Export the public function
Export-ModuleMember -Function Export-CAExcelReport 