function Export-CAYamlReport {
    <#
    .SYNOPSIS
        Generates a summary report of Conditional Access policies in YAML format.
    
    .DESCRIPTION
        This function reads YAML files containing Conditional Access policies and
        generates a comprehensive Markdown summary report. The report includes
        a table of contents and detailed information about each policy.
    
    .PARAMETER Policies
        The Conditional Access policies to include in the report. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy YAML files.
        
    .PARAMETER OutputPath
        The path where the Markdown report will be saved. Defaults to the configured Markdown path.
        
    .PARAMETER ReportFileName
        The filename for the generated report. Defaults to "ca-summary.md".
    
    .EXAMPLE
        Export-CAYamlReport -Path "./policies/yaml/clean" -OutputPath "./docs"
    
    .EXAMPLE
        Get-CAPolicy | ConvertTo-CAYaml -ReturnObjects | Export-CAYamlReport -OutputPath "./reports"
    
    .NOTES
        This function requires the powershell-yaml module to be installed.
        You can install it with: Install-Module powershell-yaml -Scope CurrentUser
    #>
    
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    param (
        [Parameter(Mandatory=$true, ParameterSetName="FromPolicies", ValueFromPipeline=$true)]
        [PSCustomObject[]]$Policies,
        
        [Parameter(Mandatory=$true, ParameterSetName="FromPath")]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportFileName = "ca-summary.md"
    )
    
    begin {
        # Get config paths
        if ([string]::IsNullOrEmpty($OutputPath)) {
            $config = Get-CAConfig
            $OutputPath = Join-Path -Path $config.OutputPaths.Base -ChildPath $config.OutputPaths.Markdown
        }
    
        # Check if powershell-yaml module is available when loading from YAML files
        if ($PSCmdlet.ParameterSetName -eq "FromPath" -and 
            -not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
            Write-Error "The powershell-yaml module is required for this function when loading from YAML files. Please install it with: Install-Module powershell-yaml -Scope CurrentUser"
            return
        }
        
        # Import the module if needed
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            try {
                Import-Module 'powershell-yaml' -ErrorAction Stop
            }
            catch {
                Write-Error "Failed to import the powershell-yaml module: $_"
                return
            }
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
        # Load policies from YAML files if specified
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            $allPolicies = try {
                Get-ChildItem -Path $Path -Filter "*.yaml" -ErrorAction Stop | 
                ForEach-Object { 
                    try {
                        $yamlContent = Get-Content $_.FullName -Raw
                        $policy = ConvertFrom-Yaml $yamlContent
                        
                        # Add metadata about the source file
                        $policy | Add-Member -NotePropertyName "SourceFile" -NotePropertyValue $_.Name -Force
                        
                        $policy
                    }
                    catch {
                        Write-Warning "Failed to parse YAML file: $($_.Name)"
                        Write-Warning $_.Exception.Message
                        return
                    }
                }
            }
            catch {
                Write-Error "Failed to read YAML files: $_"
                return
            }
        }
        
        # Add source file property if missing (for policies from pipeline)
        foreach ($policy in $allPolicies) {
            if (-not $policy.PSObject.Properties['SourceFile']) {
                $safeName = if ($policy.displayName) {
                    $policy.displayName -replace '[^\w\-\.]', '_'
                } else {
                    "Policy_" + (New-Guid).ToString().Substring(0, 8)
                }
                $policy | Add-Member -NotePropertyName "SourceFile" -NotePropertyValue "$safeName.yaml" -Force
            }
        }
        
        # Sort policies by display name
        $allPolicies = $allPolicies | Sort-Object { $_.displayName }
        
        # Generate table of contents
        $toc = "## Table of Contents`n`n"
        foreach ($policy in $allPolicies) {
            # Create a valid anchor link
            $anchor = $policy.displayName.ToLower() -replace '[^a-z0-9\s-]','' -replace '\s','-'
            $toc += "- [$($policy.displayName)](#$anchor)`n"
        }
        
        # Generate policy details
        $policyDetails = @()
        foreach ($policy in $allPolicies) {
            $policyDetails += Get-PolicyDetails -policy $policy
        }
        
        # Generate main documentation
        $documentation = "# Conditional Access Policies`n`n"
        $documentation += $toc
        $documentation += "`n# Detailed Policy Documentation`n"
        $documentation += ($policyDetails -join "`n")
        
        # Write documentation to file
        $outputFilePath = Join-Path $OutputPath $ReportFileName
        $documentation | Out-File $outputFilePath -Encoding UTF8
        
        Write-Verbose "Documentation generated at $outputFilePath"
        
        # Return result
        return [PSCustomObject]@{
            ReportPath = $outputFilePath
            TotalPolicies = $allPolicies.Count
        }
    }
}

function Format-DateTime {
    <#
    .SYNOPSIS
        Formats a datetime string consistently.
    
    .DESCRIPTION
        This function formats a datetime string in a consistent format (dd-MM-yyyy HH:mm).
        If the input is empty or invalid, it returns appropriate placeholder text.
    
    .PARAMETER DateTimeString
        The datetime string to format.
    
    .EXAMPLE
        Format-DateTime -DateTimeString "2025-10-20T12:34:56Z"
        
    .NOTES
        This is an internal helper function used by Export-CAYamlReport.
    #>
    
    param(
        [string]$dateTimeString
    )
    
    if ([string]::IsNullOrEmpty($dateTimeString)) {
        return "N/A"
    }
    try {
        return ([DateTime]$dateTimeString).ToString("dd-MM-yyyy HH:mm")
    }
    catch {
        return "Invalid date"
    }
}

function Format-PolicyValue {
    <#
    .SYNOPSIS
        Formats a policy value for display in the report.
    
    .DESCRIPTION
        This function recursively formats a policy value for display in the report,
        handling dictionaries, arrays, and scalar values appropriately.
    
    .PARAMETER Value
        The value to format.
    
    .EXAMPLE
        Format-PolicyValue -Value $policy.conditions
        
    .NOTES
        This is an internal helper function used by Export-CAYamlReport.
    #>
    
    param($value)
    
    if ($null -eq $value) { return $null }
    
    if ($value -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $value.Keys) {
            $formattedValue = Format-PolicyValue $value[$key]
            if ($null -ne $formattedValue) {
                $result[$key] = $formattedValue
            }
        }
        return $result
    }
    elseif ($value -is [PSCustomObject]) {
        $result = @{}
        foreach ($property in $value.PSObject.Properties) {
            $formattedValue = Format-PolicyValue $property.Value
            if ($null -ne $formattedValue) {
                $result[$property.Name] = $formattedValue
            }
        }
        return $result
    }
    elseif ($value -is [array]) {
        # Return the actual array elements, not just the length
        return @($value | Where-Object { $null -ne $_ })
    }
    else {
        return $value
    }
}

function Format-PropertyDetails {
    <#
    .SYNOPSIS
        Formats a property and its value for display in the report.
    
    .DESCRIPTION
        This function formats a property and its value for display in the report,
        with appropriate indentation based on the property hierarchy.
    
    .PARAMETER PropertyName
        The name of the property.
        
    .PARAMETER PropertyValue
        The value of the property.
        
    .PARAMETER IndentLevel
        The indentation level for the property in the hierarchy.
    
    .EXAMPLE
        Format-PropertyDetails -PropertyName "conditions" -PropertyValue $policy.conditions -IndentLevel 0
        
    .NOTES
        This is an internal helper function used by Export-CAYamlReport.
    #>
    
    param(
        [string]$propertyName,
        $propertyValue,
        [int]$indentLevel = 0
    )
    
    if ($null -eq $propertyValue -or $propertyValue -eq '') {
        return $null
    }
    
    $indent = "  " * $indentLevel
    $details = ""
    
    if ($propertyValue -is [System.Collections.IDictionary]) {
        $details += "`n$indent- **$propertyName**:"
        foreach ($item in $propertyValue.GetEnumerator() | Where-Object { $null -ne $_.Value }) {
            $subDetails = Format-PropertyDetails -propertyName $item.Key -propertyValue $item.Value -indentLevel ($indentLevel + 1)
            if ($subDetails) {
                $details += $subDetails
            }
        }
    }
    elseif ($propertyValue -is [PSCustomObject]) {
        $details += "`n$indent- **$propertyName**:"
        foreach ($property in $propertyValue.PSObject.Properties) {
            if ($null -ne $property.Value) {
                $subDetails = Format-PropertyDetails -propertyName $property.Name -propertyValue $property.Value -indentLevel ($indentLevel + 1)
                if ($subDetails) {
                    $details += $subDetails
                }
            }
        }
    }
    elseif ($propertyValue -is [array]) {
        if ($propertyValue.Count -gt 0) {
            $isComplexArray = $propertyValue | Where-Object { 
                $_ -is [System.Collections.IDictionary] -or $_ -is [PSCustomObject] 
            }
            
            if ($isComplexArray) {
                $details += "`n$indent- **$propertyName**:"
                foreach ($item in $propertyValue) {
                    if ($item -is [System.Collections.IDictionary] -or $item -is [PSCustomObject]) {
                        foreach ($key in $item.PSObject.Properties) {
                            $subDetails = Format-PropertyDetails -propertyName $key.Name -propertyValue $key.Value -indentLevel ($indentLevel + 1)
                            if ($subDetails) {
                                $details += $subDetails
                            }
                        }
                    } else {
                        $details += "`n$indent  - $item"
                    }
                }
            } else {
                # Display array contents instead of showing length
                $details += "`n$indent- **$propertyName**:"
                foreach ($item in $propertyValue) {
                    $details += "`n$indent  - $item"
                }
            }
        }
    }
    else {
        $details += "`n$indent- **$propertyName**: $propertyValue"
    }
    
    return $details
}

function Get-PolicyDetails {
    <#
    .SYNOPSIS
        Generates detailed documentation for a policy.
    
    .DESCRIPTION
        This function generates detailed Markdown documentation for a Conditional Access policy,
        including basic information and all policy properties.
    
    .PARAMETER Policy
        The policy object to document.
    
    .EXAMPLE
        Get-PolicyDetails -Policy $policy
        
    .NOTES
        This is an internal helper function used by Export-CAYamlReport.
    #>
    
    param($policy)
    
    $details = "### $($policy.displayName)`n"
    $details += "[🔼 Back to top](#table-of-contents)`n`n"
    
    # Add basic information
    $details += "- **File**: $($policy.SourceFile) _(Original: $($policy.displayName))_`n"
    $details += "- **State**: $($policy.state)`n"
    $details += "- **Created**: $(Format-DateTime $policy.createdDateTime)`n"
    $details += "- **Modified**: $(if ($policy.modifiedDateTime) { Format-DateTime $policy.modifiedDateTime } else { 'Never' })`n"
    $details += "- **ID**: $($policy.id)`n"

    # Process all policy properties except basic info
    $excludeProperties = @('displayName', 'state', 'createdDateTime', 'modifiedDateTime', 'id', 
                           'Keys', 'Values', 'Count', 'SourceFile', 'SourceFileName', 'SourceFilePath')
    
    foreach ($prop in $policy.PSObject.Properties) {
        if ($prop.Name -notin $excludeProperties -and $null -ne $prop.Value) {
            $formattedValue = Format-PolicyValue $prop.Value
            if ($null -ne $formattedValue) {
                $details += Format-PropertyDetails -propertyName $prop.Name -propertyValue $formattedValue
            }
        }
    }

    $details += "`n`n"
    return $details
}

# Export the public function
Export-ModuleMember -Function Export-CAYamlReport 