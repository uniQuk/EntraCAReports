function ConvertTo-CACleanYaml {
    <#
    .SYNOPSIS
        Cleans and normalizes Conditional Access policies in YAML format.
    
    .DESCRIPTION
        This function processes YAML files containing Conditional Access policies,
        removes empty values, and orders properties for better readability and
        version control. It can process either YAML files in a directory or
        policy objects directly.
    
    .PARAMETER Policies
        The Conditional Access policies to clean. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy YAML files.
        
    .PARAMETER OutputPath
        The path where cleaned YAML files will be saved. If not specified, uses the configured path.
        
    .PARAMETER ReturnObjects
        Switch to return the cleaned policy objects instead of writing to files.
        
    .EXAMPLE
        ConvertTo-CACleanYaml -Path "./policies/yaml/complete" -OutputPath "./policies/yaml/clean"
    
    .EXAMPLE
        Get-CAPolicy | ConvertTo-CAYaml | ConvertTo-CACleanYaml -ReturnObjects
    
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
        [switch]$ReturnObjects
    )
    
    begin {
        # Check if powershell-yaml module is available
        if (-not (Get-Module -ListAvailable -Name 'powershell-yaml')) {
            Write-Error "The powershell-yaml module is required for this function. Please install it with: Install-Module powershell-yaml -Scope CurrentUser"
            return
        }
        
        # Import the module
        try {
            Import-Module 'powershell-yaml' -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to import the powershell-yaml module: $_"
            return
        }
        
        # Get the proper output path if not specified
        if ([string]::IsNullOrEmpty($OutputPath)) {
            # Get configuration to determine proper paths
            $config = Get-CAConfig
            $basePath = $config.OutputPaths.Base
            $cleanPath = $config.OutputPaths.Clean
            $OutputPath = Join-Path -Path $basePath -ChildPath $cleanPath
            Write-Verbose "Using configured output path: $OutputPath"
        }
        
        # Initialize collections if using pipeline input
        if ($PSCmdlet.ParameterSetName -eq "FromPolicies") {
            $allPolicies = @()
        }
        
        # Create output directory if it doesn't exist and not just returning objects
        if (![string]::IsNullOrEmpty($OutputPath) -and !$ReturnObjects) {
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
        # Load policies from YAML files if specified
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            $allPolicies = try {
                Get-ChildItem -Path $Path -Filter "*.yaml" -ErrorAction Stop | 
                ForEach-Object { 
                    try {
                        $yamlContent = Get-Content $_.FullName -Raw
                        $policy = ConvertFrom-Yaml $yamlContent
                        
                        # Add metadata about the source file
                        $policy | Add-Member -NotePropertyName SourceFileName -NotePropertyValue $_.Name -Force
                        $policy | Add-Member -NotePropertyName SourceFilePath -NotePropertyValue $_.FullName -Force
                        
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
        
        # Check if we have any policies to process
        if ($null -eq $allPolicies -or ($allPolicies -is [array] -and $allPolicies.Count -eq 0)) {
            Write-Warning "No policies available to convert to clean YAML."
            return [PSCustomObject]@{
                CleanedFiles = @()
                TotalCleaned = 0
            }
        }
        
        # Process each policy
        $cleanedPolicies = @()
        
        foreach ($policy in $allPolicies) {
            # Skip null policies
            if ($null -eq $policy) {
                Write-Verbose "Skipping null policy object."
                continue
            }
            
            # Clean and order the policy
            try {
                # Check if the policy has the necessary structure before cleaning
                if ($null -eq $policy.displayName) {
                    Write-Warning "Policy is missing displayName property, adding a default name."
                    $policy | Add-Member -NotePropertyName displayName -NotePropertyValue "Unnamed Policy" -Force
                }
                
                # Use defensive programming when calling the pipeline operators
                $cleanedPolicy = $null
                try {
                    # First remove empty values
                    $intermediatePolicy = Remove-EmptyValues -InputObject $policy
                    
                    # Then format the properties if the previous step succeeded
                    if ($null -ne $intermediatePolicy) {
                        $cleanedPolicy = Format-PolicyProperties -InputObject $intermediatePolicy
                    } else {
                        Write-Warning "Failed to remove empty values from policy '$($policy.displayName)'."
                        # Use the original policy as fallback
                        $cleanedPolicy = $policy
                    }
                }
                catch {
                    Write-Warning "Error during policy cleanup pipeline: $_"
                    # Use the original policy as fallback
                    $cleanedPolicy = $policy
                }
                
                # Ensure we have a policy object to work with
                if ($null -eq $cleanedPolicy) {
                    Write-Warning "Cleanup resulted in a null policy object, using original policy."
                    $cleanedPolicy = $policy
                }
                
                if ($ReturnObjects) {
                    # Add to collection for return
                    $cleanedPolicies += $cleanedPolicy
                }
                else {
                    # Determine output filename
                    $outputFileName = if ($PSCmdlet.ParameterSetName -eq "FromPath" -and 
                                          $null -ne $policy.SourceFileName) {
                        $policy.SourceFileName
                    } else {
                        # Create a safe filename
                        $safeName = if ($null -ne $policy.displayName) {
                            $policy.displayName -replace '[^\w\-\.]', '_'
                        } else {
                            "Policy_" + (New-Guid).ToString().Substring(0, 8)
                        }
                        "$safeName.yaml"
                    }
                    
                    # Convert to YAML and save with error handling
                    try {
                        $cleanedYaml = $cleanedPolicy | ConvertTo-Yaml -ErrorAction Stop
                        
                        if ([string]::IsNullOrEmpty($cleanedYaml)) {
                            Write-Warning "YAML conversion produced empty result for policy '$($policy.displayName)'."
                            continue
                        }
                        
                        $outputFilePath = Join-Path $OutputPath $outputFileName
                        $cleanedYaml | Out-File $outputFilePath -Encoding UTF8
                        
                        Write-Verbose "Cleaned and saved policy to: $outputFilePath"
                        
                        # Add to results
                        $cleanedPolicies += [PSCustomObject]@{
                            PolicyName = $policy.displayName
                            FileName = $outputFileName
                            FilePath = $outputFilePath
                        }
                    }
                    catch {
                        Write-Warning "Error converting policy '$($policy.displayName)' to YAML: $_"
                    }
                }
            }
            catch {
                Write-Warning "Error processing policy '$($policy.displayName)': $_"
            }
        }
        
        # Return results
        if ($ReturnObjects) {
            return $cleanedPolicies
        } else {
            return [PSCustomObject]@{
                CleanedFiles = $cleanedPolicies
                TotalCleaned = $cleanedPolicies.Count
            }
        }
    }
}

function Remove-EmptyValues {
    <#
    .SYNOPSIS
        Removes empty values from an object.
    
    .DESCRIPTION
        This function recursively processes an object and removes all empty values,
        including empty strings, empty arrays, empty dictionaries, and null values.
    
    .PARAMETER InputObject
        The object to process.
    
    .EXAMPLE
        $cleanObject = $myObject | Remove-EmptyValues
    
    .NOTES
        This is an internal helper function used by ConvertTo-CACleanYaml.
    #>
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [AllowNull()]
        [object]$InputObject
    )
    
    process {
        # Handle null input
        if ($null -eq $InputObject) {
            return $null
        }
        
        if ($InputObject -is [System.Collections.IDictionary]) {
            $result = @{}
            foreach ($key in @($InputObject.Keys)) {
                $value = Remove-EmptyValues $InputObject[$key]
                if ($null -ne $value -and $value -ne '' -and 
                    (-not ($value -is [array] -and $value.Count -eq 0)) -and
                    (-not ($value -is [System.Collections.IDictionary] -and $value.Count -eq 0))) {
                    $result[$key] = $value
                }
            }
            return $result
        }
        elseif ($InputObject -is [array]) {
            $result = @($InputObject | ForEach-Object { Remove-EmptyValues $_ } | Where-Object { 
                $null -ne $_ -and $_ -ne '' -and
                (-not ($_ -is [array] -and $_.Count -eq 0)) -and
                (-not ($_ -is [System.Collections.IDictionary] -and $_.Count -eq 0))
            })
            return $result
        }
        elseif ($InputObject -is [PSCustomObject]) {
            $result = [PSCustomObject]@{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $value = Remove-EmptyValues $property.Value
                if ($null -ne $value -and $value -ne '' -and 
                    (-not ($value -is [array] -and $value.Count -eq 0)) -and
                    (-not ($value -is [System.Collections.IDictionary] -and $value.Count -eq 0))) {
                    $result | Add-Member -MemberType NoteProperty -Name $property.Name -Value $value
                }
            }
            return $result
        }
        else {
            return $InputObject
        }
    }
}

function Format-PolicyProperties {
    <#
    .SYNOPSIS
        Formats properties of a Conditional Access policy object for consistent ordering.
    
    .DESCRIPTION
        This function formats the properties of a Conditional Access policy object
        according to a predefined order, with important properties like displayName
        and state appearing first.
    
    .PARAMETER InputObject
        The policy object to format.
    
    .EXAMPLE
        $formattedPolicy = $policy | Format-PolicyProperties
    
    .NOTES
        This is an internal helper function used by ConvertTo-CACleanYaml.
    #>
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [AllowNull()]
        [object]$InputObject
    )
    
    process {
        # Handle null input
        if ($null -eq $InputObject) {
            return $null
        }
        
        # Define the preferred order of properties
        $propertyOrder = @(
            'displayName',
            'state',
            'createdDateTime',
            'modifiedDateTime',
            'id'
        )
        
        # Handle different input types
        if ($InputObject -is [System.Collections.IDictionary]) {
            $orderedData = [ordered]@{}
            
            # First add the properties in our preferred order
            foreach ($prop in $propertyOrder) {
                if ($InputObject.ContainsKey($prop)) {
                    $orderedData[$prop] = $InputObject[$prop]
                }
            }
            
            # Then add all remaining properties
            foreach ($key in $InputObject.Keys) {
                if (-not $propertyOrder.Contains($key)) {
                    $orderedData[$key] = $InputObject[$key]
                }
            }
            
            return $orderedData
        }
        elseif ($InputObject -is [PSCustomObject]) {
            $orderedData = [PSCustomObject]@{}
            
            # First add the properties in our preferred order
            foreach ($prop in $propertyOrder) {
                if ($InputObject.PSObject.Properties[$prop]) {
                    $orderedData | Add-Member -MemberType NoteProperty -Name $prop -Value $InputObject.$prop
                }
            }
            
            # Then add all remaining properties
            foreach ($property in $InputObject.PSObject.Properties) {
                if (-not $propertyOrder.Contains($property.Name)) {
                    $orderedData | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
                }
            }
            
            return $orderedData
        }
        else {
            # If it's not a dictionary or PSObject, just return as is
            return $InputObject
        }
    }
}

# Export the public function
Export-ModuleMember -Function ConvertTo-CACleanYaml 