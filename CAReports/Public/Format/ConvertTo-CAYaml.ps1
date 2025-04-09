function ConvertTo-CAYaml {
    <#
    .SYNOPSIS
        Converts Conditional Access policies from JSON to YAML format.
    
    .DESCRIPTION
        This function converts Conditional Access policies from JSON to YAML format
        for better readability and version control. It can process either individual
        policy objects or JSON files in a directory.
    
    .PARAMETER Policies
        The Conditional Access policies to convert. Can be provided as an array of policy objects.
    
    .PARAMETER Path
        The path to the directory containing Conditional Access policy JSON files.
        
    .PARAMETER OutputPath
        The path where YAML files will be saved. If not specified, uses the configured path.
    
    .PARAMETER GenerateManifest
        Switch to generate a manifest file that maps YAML filenames to original policy names.
        
    .PARAMETER UseSafeFileNames
        Switch to use MD5 hashed filenames for the YAML files. This ensures valid filenames
        regardless of policy name content.
        
    .EXAMPLE
        Get-CAPolicy | ConvertTo-CAYaml -OutputPath "./policies/yaml"
    
    .EXAMPLE
        ConvertTo-CAYaml -Path "./policies/data" -GenerateManifest
    
    .NOTES
        This function requires the powershell-yaml module to be installed.
        You can install it with: Install-Module powershell-yaml -Scope CurrentUser
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
        [switch]$GenerateManifest,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseSafeFileNames
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
            $yamlPath = Join-Path -Path $basePath -ChildPath $config.OutputPaths.Yaml
            $OutputPath = $yamlPath
            Write-Verbose "Using configured output path: $OutputPath"
        }
        
        # Initialize collections if using pipeline input
        if ($PSCmdlet.ParameterSetName -eq "FromPolicies") {
            $allPolicies = @()
        }
        
        # Create output directory if it doesn't exist
        if (![string]::IsNullOrEmpty($OutputPath)) {
            New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
            Write-Verbose "Created output directory: $OutputPath"
        }
        
        # Initialize manifest
        $manifest = @{}
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
                        
                        # Add metadata about the source file
                        $policy | Add-Member -NotePropertyName SourceFileName -NotePropertyValue $_.Name -Force
                        $policy | Add-Member -NotePropertyName SourceBaseName -NotePropertyValue $_.BaseName -Force
                        
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
        
        # Convert each policy to YAML and save
        $convertedFiles = @()
        
        foreach ($policy in $allPolicies) {
            # Determine the base filename (without extension)
            $baseFileName = if ($PSCmdlet.ParameterSetName -eq "FromPath") {
                $policy.SourceBaseName
            } else {
                $policy.displayName
            }
            
            # Generate filename
            $fileName = if ($UseSafeFileNames) {
                Get-SafeFileName -originalName $baseFileName
            } else {
                # Create a safe filename based on displayName (fallback to a random name if empty)
                $safeName = if ($policy.displayName) {
                    $policy.displayName -replace '[^\w\-\.]', '_'
                } else {
                    "Policy_" + (New-Guid).ToString().Substring(0, 8)
                }
                "$safeName.yaml"
            }
            
            # Convert to YAML
            $yamlContent = $policy | ConvertTo-Yaml
            
            # Save to file
            $outputFilePath = Join-Path $OutputPath $fileName
            $yamlContent | Out-File $outputFilePath -Encoding UTF8
            
            Write-Verbose "Converted policy '$($policy.displayName)' to YAML: $fileName"
            
            # Add to manifest if requested
            if ($GenerateManifest) {
                $manifest[$fileName] = @{
                    OriginalName = $baseFileName
                    PolicyDisplayName = $policy.displayName
                }
            }
            
            # Add to results
            $convertedFiles += [PSCustomObject]@{
                PolicyName = $policy.displayName
                FileName = $fileName
                FilePath = $outputFilePath
            }
        }
        
        # Save manifest if requested
        if ($GenerateManifest -and $manifest.Count -gt 0) {
            $manifestPath = Join-Path $OutputPath "policy_manifest.json"
            $manifest | ConvertTo-Json | Out-File $manifestPath -Encoding UTF8
            Write-Verbose "Generated policy manifest: $manifestPath"
        }
        
        # Return the results
        return [PSCustomObject]@{
            ConvertedFiles = $convertedFiles
            ManifestPath = if ($GenerateManifest) { $manifestPath } else { $null }
            TotalConverted = $convertedFiles.Count
        }
    }
}

function Get-SafeFileName {
    <#
    .SYNOPSIS
        Generates a safe filename based on an MD5 hash of the input string.
    
    .DESCRIPTION
        This function takes an input string and generates a safe filename by creating
        an MD5 hash of the input and prefixing it with "CA_".
    
    .PARAMETER OriginalName
        The original string to convert to a safe filename.
    
    .EXAMPLE
        Get-SafeFileName -OriginalName "Policy with special characters: <>/\"
    
    .NOTES
        This is an internal helper function used by ConvertTo-CAYaml.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$OriginalName
    )
    
    # Create MD5 hash
    $hash = [System.Security.Cryptography.MD5]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($OriginalName)
    )
    
    # Convert hash to hex string and take first 8 characters
    $shortHash = [System.BitConverter]::ToString($hash).Replace("-", "").Substring(0, 8)
    
    # Return safe filename
    return "CA_" + $shortHash + ".yaml"
}

# Export the function
Export-ModuleMember -Function ConvertTo-CAYaml 