function Get-CAConfig {
    <#
    .SYNOPSIS
        Gets the current CAReports configuration.
    
    .DESCRIPTION
        This function retrieves the current CAReports configuration, including
        output paths, API settings, and application preferences.
    
    .PARAMETER Path
        Optional path to retrieve a specific configuration section.
        
    .PARAMETER DefaultValue
        Optional default value to return if the configuration path is not found.
    
    .EXAMPLE
        Get-CAConfig
        
        Returns the complete configuration hashtable.
    
    .EXAMPLE
        Get-CAConfig -Path "OutputPaths.Base"
        
        Returns the value of the Base property in the OutputPaths section.
    
    .EXAMPLE
        Get-CAConfig -Path "NonExistentPath" -DefaultValue "DefaultValue"
        
        Returns "DefaultValue" because the path doesn't exist.
    
    .NOTES
        This is an internal function used by other CAReports functions.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        $DefaultValue
    )
    
    # Ensure the configuration is loaded
    $configPath = Join-Path -Path $script:ModuleRoot -ChildPath "config\default-config.psd1"
    if (-not (Test-Path -Path $configPath)) {
        Write-Error "Configuration file not found: $configPath"
        return $null
    }
    
    # Import the default configuration
    $defaultConfig = Import-PowerShellDataFile -Path $configPath
    
    # Combine with runtime config
    $fullConfig = $defaultConfig.Clone()
    
    # Handle the base path properly
    if ($script:CAConfig.BaseOutputPath) {
        # Use the path specified at runtime
        $fullConfig.OutputPaths.Base = $script:CAConfig.BaseOutputPath
    }
    
    # Convert relative paths to absolute if they aren't already absolute
    if (-not [System.IO.Path]::IsPathRooted($fullConfig.OutputPaths.Base)) {
        $fullConfig.OutputPaths.Base = Join-Path -Path (Get-Location).Path -ChildPath $fullConfig.OutputPaths.Base
    }
    
    # Update other runtime values
    $fullConfig.RuntimeConfig = $script:CAConfig
    
    # If no path specified, return the full configuration
    if ([string]::IsNullOrEmpty($Path)) {
        return $fullConfig
    }
    
    # Parse the path and navigate the configuration
    $pathParts = $Path.Split('.')
    $current = $fullConfig
    
    foreach ($part in $pathParts) {
        if ($current -is [hashtable] -or $current -is [System.Collections.Specialized.OrderedDictionary]) {
            if ($current.ContainsKey($part)) {
                $current = $current[$part]
            } else {
                # Path segment not found, return default value
                return $DefaultValue
            }
        } else {
            # Current position is not a hashtable, return default value
            return $DefaultValue
        }
    }
    
    return $current
} 