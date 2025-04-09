function Initialize-CAFolders {
    <#
    .SYNOPSIS
        Creates the required folder structure for CAReports output.
    
    .DESCRIPTION
        This function creates all necessary folders for CAReports to store its 
        output data, including policies, analysis, diagrams, and other artifacts.
    
    .PARAMETER Path
        Optional base path where to create the folder structure. 
        If not specified, uses the configured base path.
    
    .EXAMPLE
        Initialize-CAFolders
        
    .EXAMPLE
        Initialize-CAFolders -Path "C:\Output\MyReport"
        
    .NOTES
        This is an internal helper function used by various CAReports functions.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path
    )
    
    try {
        # Get the module configuration
        $config = Get-CAConfig
        
        # Use provided path or get from config
        if ([string]::IsNullOrEmpty($Path)) {
            $basePath = $config.OutputPaths.Base
            Write-Verbose "Using configured base path: $basePath"
        } else {
            $basePath = $Path
            Write-Verbose "Using provided base path: $basePath"
        }
        
        # Ensure path is fully qualified
        if (-not [System.IO.Path]::IsPathRooted($basePath)) {
            $basePath = Join-Path -Path (Get-Location).Path -ChildPath $basePath
            Write-Verbose "Converting to absolute path: $basePath"
        }
        
        Write-Verbose "Creating folder structure in: $basePath"
        
        # Ensure base path exists
        if (!(Test-Path -Path $basePath)) {
            New-Item -ItemType Directory -Path $basePath -Force | Out-Null
            Write-Verbose "Created base folder: $basePath"
        } else {
            Write-Verbose "Base folder already exists: $basePath"
        }
        
        # Create required subfolders with full paths
        $folders = @(
            (Join-Path $basePath $config.OutputPaths.Policies),
            (Join-Path $basePath $config.OutputPaths.Original),
            (Join-Path $basePath $config.OutputPaths.Data),
            (Join-Path $basePath $config.OutputPaths.Analysis),
            (Join-Path $basePath $config.OutputPaths.Diagrams),
            (Join-Path $basePath $config.OutputPaths.Excel),
            (Join-Path $basePath $config.OutputPaths.Markdown),
            (Join-Path $basePath $config.OutputPaths.Yaml),
            (Join-Path $basePath $config.OutputPaths.Clean)
        )
        
        # Create each folder
        foreach ($folder in $folders) {
            if (!(Test-Path -Path $folder)) {
                try {
                    $newFolder = New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
                    Write-Verbose "Created folder: $folder"
                } catch {
                    Write-Warning "Failed to create folder: $folder - Error: $_"
                }
            } else {
                Write-Verbose "Folder already exists: $folder"
            }
        }
        
        # Update CAConfig with the actual base path used
        $script:CAConfig.BaseOutputPath = $basePath
        Write-Verbose "Updated script:CAConfig.BaseOutputPath to: $basePath"
        
        # Return the base path created
        return $basePath
    }
    catch {
        Write-Error "Error creating folder structure: $_"
        throw
    }
} 