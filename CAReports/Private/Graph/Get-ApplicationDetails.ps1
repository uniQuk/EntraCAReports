function Get-ApplicationDetails {
    <#
    .SYNOPSIS
        Retrieves information about an application used in Conditional Access policies.
    
    .DESCRIPTION
        Gets information about an application identified by its ID. The function handles
        several types of application identifiers:
        - Built-in identifiers (e.g., "All", "Office365", "MicrosoftAdminPortals")
        - Known application GUIDs from the configuration file
        - Application GUIDs that can be resolved via Microsoft Graph API
    
    .PARAMETER AppId
        The ID of the application to retrieve information for.
    
    .PARAMETER KnownAppsPath
        Optional path to a file containing known application ID to name mappings.
        If not provided, will look for a file at "../config/knownApps.txt" relative to the module's location.
    
    .EXAMPLE
        Get-ApplicationDetails -AppId "All"
        
        Returns information about the built-in "All Applications" identifier.
    
    .EXAMPLE
        Get-ApplicationDetails -AppId "00000003-0000-0000-c000-000000000000"
        
        Returns information about the application with the specified GUID.
    
    .NOTES
        This function requires a connection to Microsoft Graph established through Connect-CAGraph
        for resolving application GUIDs that are not built-in or in the known apps file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$AppId,
        
        [Parameter(Mandatory = $false)]
        [string]$KnownAppsPath
    )
    
    # Define basic known apps (for non-GUID identifiers)
    $basicKnownApps = @{
        "MicrosoftAdminPortals" = "Microsoft Admin Portals"
        "Office365" = "Office 365"
        "All" = "All Applications"
    }

    # Check basic known apps first
    if ($basicKnownApps.ContainsKey($AppId)) {
        return @{
            displayName = $basicKnownApps[$AppId]
            id = $AppId
        }
    }
    
    # Determine path to known apps file if not provided
    if (-not $KnownAppsPath) {
        $moduleRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
        $KnownAppsPath = Join-Path -Path $moduleRoot -ChildPath "config/knownApps.txt"
    }
    
    # Load known applications from file (for GUID identifiers)
    $knownApps = @{}
    
    if (Test-Path $KnownAppsPath) {
        Get-Content $KnownAppsPath | ForEach-Object {
            if ($_ -match '^"([^"]+)"\s*=\s*"([^"]+)"$') {
                $knownApps[$matches[1]] = $matches[2]
            }
        }
    } else {
        Write-Verbose "Known apps file not found at: $KnownAppsPath"
    }

    # Check if it's a known GUID app
    if ($knownApps.ContainsKey($AppId)) {
        return @{
            displayName = $knownApps[$AppId]
            id = $AppId
        }
    }

    # Only try Graph API for GUID-like strings
    if ($AppId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        try {
            $app = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$AppId')"
            return @{
                displayName = $app.displayName
                id = $AppId
            }
        }
        catch {
            Write-Warning "Failed to get details for application $AppId : $_"
        }
    }

    # Return unknown application if all else fails
    return @{
        displayName = "Unknown Application ($AppId)"
        id = $AppId
    }
} 