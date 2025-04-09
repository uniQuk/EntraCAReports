function Get-RoleDetails {
    <#
    .SYNOPSIS
        Retrieves detailed information about a Microsoft Entra ID directory role.
    
    .DESCRIPTION
        Gets detailed information about a Microsoft Entra ID directory role or role template,
        including display name and identifier.
    
    .PARAMETER RoleId
        The ID of the role or role template to retrieve.
    
    .PARAMETER IsRoleTemplate
        Whether the provided ID is a role template ID rather than a directory role ID.
        If true, the function will query the role templates endpoint.
        If false, the function will query the directory roles endpoint.
        Default is $true, assuming most conditional access policies reference role templates.
    
    .EXAMPLE
        Get-RoleDetails -RoleId "62e90394-69f5-4237-9190-012177145e10"
        
        Retrieves information about the specified role template.
    
    .EXAMPLE
        Get-RoleDetails -RoleId "69091246-20e8-4a56-aa4d-066075b2a7a8" -IsRoleTemplate $false
        
        Retrieves information about the specified directory role.
    
    .NOTES
        This function requires a connection to Microsoft Graph established through Connect-CAGraph.
        Most conditional access policies reference role templates rather than directory roles.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$RoleId,
        
        [Parameter(Mandatory = $false)]
        [bool]$IsRoleTemplate = $true
    )
    
    try {
        # Try to get role based on the specified type
        if ($IsRoleTemplate) {
            # Get role template
            $role = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoleTemplates/$RoleId"
        }
        else {
            # Get directory role
            $role = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleId"
        }
        
        # Return simplified role details
        return @{
            id = $role.id
            displayName = $role.displayName
        }
    }
    catch {
        # If checking directoryRoles fails and we weren't already checking a template, try getting it from role templates
        if (-not $IsRoleTemplate) {
            try {
                $roleTemplate = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoleTemplates/$RoleId"
                return @{
                    id = $roleTemplate.id
                    displayName = $roleTemplate.displayName
                }
            }
            catch {
                Write-Warning "Failed to get details for role template $RoleId : $_"
                return $null
            }
        }
        
        Write-Warning "Failed to get details for role $RoleId : $_"
        return $null
    }
} 