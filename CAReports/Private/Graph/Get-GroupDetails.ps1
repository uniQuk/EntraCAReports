function Get-GroupDetails {
    <#
    .SYNOPSIS
        Retrieves detailed information about a Microsoft Entra ID group.
    
    .DESCRIPTION
        Gets detailed information about a Microsoft Entra ID group, including
        display name, description, and optionally the group members.
    
    .PARAMETER GroupId
        The ID of the group to retrieve.
    
    .PARAMETER IncludeMembers
        Switch parameter to indicate whether to include group members in the result.
    
    .PARAMETER Properties
        Optional list of additional properties to retrieve. Default properties always include id, displayName, and description.
    
    .EXAMPLE
        Get-GroupDetails -GroupId "00000000-0000-0000-0000-000000000000"
        
        Retrieves basic information about the specified group.
    
    .EXAMPLE
        Get-GroupDetails -GroupId "00000000-0000-0000-0000-000000000000" -IncludeMembers
        
        Retrieves information about the specified group, including its members.
    
    .EXAMPLE
        Get-GroupDetails -GroupId "00000000-0000-0000-0000-000000000000" -Properties @("mail", "mailEnabled")
        
        Retrieves information about the specified group, including the mail and mailEnabled properties.
    
    .NOTES
        This function requires a connection to Microsoft Graph established through Connect-CAGraph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$GroupId,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeMembers,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties
    )
    
    # Check for special group types
    if ($GroupId -eq "All" -or $GroupId -eq "None") {
        # Return a custom object for special group types
        return @{
            id = $GroupId
            displayName = $GroupId
            description = "Special group type: $GroupId"
            isSpecialGroupType = $true
        }
    }
    
    try {
        # Define default properties
        $defaultProperties = @("id", "displayName", "description")
        
        # Combine default and additional properties if specified
        $selectProperties = $defaultProperties
        if ($Properties) {
            $selectProperties = $defaultProperties + ($Properties | Where-Object { $_ -notin $defaultProperties })
        }
        
        # Build the select query parameter
        $select = '$select=' + ($selectProperties -join ',')
        
        # Get group information
        $group = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId`?$select"
        
        # Create result hashtable with requested properties
        $result = @{}
        foreach ($prop in $group.PSObject.Properties) {
            if ($prop.Name -in $selectProperties) {
                $result[$prop.Name] = $prop.Value
            }
        }
        
        # If members are requested, get them
        if ($IncludeMembers) {
            try {
                $members = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,displayName,userPrincipalName"
                $result.members = $members.value
            }
            catch {
                Write-CAError -ErrorRecord $_ -Message "Failed to get members for group $GroupId" -ErrorLevel 'Warning' -LogToFile
                $result.members = @()
            }
        }
        
        return $result
    }
    catch {
        Write-CAError -ErrorRecord $_ -Message "Failed to get details for group $GroupId" -ErrorLevel 'Warning' -LogToFile
        # Return a minimal object to prevent null reference exceptions
        return @{
            id = $GroupId
            displayName = "Unknown Group ($GroupId)"
            description = "Error retrieving group details"
            error = $_.Exception.Message
        }
    }
} 