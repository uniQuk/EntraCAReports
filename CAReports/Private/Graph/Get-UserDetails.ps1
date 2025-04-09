function Get-UserDetails {
    <#
    .SYNOPSIS
        Retrieves detailed information about a Microsoft Entra ID user.
    
    .DESCRIPTION
        Gets detailed information about a Microsoft Entra ID user, including
        user principal name and display name.
    
    .PARAMETER UserId
        The ID of the user to retrieve.
    
    .PARAMETER Properties
        Optional list of additional properties to retrieve. Default properties always include id, displayName, and userPrincipalName.
    
    .EXAMPLE
        Get-UserDetails -UserId "72f988bf-86f1-41af-91ab-2d7cd011db47"
        
        Retrieves basic information about the specified user.
    
    .EXAMPLE
        Get-UserDetails -UserId "72f988bf-86f1-41af-91ab-2d7cd011db47" -Properties @("mail", "department")
        
        Retrieves information about the specified user, including the mail and department properties.
    
    .NOTES
        This function requires a connection to Microsoft Graph established through Connect-CAGraph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$UserId,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties
    )
    
    # Check for special user types that don't require Graph API calls
    if ($UserId -eq "GuestsOrExternalUsers" -or $UserId -eq "None" -or $UserId -eq "All") {
        # Return a custom object for special user types
        return @{
            id = $UserId
            displayName = $UserId
            userPrincipalName = $UserId
            isSpecialUserType = $true
        }
    }
    
    try {
        # Define default properties
        $defaultProperties = @("id", "userPrincipalName", "displayName")
        
        # Combine default and additional properties if specified
        $selectProperties = $defaultProperties
        if ($Properties) {
            $selectProperties = $defaultProperties + ($Properties | Where-Object { $_ -notin $defaultProperties })
        }
        
        # Build the select query parameter
        $select = '$select=' + ($selectProperties -join ',')
        
        # Get user information
        $user = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId`?$select"
        
        # Create result hashtable with requested properties
        $result = @{}
        foreach ($prop in $user.PSObject.Properties) {
            if ($prop.Name -in $selectProperties) {
                $result[$prop.Name] = $prop.Value
            }
        }
        
        return $result
    }
    catch {
        Write-CAError -ErrorRecord $_ -Message "Failed to get details for user $UserId" -ErrorLevel 'Warning' -LogToFile
        # Return a minimal object with just the ID to prevent null reference exceptions
        return @{
            id = $UserId
            displayName = "Unknown User ($UserId)"
            userPrincipalName = "unknown@example.com"
            error = $_.Exception.Message
        }
    }
} 