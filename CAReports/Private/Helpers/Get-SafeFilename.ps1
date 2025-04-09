function Get-SafeFilename {
    <#
    .SYNOPSIS
        Creates a safe filename from a string.
    
    .DESCRIPTION
        Sanitizes a string to be used as a filename by removing invalid characters
        and handling other edge cases. This is useful for creating filenames from
        policy names or other user-provided strings.
    
    .PARAMETER DisplayName
        The string to sanitize into a safe filename.
    
    .PARAMETER DefaultName
        The default name to use if the input is null, empty, or consists entirely of invalid characters.
    
    .EXAMPLE
        Get-SafeFilename -DisplayName "My Policy: With Invalid * Characters?"
        
        Returns: "My_Policy_With_Invalid_Characters"
    
    .EXAMPLE
        Get-SafeFilename -DisplayName $null -DefaultName "policy"
        
        Returns: "policy"
    
    .NOTES
        This function handles various edge cases such as long filenames, filenames with
        invalid characters, and null or empty filenames.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [Alias("Name", "Filename", "OriginalName")]
        [string]$DisplayName,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultName = "unnamed_policy"
    )
    
    # Return default name if input is null or empty
    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        return $DefaultName
    }

    # Get invalid characters
    $invalids = [System.IO.Path]::GetInvalidFileNameChars()
    $replacement = '_'
    
    # Replace invalid chars and control chars
    $safeName = [RegEx]::Replace($DisplayName, "[$([RegEx]::Escape(-join $invalids))]", $replacement)
    
    # Replace spaces with underscores
    $safeName = $safeName -replace '\s+', '_'
    
    # Replace multiple consecutive underscores with single underscore
    $safeName = $safeName -replace '_{2,}', '_'
    
    # Trim underscores from start and end
    $safeName = $safeName.Trim('_')
    
    # Return default name if result is empty
    if ([string]::IsNullOrWhiteSpace($safeName)) {
        return $DefaultName
    }
    
    # Truncate if too long (Windows max path is 260, leave room for path and extension)
    $maxLength = 200
    if ($safeName.Length -gt $maxLength) {
        $safeName = $safeName.Substring(0, $maxLength)
        $safeName = $safeName.TrimEnd('_')
    }
    
    # Ensure name doesn't end with a period (can cause issues on Windows)
    $safeName = $safeName -replace '\.$', '_'
    
    return $safeName
} 