function Remove-EmptyValues {
    <#
    .SYNOPSIS
        Removes empty values from an object.
    
    .DESCRIPTION
        This function recursively removes empty values (null, empty arrays, empty hashtables)
        from an object. This is useful for cleaning up policy objects before export to
        make them more readable and compact.
    
    .PARAMETER InputObject
        The object to clean.
    
    .PARAMETER MaxDepth
        The maximum recursion depth to prevent infinite loops. Default is 10.
    
    .PARAMETER CurrentDepth
        For internal use - tracks the current recursion depth.
    
    .EXAMPLE
        $cleanPolicy = Remove-EmptyValues -InputObject $policy
    
    .NOTES
        This is an internal helper function used by the CAReports module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$InputObject,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10,
        
        [Parameter(Mandatory = $false)]
        [int]$CurrentDepth = 0
    )
    
    process {
        # Return null immediately
        if ($null -eq $InputObject) {
            return $null
        }
        
        # Maximum recursion depth check
        if ($CurrentDepth -ge $MaxDepth) {
            Write-Warning "Maximum recursion depth ($MaxDepth) reached."
            return $InputObject
        }
        
        # Handle different object types
        switch ($InputObject.GetType().Name) {
            # Arrays
            { $_ -in 'Object[]', 'ArrayList', 'Collection`1' } {
                # Filter out null or empty arrays
                if ($InputObject.Count -eq 0) {
                    return $null
                }
                
                # Process each item in the array
                $result = @()
                foreach ($item in $InputObject) {
                    $cleanItem = Remove-EmptyValues -InputObject $item -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
                    if ($null -ne $cleanItem) {
                        $result += $cleanItem
                    }
                }
                
                # Return null if all items were removed, otherwise return the cleaned array
                if ($result.Count -eq 0) {
                    return $null
                }
                return $result
            }
            
            # Hashtables and PSCustomObjects
            { $_ -in 'Hashtable', 'OrderedDictionary', 'PSCustomObject' } {
                $result = [ordered]@{}
                
                # Get the properties or keys of the object
                $properties = if ($_ -eq 'PSCustomObject') {
                    $InputObject.PSObject.Properties
                } else {
                    $InputObject.Keys
                }
                
                # Process each property
                foreach ($prop in $properties) {
                    $key = if ($_ -eq 'PSCustomObject') { $prop.Name } else { $prop }
                    $value = if ($_ -eq 'PSCustomObject') { $prop.Value } else { $InputObject[$prop] }
                    
                    # Recursively clean the property value
                    $cleanValue = Remove-EmptyValues -InputObject $value -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
                    
                    # Only add non-null values
                    if ($null -ne $cleanValue) {
                        $result[$key] = $cleanValue
                    }
                }
                
                # Return null if all properties were removed
                if ($result.Count -eq 0) {
                    return $null
                }
                
                # Return the result as the same type as the input
                if ($_ -eq 'PSCustomObject') {
                    return [PSCustomObject]$result
                }
                return $result
            }
            
            # All other types (strings, numbers, etc.)
            default {
                # Return empty strings as null
                if ($InputObject -is [string] -and [string]::IsNullOrWhiteSpace($InputObject)) {
                    return $null
                }
                
                # Return all other values as-is
                return $InputObject
            }
        }
    }
} 