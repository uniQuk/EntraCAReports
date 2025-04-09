function Format-CAOutput {
    <#
    .SYNOPSIS
        Formats output data into different formats for consistency across the module.
    
    .DESCRIPTION
        The Format-CAOutput function converts input data to various output formats
        with consistent styling and structure. This centralizes formatting logic
        for all module functions that produce output.
    
    .PARAMETER InputObject
        The object to format.
    
    .PARAMETER OutputFormat
        The desired output format. Valid values are: 
        - Markdown (default)
        - JSON
        - YAML
        - Text
        - HTML
    
    .PARAMETER Title
        Optional title to include in the formatted output.
    
    .PARAMETER Description
        Optional description to include in the formatted output.
    
    .PARAMETER NoEnumerate
        If specified, prevents array enumeration in the output.
    
    .EXAMPLE
        Format-CAOutput -InputObject $policyData -OutputFormat "Markdown" -Title "Policy Analysis"
        
        Formats the policy data as Markdown with a title.
    
    .EXAMPLE
        Format-CAOutput -InputObject $policyData -OutputFormat "JSON"
        
        Returns the policy data as formatted JSON.
    
    .NOTES
        This function is used internally by various module commands to provide
        consistent output formatting across different output types.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$InputObject,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Markdown", "JSON", "YAML", "Text", "HTML")]
        [string]$OutputFormat = "Markdown",
        
        [Parameter(Mandatory = $false)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoEnumerate
    )
    
    begin {
        # Initialize collections if processing pipeline input
        $pipelineItems = @()
        
        # Define newline for consistent usage
        $nl = [Environment]::NewLine
        
        # Setup HTML header if needed
        $htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #0078d4; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #f0f0f0; text-align: left; }
        th, td { padding: 8px; border: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        code { font-family: Consolas, Monaco, 'Courier New', monospace; background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .description { color: #666; margin-bottom: 20px; }
    </style>
</head>
<body>
"@
    }
    
    process {
        # Add the current item to our collection if processing a pipeline
        if ($_ -ne $null -and $_ -ne $InputObject) {
            $pipelineItems += $_
        }
    }
    
    end {
        # If we have pipeline items, use those instead of InputObject
        if ($pipelineItems.Count -gt 0) {
            $InputObject = $pipelineItems
        }
        
        # Return early if input is null
        if ($null -eq $InputObject) {
            return $null
        }
        
        # Format the output based on the specified format
        switch ($OutputFormat) {
            "Markdown" {
                $result = ""
                
                # Add title if provided
                if ($Title) {
                    $result += "# $Title$nl$nl"
                }
                
                # Add description if provided
                if ($Description) {
                    $result += "$Description$nl$nl"
                }
                
                # Format the input object as markdown
                if ($InputObject -is [System.Collections.IDictionary]) {
                    # For hashtables/dictionaries, format as a list
                    foreach ($key in $InputObject.Keys) {
                        $value = $InputObject[$key]
                        # Format arrays as bullet lists
                        if ($value -is [array] -and -not $NoEnumerate) {
                            $result += "## $key$nl$nl"
                            foreach ($item in $value) {
                                $result += "* $item$nl"
                            }
                            $result += "$nl"
                        } else {
                            $result += "## $key$nl$nl$value$nl$nl"
                        }
                    }
                } elseif ($InputObject -is [array] -and -not $NoEnumerate) {
                    # For arrays, format as a bullet list
                    foreach ($item in $InputObject) {
                        if ($item -is [System.Collections.IDictionary]) {
                            # For array of hashtables, try to extract a name/title property
                            $itemName = if ($item.ContainsKey("displayName")) { 
                                $item["displayName"] 
                            } elseif ($item.ContainsKey("name")) { 
                                $item["name"] 
                            } elseif ($item.ContainsKey("title")) { 
                                $item["title"] 
                            } else { 
                                "Item" 
                            }
                            
                            $result += "## $itemName$nl$nl"
                            foreach ($key in $item.Keys) {
                                if ($key -ne "displayName" -and $key -ne "name" -and $key -ne "title") {
                                    $value = $item[$key]
                                    $result += "* **$key**: $value$nl"
                                }
                            }
                            $result += "$nl"
                        } else {
                            $result += "* $item$nl"
                        }
                    }
                } else {
                    # For simple objects or when NoEnumerate is specified
                    $result += "$InputObject$nl"
                }
                
                return $result
            }
            
            "JSON" {
                # Convert to JSON with formatting
                $jsonResult = $InputObject | ConvertTo-Json -Depth 10 -Compress:$false
                return $jsonResult
            }
            
            "YAML" {
                # Ensure the powershell-yaml module is available
                if (-not (Get-Module -Name powershell-yaml -ListAvailable)) {
                    Write-Warning "The 'powershell-yaml' module is required for YAML output. Please install it with 'Install-Module powershell-yaml'."
                    return $null
                }
                
                # Import the module and convert to YAML
                Import-Module powershell-yaml
                $yamlResult = $InputObject | ConvertTo-Yaml
                return $yamlResult
            }
            
            "Text" {
                # Simple text output
                $textResult = ""
                
                if ($Title) {
                    $textResult += "$Title$nl"
                    $textResult += "=" * $Title.Length + "$nl$nl"
                }
                
                if ($Description) {
                    $textResult += "$Description$nl$nl"
                }
                
                # Convert objects to text representation
                if ($InputObject -is [System.Collections.IDictionary]) {
                    foreach ($key in $InputObject.Keys) {
                        $value = $InputObject[$key]
                        $textResult += "${key}: "
                        
                        if ($value -is [array] -and -not $NoEnumerate) {
                            $textResult += "$nl"
                            foreach ($item in $value) {
                                $textResult += "  - $item$nl"
                            }
                        } else {
                            $textResult += "$value$nl"
                        }
                    }
                } elseif ($InputObject -is [array] -and -not $NoEnumerate) {
                    foreach ($item in $InputObject) {
                        if ($item -is [System.Collections.IDictionary]) {
                            foreach ($key in $item.Keys) {
                                $textResult += "${key}: $($item[$key])$nl"
                            }
                            $textResult += "$nl"
                        } else {
                            $textResult += "- $item$nl"
                        }
                    }
                } else {
                    $textResult += "$InputObject$nl"
                }
                
                return $textResult
            }
            
            "HTML" {
                $nl = [Environment]::NewLine
                $sb = [System.Text.StringBuilder]::new()
                
                # Add title if provided
                if ($Title) {
                    [void]$sb.Append("<h1>")
                    [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($Title))
                    [void]$sb.Append("</h1>")
                    [void]$sb.Append($nl)
                }
                
                # Add description if provided
                if ($Description) {
                    [void]$sb.Append("<div class='description'>")
                    [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($Description))
                    [void]$sb.Append("</div>")
                    [void]$sb.Append($nl)
                }
                
                # Format the input object as HTML
                if ($InputObject -is [System.Collections.IDictionary]) {
                    # For hashtables/dictionaries, format as sections
                    foreach ($key in $InputObject.Keys) {
                        $value = $InputObject[$key]
                        [void]$sb.Append("<h2>")
                        [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($key))
                        [void]$sb.Append("</h2>")
                        [void]$sb.Append($nl)
                        
                        # Format arrays as bullet lists
                        if ($value -is [array] -and -not $NoEnumerate) {
                            [void]$sb.Append("<ul>")
                            [void]$sb.Append($nl)
                            foreach ($item in $value) {
                                [void]$sb.Append("  <li>")
                                [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($item))
                                [void]$sb.Append("</li>")
                                [void]$sb.Append($nl)
                            }
                            [void]$sb.Append("</ul>")
                            [void]$sb.Append($nl)
                        } else {
                            [void]$sb.Append("<p>")
                            [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($value))
                            [void]$sb.Append("</p>")
                            [void]$sb.Append($nl)
                        }
                    }
                } elseif ($InputObject -is [array] -and -not $NoEnumerate) {
                    # For arrays, check if they might be table data
                    if ($InputObject.Count -gt 0 -and $InputObject[0] -is [System.Collections.IDictionary]) {
                        # Get all possible property names
                        $allProperties = @()
                        foreach ($item in $InputObject) {
                            $allProperties += $item.Keys
                        }
                        $uniqueProperties = $allProperties | Select-Object -Unique
                        
                        # Create an HTML table
                        [void]$sb.Append("<table>")
                        [void]$sb.Append($nl)
                        [void]$sb.Append("<tr>")
                        [void]$sb.Append($nl)
                        foreach ($prop in $uniqueProperties) {
                            [void]$sb.Append("  <th>")
                            [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($prop))
                            [void]$sb.Append("</th>")
                            [void]$sb.Append($nl)
                        }
                        [void]$sb.Append("</tr>")
                        [void]$sb.Append($nl)
                        
                        foreach ($item in $InputObject) {
                            [void]$sb.Append("<tr>")
                            [void]$sb.Append($nl)
                            foreach ($prop in $uniqueProperties) {
                                $value = if ($item.ContainsKey($prop)) { $item[$prop] } else { "" }
                                [void]$sb.Append("  <td>")
                                [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($value))
                                [void]$sb.Append("</td>")
                                [void]$sb.Append($nl)
                            }
                            [void]$sb.Append("</tr>")
                            [void]$sb.Append($nl)
                        }
                        
                        [void]$sb.Append("</table>")
                        [void]$sb.Append($nl)
                    } else {
                        # Simple list
                        [void]$sb.Append("<ul>")
                        [void]$sb.Append($nl)
                        foreach ($item in $InputObject) {
                            [void]$sb.Append("  <li>")
                            [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($item))
                            [void]$sb.Append("</li>")
                            [void]$sb.Append($nl)
                        }
                        [void]$sb.Append("</ul>")
                        [void]$sb.Append($nl)
                    }
                } else {
                    # For simple objects or when NoEnumerate is specified
                    [void]$sb.Append("<pre>")
                    [void]$sb.Append([System.Web.HttpUtility]::HtmlEncode($InputObject))
                    [void]$sb.Append("</pre>")
                    [void]$sb.Append($nl)
                }
                
                # Complete HTML document
                $htmlResult = $htmlHeader + $sb.ToString() + "</body></html>"
                return $htmlResult
            }
        }
    }
} 