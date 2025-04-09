function Get-CAPolicy {
    <#
    .SYNOPSIS
        Retrieves Conditional Access policies from the Microsoft Graph API.
    
    .DESCRIPTION
        Fetches Conditional Access policies from the Microsoft Graph API and optionally
        enhances them with additional metadata about users, groups, applications, and roles.
        This command supports both development (expanded) and production (streamlined) modes.
    
    .PARAMETER Id
        The ID of a specific policy to retrieve. If not specified, all policies are retrieved.
    
    .PARAMETER IncludeMetadata
        Whether to include additional metadata for users, groups, applications, and roles.
    
    .PARAMETER OutputPath
        The directory where policy files will be saved. If not specified, uses the configured paths.
    
    .PARAMETER Enhanced
        Whether to use enhanced mode, which includes full group membership details (Dev environment).
        This parameter is slower but provides more comprehensive information.
    
    .PARAMETER SaveOriginal
        Whether to save the original (unmodified) policies as JSON files.
    
    .PARAMETER SaveEnhanced
        Whether to save the enhanced policies (with additional metadata) as JSON files.
    
    .EXAMPLE
        Get-CAPolicy
        
        Retrieves all Conditional Access policies without additional metadata.
    
    .EXAMPLE
        Get-CAPolicy -Id "00000000-0000-0000-0000-000000000000"
        
        Retrieves a specific Conditional Access policy by its ID.
    
    .EXAMPLE
        Get-CAPolicy -IncludeMetadata -OutputPath "C:\Policies" -SaveOriginal -SaveEnhanced
        
        Retrieves all Conditional Access policies with additional metadata,
        and saves both original and enhanced versions to the specified directory.
    
    .EXAMPLE
        Get-CAPolicy -IncludeMetadata -Enhanced
        
        Retrieves all Conditional Access policies with full metadata including group memberships.
    
    .NOTES
        This function requires a connection to Microsoft Graph established through Connect-CAGraph.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Id,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeMetadata,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Enhanced,
        
        [Parameter(Mandatory = $false)]
        [switch]$SaveOriginal,
        
        [Parameter(Mandatory = $false)]
        [switch]$SaveEnhanced
    )
    
    begin {
        # Check if we're connected to Microsoft Graph
        if (-not $script:CAConfig.ConnectionStatus) {
            throw "Not connected to Microsoft Graph. Run Connect-CAGraph first."
        }
        
        # Set up output paths
        if ($SaveOriginal -or $SaveEnhanced) {
            # Get configuration to determine proper paths
            $config = Get-CAConfig
            
            if ([string]::IsNullOrEmpty($OutputPath)) {
                # Use the base path from config + policies subdir
                $basePath = $config.OutputPaths.Base
                $policiesPath = Join-Path -Path $basePath -ChildPath $config.OutputPaths.Policies
            } else {
                $policiesPath = $OutputPath
            }
            
            # Get paths for original and enhanced policies
            $originalPath = Join-Path -Path $policiesPath -ChildPath "original"
            $enhancedPath = Join-Path -Path $policiesPath -ChildPath "data"
            
            # Create directories if they don't exist
            New-Item -ItemType Directory -Force -Path $originalPath | Out-Null
            New-Item -ItemType Directory -Force -Path $enhancedPath | Out-Null
            
            Write-Verbose "Policy output paths: Original=$originalPath, Enhanced=$enhancedPath"
        }
    }
    
    process {
        try {
            # Construct the Graph API query
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            if (-not [string]::IsNullOrEmpty($Id)) {
                $uri = "$uri/$Id"
            }
            
            # Get the policies
            Write-Verbose "Fetching policies from $uri"
            $policies = Invoke-MgGraphRequest -Method GET -Uri $uri
            
            # Extract the value if we get a collection
            if ($policies.value) {
                $policies = $policies.value
            } else {
                # If we got a single policy, wrap it in an array for consistent processing
                $policies = @($policies)
            }
            
            Write-Verbose "Retrieved $($policies.Count) policies"
            
            # Save original policies if requested
            if ($SaveOriginal) {
                foreach ($policy in $policies) {
                    $fileName = Get-SafeFilename -DisplayName $policy.displayName -DefaultName $policy.id
                    $filePath = Join-Path -Path $originalPath -ChildPath "$fileName.json"
                    $policy | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8
                    Write-Verbose "Saved original policy to: $filePath"
                }
                Write-Verbose "Original policies saved to $originalPath"
            }
            
            # Process and enhance policies if needed
            if ($IncludeMetadata) {
                $enhancedPolicies = @()
                
                foreach ($policy in $policies) {
                    Write-Verbose "Enhancing policy: $($policy.displayName)"
                    $enhancedPolicy = $policy | ConvertTo-Json -Depth 100 | ConvertFrom-Json
                    
                    # Process applications section
                    if ($policy.conditions.applications) {
                        if ($policy.conditions.applications.includeApplications) {
                            $enhancedApps = @{}
                            foreach ($appId in $policy.conditions.applications.includeApplications) {
                                if ($appId -ne "All") {
                                    $appDetails = Get-ApplicationDetails -AppId $appId
                                    if ($appDetails) {
                                        $enhancedApps[$appId] = $appDetails
                                    }
                                } else {
                                    $enhancedApps = @("All")
                                    break
                                }
                            }
                            $enhancedPolicy.conditions.applications.includeApplications = $enhancedApps
                        }
                        
                        # Process excluded applications
                        if ($policy.conditions.applications.excludeApplications) {
                            $enhancedApps = @{}
                            foreach ($appId in $policy.conditions.applications.excludeApplications) {
                                $appDetails = Get-ApplicationDetails -AppId $appId
                                if ($appDetails) {
                                    $enhancedApps[$appId] = $appDetails
                                }
                            }
                            $enhancedPolicy.conditions.applications.excludeApplications = $enhancedApps
                        }
                    }
                    
                    # Process users section
                    if ($policy.conditions.users) {
                        $userLists = @(
                            @{ Path = 'includeUsers'; List = $policy.conditions.users.includeUsers },
                            @{ Path = 'excludeUsers'; List = $policy.conditions.users.excludeUsers }
                        )
                        
                        foreach ($userList in $userLists) {
                            if ($userList.List) {
                                $enhancedUsers = @{}
                                foreach ($userId in $userList.List) {
                                    if ($userId -ne "All") {
                                        $userDetails = Get-UserDetails -UserId $userId
                                        if ($userDetails) {
                                            $enhancedUsers[$userId] = $userDetails
                                        }
                                    } else {
                                        $enhancedUsers = @("All")
                                        break
                                    }
                                }
                                $enhancedPolicy.conditions.users."$($userList.Path)" = $enhancedUsers
                            }
                        }
                        
                        # Process groups - use different approach based on Enhanced mode
                        $groupLists = @(
                            @{ Path = 'includeGroups'; List = $policy.conditions.users.includeGroups },
                            @{ Path = 'excludeGroups'; List = $policy.conditions.users.excludeGroups }
                        )
                        
                        foreach ($groupList in $groupLists) {
                            if ($groupList.List) {
                                $enhancedGroups = @{}
                                foreach ($groupId in $groupList.List) {
                                    if ($Enhanced) {
                                        # Development mode - get full group details with members
                                        $groupDetails = Get-GroupDetails -GroupId $groupId -IncludeMembers
                                    } else {
                                        # Production mode - just get basic group details with member count
                                        $groupDetails = Get-GroupDetails -GroupId $groupId
                                    }
                                    
                                    if ($groupDetails) {
                                        $enhancedGroups[$groupId] = $groupDetails
                                    }
                                }
                                $enhancedPolicy.conditions.users."$($groupList.Path)" = $enhancedGroups
                            }
                        }
                        
                        # Process roles
                        $roleLists = @(
                            @{ Path = 'includeRoles'; List = $policy.conditions.users.includeRoles },
                            @{ Path = 'excludeRoles'; List = $policy.conditions.users.excludeRoles }
                        )
                        
                        foreach ($roleList in $roleLists) {
                            if ($roleList.List) {
                                $enhancedRoles = @{}
                                foreach ($roleId in $roleList.List) {
                                    $roleDetails = Get-RoleDetails -RoleId $roleId
                                    if ($roleDetails) {
                                        $enhancedRoles[$roleId] = $roleDetails
                                    }
                                }
                                $enhancedPolicy.conditions.users."$($roleList.Path)" = $enhancedRoles
                            }
                        }
                    }
                    
                    # Reorder properties for consistency
                    $enhancedPolicy = Get-ReorderedPolicy -Policy $enhancedPolicy
                    
                    # Add to the collection
                    $enhancedPolicies += $enhancedPolicy
                    
                    # Save enhanced policy if requested
                    if ($SaveEnhanced) {
                        $fileName = Get-SafeFilename -DisplayName $policy.displayName -DefaultName $policy.id
                        $filePath = Join-Path -Path $enhancedPath -ChildPath "$fileName.json"
                        $enhancedPolicy | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8
                        Write-Verbose "Saved enhanced policy to: $filePath"
                    }
                }
                
                Write-Verbose "Enhanced $($enhancedPolicies.Count) policies"
                if ($SaveEnhanced) {
                    Write-Verbose "Enhanced policies saved to $enhancedPath"
                }
                
                # Return enhanced policies
                return $enhancedPolicies
            } else {
                # Return original policies
                return $policies
            }
        }
        catch {
            Write-Error "Error retrieving Conditional Access policies: $_"
            throw $_
        }
    }
    
    end {
        Write-Verbose "Policy retrieval completed"
    }
} 