function Get-ReorderedPolicy {
    <#
    .SYNOPSIS
        Reorders Conditional Access policy properties for consistent output.
    
    .DESCRIPTION
        This function takes a Conditional Access policy object and reorders its properties
        to ensure consistent output format. This is useful for comparing policies and
        generating standardized reports.
    
    .PARAMETER Policy
        The Conditional Access policy object to reorder.
    
    .EXAMPLE
        $reorderedPolicy = Get-ReorderedPolicy -Policy $policy
    
    .NOTES
        This is an internal helper function used by the CAReports module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSCustomObject]$Policy
    )
    
    process {
        # Create ordered hashtable for consistent property ordering
        $reordered = [ordered]@{
            id = $Policy.id
            displayName = $Policy.displayName
            state = $Policy.state
            createdDateTime = $Policy.createdDateTime
            modifiedDateTime = $Policy.modifiedDateTime
            conditions = [ordered]@{
                users = [ordered]@{}
                applications = [ordered]@{}
                clientAppTypes = @()
                locations = [ordered]@{}
                platforms = [ordered]@{}
            }
            grantControls = [ordered]@{}
            sessionControls = [ordered]@{}
        }
        
        # Copy user conditions
        if ($Policy.conditions.users) {
            $userConditions = $Policy.conditions.users
            $userProps = [ordered]@{}
            
            if ($null -ne $userConditions.includeUsers) { 
                $userProps.includeUsers = $userConditions.includeUsers 
            }
            if ($null -ne $userConditions.excludeUsers) { 
                $userProps.excludeUsers = $userConditions.excludeUsers 
            }
            if ($null -ne $userConditions.includeGroups) { 
                $userProps.includeGroups = $userConditions.includeGroups 
            }
            if ($null -ne $userConditions.excludeGroups) { 
                $userProps.excludeGroups = $userConditions.excludeGroups 
            }
            if ($null -ne $userConditions.includeRoles) { 
                $userProps.includeRoles = $userConditions.includeRoles 
            }
            if ($null -ne $userConditions.excludeRoles) { 
                $userProps.excludeRoles = $userConditions.excludeRoles 
            }
            if ($null -ne $userConditions.includeGuestsOrExternalUsers) { 
                $userProps.includeGuestsOrExternalUsers = $userConditions.includeGuestsOrExternalUsers 
            }
            
            $reordered.conditions.users = $userProps
        }
        
        # Copy application conditions
        if ($Policy.conditions.applications) {
            $appConditions = $Policy.conditions.applications
            $appProps = [ordered]@{}
            
            if ($null -ne $appConditions.includeApplications) { 
                $appProps.includeApplications = $appConditions.includeApplications 
            }
            if ($null -ne $appConditions.excludeApplications) { 
                $appProps.excludeApplications = $appConditions.excludeApplications 
            }
            if ($null -ne $appConditions.includeUserActions) { 
                $appProps.includeUserActions = $appConditions.includeUserActions 
            }
            
            $reordered.conditions.applications = $appProps
        }
        
        # Copy client app types
        if ($Policy.conditions.clientAppTypes) {
            $reordered.conditions.clientAppTypes = $Policy.conditions.clientAppTypes
        }
        
        # Copy platform conditions
        if ($Policy.conditions.platforms) {
            $platformConditions = $Policy.conditions.platforms
            $platformProps = [ordered]@{}
            
            if ($null -ne $platformConditions.includePlatforms) { 
                $platformProps.includePlatforms = $platformConditions.includePlatforms 
            }
            if ($null -ne $platformConditions.excludePlatforms) { 
                $platformProps.excludePlatforms = $platformConditions.excludePlatforms 
            }
            
            $reordered.conditions.platforms = $platformProps
        }
        
        # Copy location conditions
        if ($Policy.conditions.locations) {
            $locationConditions = $Policy.conditions.locations
            $locationProps = [ordered]@{}
            
            if ($null -ne $locationConditions.includeLocations) { 
                $locationProps.includeLocations = $locationConditions.includeLocations 
            }
            if ($null -ne $locationConditions.excludeLocations) { 
                $locationProps.excludeLocations = $locationConditions.excludeLocations 
            }
            
            $reordered.conditions.locations = $locationProps
        }
        
        # Copy grant controls
        if ($Policy.grantControls) {
            $grantProps = [ordered]@{}
            
            if ($null -ne $Policy.grantControls.operator) { 
                $grantProps.operator = $Policy.grantControls.operator 
            }
            if ($null -ne $Policy.grantControls.builtInControls) { 
                $grantProps.builtInControls = $Policy.grantControls.builtInControls 
            }
            if ($null -ne $Policy.grantControls.customAuthenticationFactors) { 
                $grantProps.customAuthenticationFactors = $Policy.grantControls.customAuthenticationFactors 
            }
            if ($null -ne $Policy.grantControls.termsOfUse) { 
                $grantProps.termsOfUse = $Policy.grantControls.termsOfUse 
            }
            
            $reordered.grantControls = $grantProps
        }
        
        # Copy session controls
        if ($Policy.sessionControls) {
            $sessionProps = [ordered]@{}
            
            if ($null -ne $Policy.sessionControls.applicationEnforcedRestrictions) { 
                $sessionProps.applicationEnforcedRestrictions = $Policy.sessionControls.applicationEnforcedRestrictions 
            }
            if ($null -ne $Policy.sessionControls.cloudAppSecurity) { 
                $sessionProps.cloudAppSecurity = $Policy.sessionControls.cloudAppSecurity 
            }
            if ($null -ne $Policy.sessionControls.signInFrequency) { 
                $sessionProps.signInFrequency = $Policy.sessionControls.signInFrequency 
            }
            if ($null -ne $Policy.sessionControls.persistentBrowser) { 
                $sessionProps.persistentBrowser = $Policy.sessionControls.persistentBrowser 
            }
            
            $reordered.sessionControls = $sessionProps
        }
        
        # Return reordered policy
        return [PSCustomObject]$reordered
    }
} 