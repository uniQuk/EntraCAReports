@{
    # Default output paths
    OutputPaths = @{
        Base = "CAReports_Output"  # Relative path to current directory
        Policies = "policies"
        Original = "policies/original"
        Data = "policies/data"
        Analysis = "analysis"
        Diagrams = "diagrams"
        Excel = "analysis/excel"
        Markdown = "analysis/markdown"
        Yaml = "policies/yaml"
        Clean = "policies/yaml/clean"
    }
    
    # Graph API parameters
    Graph = @{
        ApiVersion = "v1.0"
        DefaultScopes = @(
            "Policy.Read.All"
            "Directory.Read.All"
            "Application.Read.All"
        )
    }
    
    # Application settings
    Application = @{
        DefaultRunMode = "Interactive"  # Interactive, Silent, Verbose
        DefaultEnvironment = "Production"  # Production, Development
        MaxThreads = 4  # For parallel processing
        MaxRetries = 3  # For API calls
        RetryDelaySeconds = 2  # Delay between retries
        MaxCacheItems = 1000  # Cache size for API responses
    }
    
    # Report settings
    Reports = @{
        IncludeInactivePolicies = $true
        ExcelConditionalFormatting = $true
        DiagramsFormat = "Mermaid"
        DefaultSort = "displayName"
        NamespacePrefix = "CA"  # Used in naming conventions
    }
    
    # Feature flags
    Features = @{
        UseEnhancedMetadata = $true
        CacheApiResponses = $true
        ShowProgress = $true
        AutoSaveResults = $false
        VerifyConnectivity = $true
    }
} 