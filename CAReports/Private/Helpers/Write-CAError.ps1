function Write-CAError {
    <#
    .SYNOPSIS
        Standardized error handling for the CAReports module.
    
    .DESCRIPTION
        This function provides a consistent way to handle and report errors across
        the CAReports module. It supports different error levels, custom messages,
        and can conditionally terminate execution.
    
    .PARAMETER ErrorRecord
        The error record to process, typically $_ from a catch block.
    
    .PARAMETER Message
        A custom message to prepend to the error details.
    
    .PARAMETER Category
        The error category to use. Defaults to 'OperationStopped'.
    
    .PARAMETER ErrorLevel
        The severity level of the error:
        - Warning: logs a warning but doesn't terminate execution
        - Error: logs an error but doesn't terminate execution
        - Terminal: logs an error and terminates execution with throw
    
    .PARAMETER LogToFile
        Whether to log the error to a file in addition to the console.
    
    .EXAMPLE
        try {
            # Some operation that might fail
        }
        catch {
            Write-CAError -ErrorRecord $_ -Message "Failed to process policy"
        }
    
    .NOTES
        This is an internal helper function used by the CAReports module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        
        [Parameter(Mandatory = $false)]
        [string]$Message = "An error occurred",
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.ErrorCategory]$Category = [System.Management.Automation.ErrorCategory]::OperationStopped,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Warning', 'Error', 'Terminal')]
        [string]$ErrorLevel = 'Error',
        
        [Parameter(Mandatory = $false)]
        [switch]$LogToFile
    )
    
    # Build a detailed error message
    $errorMessage = "$Message. $($ErrorRecord.Exception.Message)"
    $errorDetails = @{
        Message = $errorMessage
        Category = $Category
        ErrorId = $ErrorRecord.FullyQualifiedErrorId
        TargetObject = $ErrorRecord.TargetObject
        InnerException = $ErrorRecord.Exception.InnerException
        ScriptStackTrace = $ErrorRecord.ScriptStackTrace
        PositionMessage = $ErrorRecord.InvocationInfo.PositionMessage
    }
    
    # Add function and line info if available
    if ($ErrorRecord.InvocationInfo) {
        $errorDetails.Function = $ErrorRecord.InvocationInfo.MyCommand.Name
        $errorDetails.Line = $ErrorRecord.InvocationInfo.ScriptLineNumber
    }
    
    # Create a structured error record for easy parsing
    $structuredError = [PSCustomObject]$errorDetails
    
    # Handle error based on error level
    switch ($ErrorLevel) {
        'Warning' {
            Write-Warning $errorMessage
        }
        'Error' {
            Write-Error $errorMessage -ErrorId $ErrorRecord.FullyQualifiedErrorId -Category $Category
        }
        'Terminal' {
            Write-Error $errorMessage -ErrorId $ErrorRecord.FullyQualifiedErrorId -Category $Category
            throw $ErrorRecord
        }
    }
    
    # Log to file if requested
    if ($LogToFile) {
        $logPath = Join-Path -Path $script:CAConfig.BaseOutputPath -ChildPath "Logs"
        if (!(Test-Path -Path $logPath)) {
            New-Item -ItemType Directory -Path $logPath -Force | Out-Null
        }
        
        $logFile = Join-Path -Path $logPath -ChildPath "CAReports_Errors_$(Get-Date -Format 'yyyyMMdd').log"
        $logEntry = @{
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Level = $ErrorLevel
            Message = $errorMessage
            Function = $errorDetails.Function
            ScriptLine = $errorDetails.Line
            ErrorId = $errorDetails.ErrorId
        }
        
        # Convert to JSON for structured logging
        $logEntryJson = $logEntry | ConvertTo-Json -Compress
        Add-Content -Path $logFile -Value $logEntryJson
    }
    
    # Return the structured error for potential further processing
    return $structuredError
} 