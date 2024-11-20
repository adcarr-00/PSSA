# VulnerablePortsRule.psm1

# Define the custom PSScriptAnalyzer rule
function Test-VulnerablePorts {
    param(
        [string]$scriptText
    )
    
    # List of known vulnerable ports
    $vulnerablePorts = @(23, 139, 445, 3389)
    
    # Define regex patterns for commands related to opening ports
    $patterns = @(
        'New-NetFirewallRule', 
        'Set-NetFirewallRule'
    )
    
    # Match script text with cmdlets opening specific vulnerable ports
    foreach ($pattern in $patterns) {
        if ($scriptText -match $pattern) {
            # Look for cmdlets that specify vulnerable ports
            foreach ($port in $vulnerablePorts) {
                if ($scriptText -match "\b$port\b") {
                    return @(
                        @{
                            RuleName    = 'Vulnerable Port Detection'
                            Severity    = 'Warning'
                            Message     = "Vulnerable port $port is being opened or configured."
                            ScriptBlock = $scriptText
                        }
                    )
                }
            }
        }
    }
    return $null
}

# Register the custom rule in PSScriptAnalyzer
function Invoke-VulnerablePortsRule {
    $ruleName = 'VulnerablePortsRule'
    
    # Load the script content to analyze
    $scriptContent = Get-Content -Path $PSCommandPath -Raw

    $violations = Test-VulnerablePorts -scriptText $scriptContent

    # Report violations (if any)
    if ($violations) {
        foreach ($violation in $violations) {
            Write-Host "$($violation.RuleName) - $($violation.Severity): $($violation.Message)"
        }
    }
    else {
        Write-Host "No violations detected."
    }
}
