<#
.SYNOPSIS
Detects the use of vulnerable ports (e.g., 23, 139, 445, 3389) in firewall rule configurations using AST.

.DESCRIPTION
This custom rule for PSScriptAnalyzer analyzes PowerShell scripts to detect the use of specific cmdlets 
(`New-NetFirewallRule` or `Set-NetFirewallRule`) that open vulnerable ports, such as Telnet (Port 23), 
NetBIOS (Port 139), SMB (Port 445), and RDP (Port 3389). It flags these occurrences with a warning.

.EXAMPLE
Measure-VulnerablePortsRule -Ast $AstObject

This command analyzes the script's AST and checks if any of the vulnerable ports are being opened via 
firewall rules.

.INPUTS
[System.Management.Automation.Language.ScriptBlockAst]

The function accepts an AST of a script, parsed using PowerShell's Language API.

.OUTPUTS
[Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]]

The function returns an array of DiagnosticRecord objects, which contain details about any violations found 
in the script. Each violation includes a message, severity level, and location in the script.

.NOTES
This rule is intended to help identify potential security risks associated with opening vulnerable ports in 
firewall rules.
#>

function Measure-VulnerablePortsRule {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {
        $results = @()

        # List of vulnerable ports (e.g., Telnet, SMB, RDP)
        $vulnerablePorts = @(23, 139, 445, 3389)

        # Define predicates to find cmdlets (New-NetFirewallRule, Set-NetFirewallRule)
        [ScriptBlock]$predicate1 = {
            param ($Ast)
            return ($Ast -is [System.Management.Automation.Language.InvocationExpressionAst] -and $Ast.Expression.ToString() -match 'New-NetFirewallRule|Set-NetFirewallRule')
        }

        # Finds ASTs that match the predicate
        $cmdletInvocations = $ScriptBlockAst.FindAll($predicate1, $true)

        # Check for vulnerable ports in the cmdlet arguments
        foreach ($invocation in $cmdletInvocations) {
            # Check the arguments for port numbers
            foreach ($port in $vulnerablePorts) {
                if ($invocation.ToString() -match "\b$port\b") {
                    $result = [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord]@{
                        'Message' = "Vulnerable port $port is being opened by firewall rule."
                        'RuleName' = 'VulnerablePortsRule'
                        'Severity' = 'Warning'
                        'Extent' = $invocation.Extent
                    }
                    $results += $result
                }
            }
        }

        return $results
    }
}

# Export the function so it can be used by PSScriptAnalyzer
Export-ModuleMember -Function Measure-VulnerablePortsRule
