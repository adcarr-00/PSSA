# VulnerablePortsRule.psm1

<#
.SYNOPSIS
Detects the use of vulnerable ports (e.g., 23, 139, 445, 3389) in firewall rule configurations.

.DESCRIPTION
This custom rule for PSScriptAnalyzer analyzes PowerShell scripts to detect the use of specific cmdlets 
(`New-NetFirewallRule` or `Set-NetFirewallRule`) that open vulnerable ports, such as Telnet (Port 23), 
NetBIOS (Port 139), SMB (Port 445), and RDP (Port 3389). It flags these occurrences with a warning.

.EXAMPLE
Measure-VulnerablePortsRule -ScriptBlockAst $ScriptBlockAst

This command analyzes the script block and checks if any of the vulnerable ports are being opened via 
firewall rules.

.INPUTS
[System.Management.Automation.Language.ScriptBlockAst]

The function accepts a ScriptBlockAst, which is the abstract syntax tree (AST) of a PowerShell script.

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
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    process {
        $results = @()

        # Define known vulnerable ports
        $vulnerablePorts = @(23, 139, 445, 3389)

        # Define a predicate to find cmdlets that may open ports
        [ScriptBlock]$predicate = {
            param ([System.Management.Automation.Language.Ast]$Ast)
            if ($Ast -is [System.Management.Automation.Language.InvocationExpressionAst]) {
                $cmdlet = $Ast.Command.ToString()
                return $cmdlet -match "New-NetFirewallRule|Set-NetFirewallRule"
            }
            return $false
        }

        # Find the ASTs that match the predicate (cmdlets opening ports)
        [System.Management.Automation.Language.Ast[]]$firewallCmdletAst = $ScriptBlockAst.FindAll($predicate, $true)

        # Now, check if any vulnerable port is mentioned in the script
        foreach ($port in $vulnerablePorts) {
            [ScriptBlock]$portPredicate = {
                param ([System.Management.Automation.Language.Ast]$Ast)
                if ($Ast -is [System.Management.Automation.Language.LiteralExpressionAst]) {
                    return $Ast.Value -eq $port
                }
                return $false
            }

            $portAst = $ScriptBlockAst.FindAll($portPredicate, $true)
            if ($portAst.Count -gt 0 -and $firewallCmdletAst.Count -gt 0) {
                $result = [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord]@{
                    'Message' = "Vulnerable port $port is being opened by firewall rule."
                    'Extent' = $firewallCmdletAst[0].Extent
                    'RuleName' = 'VulnerablePortsRule'
                    'Severity' = 'Warning'
                }
                $results += $result
            }
        }

        return $results
    }
}

# Export the function so it can be used by PSScriptAnalyzer
Export-ModuleMember -Function Measure-VulnerablePortsRule
