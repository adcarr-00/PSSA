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
        try
        {
            # Define the known vulnerable ports
            $vulnerablePorts = @(23, 139, 445, 3389)

            # Predicate to detect `New-NetFirewallRule` cmdlet and check for vulnerable ports
            [ScriptBlock]$Predicate = {
                Param ([System.Management.Automation.Language.Ast]$Ast)
                [bool]$returnValue = $false
                if ($Ast -is [System.Management.Automation.Language.CommandAst])
                {
                    [System.Management.Automation.Language.CommandAst]$comAst = $Ast

                    # Check if the cmdlet is New-NetFirewallRule
                    if ($comAst.CommandElements[0].ToString() -match "New-NetFirewallRule|Set-NetFirewallRule"){
                        # Loop through the CommandElementAst objects (parameters and arguments)
                        foreach ($elementAst in $comAst.CommandElements) {
                            # Check for the parameters that involve ports (LocalPort or RemotePort)
                            if ($elementAst -match "-LocalPort|-RemotePort") {
                                # The next element in the CommandElements array is the argument for the parameter
                                $portAst = $comAst.CommandElements[$comAst.CommandElements.IndexOf($elementAst) + 1]
                                # Check if the port is in the list of vulnerable ports
                                foreach ($port in $vulnerablePorts) {
                                    if ($portAst -eq $port.ToString()) {
                                        $returnValue = $true
                                    }
                                }
                            }
                        }
                    }
                }
                return $returnValue
            }
            [System.Management.Automation.Language.Ast[]]$Violations = $ScriptBlockAst.FindAll($Predicate,$True)
            Foreach ($Violation in $Violations) {
                    $result = [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord]@{
                        'Message' = "This is a firewall rule"
                        'Extent' = $Violation.Extent
                        'RuleName' = $PSCmdlet.MyInvocation.InvocationName
                        'Severity' = 'Information'
                    }       
                    $results += $result
            }
            return $results
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
}

# Export the function so it can be used by PSScriptAnalyzer
Export-ModuleMember -Function Measure-*
