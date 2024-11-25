# VulnerablePortsRule.psm1

<#
.SYNOPSIS
Detects the use of services with known vulnerabilities (e.g., SMB, Telnet, FTP) in firewall rule configurations.

.DESCRIPTION
Ports opened on Windows machines should not introduce known vulnerable services. To fix the violation of this rule, 
remove the vulnerable service. Seek guidance for secure networking configuration if further assistance is required.

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
            [string[]]$vulnerableServices = @("ftpsvc", "TlntSvr", "LanmanServer")

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
                            if ($elementAst -match "-Service") {
                                # The next element in the CommandElements array is the argument for the parameter
                                $portAst = $comAst.CommandElements[$comAst.CommandElements.IndexOf($elementAst) + 1].ToString()
                                # Check if the port is in the list of vulnerable ports
                                foreach ($vulnService in $vulnerableServices) {
                                    if ($portAst.Trim() -eq $vulnService) {
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
                        'Message' = (Get-Help Measure-VulnerablePortsRule).Description.Text -replace "`r`n", " "
                        'Extent' = $Violation.Extent
                        'RuleName' = $PSCmdlet.MyInvocation.InvocationName
                        'Severity' = 'Error'
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
