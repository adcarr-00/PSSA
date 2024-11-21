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
            
            # Debugging the predicate itself
            Write-Host "Checking AST: $($Ast.GetType().Name)"
            
            if ($Ast -is [System.Management.Automation.Language.CommandAst]) {
                $cmdlet = $Ast.Command.ToString()
                
                # Debugging: print the cmdlet found
                Write-Host "Found cmdlet: $cmdlet"

                # Check if the command is one of the vulnerable firewall cmdlets
                return $cmdlet -match "New-NetFirewallRule|Set-NetFirewallRule"
            }

            return $false
        }

        # Find the ASTs that match the predicate (cmdlets opening ports)
        [System.Management.Automation.Language.Ast[]]$firewallCmdletAst = $ScriptBlockAst.FindAll($predicate, $true)

        # Debugging output for ASTs found
        Write-Host "Found $($firewallCmdletAst.Count) cmdlet(s) that might open ports"

        if ($firewallCmdletAst.Count -gt 0) {
            # For each found command, we will check for vulnerable ports
            foreach ($cmd in $firewallCmdletAst) {
                # Ensure $cmd is a valid CommandAst
                if ($cmd -is [System.Management.Automation.Language.CommandAst]) {
                    # Debugging: print the command being processed
                    Write-Host "Processing CommandAst: $($cmd.Command)"

                    # Ensure CommandElements is not null
                    $commandArgs = $cmd.CommandElements

                    # Debugging: print the command arguments
                    if ($commandArgs -eq $null) {
                        Write-Host "Command elements are null"
                    } else {
                        Write-Host "Command elements found: $($commandArgs.Count)"
                    }

                    if ($commandArgs -ne $null) {
                        # Check if any arguments contain a vulnerable port (example: 23, 139, 445, 3389)
                        foreach ($arg in $commandArgs) {
                            # Debugging: print the argument and check for $arg.Extent
                            Write-Host "Processing argument: $($arg.ToString())"
                            
                            if ($arg.Extent -eq $null) {
                                Write-Host "Argument Extent is null for: $($arg.ToString())"
                            } else {
                                Write-Host "Argument Extent: $($arg.Extent)"
                            }

                            foreach ($port in $vulnerablePorts) {
                                if ($arg.Extent -ne $null -and $arg.Extent.ToString() -match "\b$port\b") {
                                    Write-Host "Vulnerable port $port detected in argument $($arg.ToString())"

                                    $results += [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord]@{
                                        'Message' = "Vulnerable port $port is being opened or configured in $($cmd.GetCommandName())"
                                        'Extent' = $cmd.Extent
                                        'RuleName' = 'VulnerablePortDetection'
                                        'Severity' = 'Warning'
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Write-Host "Skipping non-CommandAst: $($cmd)"
                }
            }
        } else {
            Write-Host "No matching cmdlets found in the script."
        }

        return $results
    }
}

# Export the function so it can be used by PSScriptAnalyzer
Export-ModuleMember -Function Measure-VulnerablePortsRule
