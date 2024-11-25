# PSScriptAnalyzerSettings.psd1
@{
    Severity = @('Error', 'Warning')
    CustomRulePath = @('.\security-settings\VulnerablePortsRule.psm1')
    IncludeDefaultRules = $true
}
