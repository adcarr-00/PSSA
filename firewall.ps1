Write-Output 'This is a Test to check that the PS script does not open vulnerable ports inbound'
New-NetFirewallRule -DisplayName 'Open Telnet' -Direction Inbound -LocalPort 21001 -Protocol TCP -Service "TlntSvr" -Action Allow
New-NetFirewallRule -DisplayName 'Open FTPD' -Direction Inbound -Protocol TCP -Service "ftpsvc" -Action Allow
New-NetFirewallRule -DisplayName 'Open SMB' -Direction Inbound -Protocol TCP -Service "LanmanServer" -Action Allow
Get-NetTCPConnection -State Listen
