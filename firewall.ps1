Write-Output 'This is a Test to check that the PS script does not open vulnerable ports inbound'
New-NetFirewallRule -DisplayName 'Open Telnet' -Direction Inbound -LocalPort 23 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName 'Open FTP' -Direction Inbound -LocalPort 20 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName 'Open FTP1' -Direction Inbound -LocalPort 21 -Protocol TCP -Action Allow
Get-NetTCPConnection -State Listen
