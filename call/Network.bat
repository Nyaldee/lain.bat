@echo off
netsh dump > "%USERPROFILE%\Desktop\backup_netsh.txt"
:: netsh -f "%USERPROFILE%\Desktop\backup_netsh.txt"
netsh int ip reset >nul 2>&1
netsh winsock reset >nul 2>&1
ipconfig /flushdns >nul 2>&1
:: netsh advfirewall reset
for %%I in ("Ethernet" "Ethernet 2" "Wi-Fi" "Wi-Fi 2" "WiFi" "WiFi 2" "Ethernet2" "Wi-Fi2") do (
    netsh int ipv4 set dns name="%%I" static 1.1.1.1 primary validate=no >nul 2>&1
    netsh int ipv4 add dns name="%%I" 1.0.0.1 index=2 >nul 2>&1
)
netsh advfirewall firewall set rule group="Network Discovery" new enable=No >nul 2>&1
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No >nul 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul 2>&1
powershell -Command "Enable-NetAdapterChecksumOffload -Name "*" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Disable-NetAdapterChecksumOffload -Name "*" -IpIPv4 -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Disable-NetAdapterChecksumOffload -Name "*" -UdpIPv4 -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Disable-NetAdapterChecksumOffload -Name "*" -UdpIPv6 -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Disable-NetAdapterLso -Name "*" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Advanced EEE' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'ARP Offload' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'AutoDetach' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Auto Disable Gigabit' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Energy-Efficient Ethernet' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Flow Control' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Gigabit Lite' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Green Ethernet' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'IPv4 Checksum Offload' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Jumbo Frame' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Large Send Offload v2 (IPv4)' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Large Send Offload v2 (IPv6)' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'TCP Checksum Offload (IPv4)' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'TCP Checksum Offload (IPv6)' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'UDP Checksum Offload (IPv4)' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'UDP Checksum Offload (IPv6)' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'JumboPacket' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Log Link State Event' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'NS Offload' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Power Saving Mode' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'PTP Hardware Timetamp' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Priority & VLAN' -DisplayValue "Enabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Packet Priority & VLAN' -DisplayValue "Enabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Receive Side Scaling' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Wait for Link' -DisplayValue "Off" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Wake on Link Settings' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Wake on Magic Packet' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Wake on magic packet when system is in the S0ix power state' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Shutdown Wake-On-Lan' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name "*" -DisplayName 'Wake on pattern match' -DisplayValue "Disabled" -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Disable-NetAdapterBinding -Name '*' -AllBindings -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Enable-NetAdapterBinding -Name '*' -ComponentID ms_pacer -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Get-WmiObject Win32_NetworkAdapterConfiguration | ForEach-Object { $_.SetTcpipNetbios(2) } -ErrorAction SilentlyContinue | Out-Null"
(ipconfig /flushdns & ipconfig /release & ipconfig /renew) >nul 2>&1
netsh interface ip delete arpcache >nul 2>&1
netsh int tcp set global rsc=disabled ecn=enabled >nul 2>&1
powershell -Command "Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetOffloadGlobalSetting -ReceiveSideScaling disabled -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled -ErrorAction SilentlyContinue | Out-Null"
netsh int tcp set supplemental template=Internet congestionprovider=DCTCP >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "1048576" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "1048576" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "BufferAlignment" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DoNotHoldNICBuffers" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DisableDirectAcceptEx" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DisableChainedReceive" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "IgnorePushBitOnReceives" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "IgnoreOrderlyRelease" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "DisableAddressSharing" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "1024" /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "1024" /f >nul 2>&1
pause
