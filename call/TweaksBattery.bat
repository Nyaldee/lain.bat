@echo off
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabled /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabledDefault /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMax /t REG_DWORD /d 100 /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMax /t REG_DWORD /d 100 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMin /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMin /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v CsEnabled /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v VideoQualityOnBattery /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /v DisableANQP /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\WlanSvc\Scan" /v ScanWhenAssociated /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v EnableActiveProbing /t REG_DWORD /d 0 /f >nul 2>&1
bcdedit /deletevalue useplatformtick >nul 2>&1
bcdedit /set disabledynamictick No >nul 2>&1
powercfg -restoredefaultschemes >nul 2>&1
powercfg /hibernate on >nul 2>&1
powershell -Command "Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Energy-Efficient Ethernet' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Green Ethernet' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Power Saving Mode' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Idle power down restriction' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'Reduce Speed On Power Down' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Enable-NetAdapterChecksumOffload -Name '*' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Enable-NetAdapterLso -Name '*' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Enable-NetAdapterRsc -Name '*' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'ARP Offload' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Set-NetAdapterAdvancedProperty -Name '*' -DisplayName 'NS Offload' -DisplayValue 'Enabled' -ErrorAction SilentlyContinue | Out-Null"
