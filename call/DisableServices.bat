reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "AutoRun" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
net stop "beep" /y >nul 2>&1 & sc config "beep" start= Disabled >nul 2>&1
net stop "DusmSvc" /y >nul 2>&1 & sc config "DusmSvc" start= Disabled >nul 2>&1
net stop "RasMan" /y >nul 2>&1 & sc config "RasMan" start= Disabled >nul 2>&1
net stop "SstpSvc" /y >nul 2>&1 & sc config "SstpSvc" start= Disabled >nul 2>&1
net stop "BthAvctpSvc" /y >nul 2>&1 & sc config "BthAvctpSvc" start= Disabled >nul 2>&1
net stop "DsmSvc" /y >nul 2>&1 & sc config "DsmSvc" start= Disabled >nul 2>&1
net stop "MapsBroker" /y >nul 2>&1 & sc config "MapsBroker" start= Disabled >nul 2>&1
net stop "DiagTrack" /y >nul 2>&1 & sc config "DiagTrack" start= Disabled >nul 2>&1
net stop "VaultSvc" /y >nul 2>&1 & sc config "VaultSvc" start= Disabled >nul 2>&1
net stop "DmEnrollmentSvc" /y >nul 2>&1 & sc config "DmEnrollmentSvc" start= Disabled >nul 2>&1
net stop "DPS" /y >nul 2>&1 & sc config "DPS" start= Disabled >nul 2>&1
net stop "WdiSystemHost" /y >nul 2>&1 & sc config "WdiSystemHost" start= Disabled >nul 2>&1
net stop "DisplayEnhancementService" /y >nul 2>&1 & sc config "DisplayEnhancementService" start= Disabled >nul 2>&1
net stop "TrkWks" /y >nul 2>&1 & sc config "TrkWks" start= Disabled >nul 2>&1
net stop "lfsvc" /y >nul 2>&1 & sc config "lfsvc" start= Disabled >nul 2>&1
net stop "gpsvc" /y >nul 2>&1 & sc config "gpsvc" start= Disabled >nul 2>&1
net stop "wlidsvc" /y >nul 2>&1 & sc config "wlidsvc" start= Disabled >nul 2>&1
net stop "NgcCtnrSvc" /y >nul 2>&1 & sc config "NgcCtnrSvc" start= Disabled >nul 2>&1
net stop "InstallService" /y >nul 2>&1 & sc config "InstallService" start= Disabled >nul 2>&1
net stop "Spooler" /y >nul 2>&1 & sc config "Spooler" start= Disabled >nul 2>&1
net stop "PcaSvc" /y >nul 2>&1 & sc config "PcaSvc" start= Disabled >nul 2>&1
net stop "seclogon" /y >nul 2>&1 & sc config "seclogon" start= Disabled >nul 2>&1
net stop "SSDPSRV" /y >nul 2>&1 & sc config "SSDPSRV" start= Disabled >nul 2>&1
net stop "SysMain" /y >nul 2>&1 & sc config "SysMain" start= Disabled >nul 2>&1
net stop "Themes" /y >nul 2>&1 & sc config "Themes" start= Disabled >nul 2>&1
net stop "TabletInputService" /y >nul 2>&1 & sc config "TabletInputService" start= Disabled >nul 2>&1
net stop "StiSvc" /y >nul 2>&1 & sc config "StiSvc" start= Disabled >nul 2>&1
net stop "WManSvc" /y >nul 2>&1 & sc config "WManSvc" start= Disabled >nul 2>&1
net stop "WSearch" /y >nul 2>&1 & sc config "WSearch" start= Disabled >nul 2>&1
net stop "LanmanWorkstation" /y >nul 2>&1 & sc config "LanmanWorkstation" start= Disabled >nul 2>&1
net stop "XboxGipSvc" /y >nul 2>&1 & sc config "XboxGipSvc" start= Disabled >nul 2>&1
net stop "LanmanServer" /y >nul 2>&1 & sc config "LanmanServer" start= Disabled >nul 2>&1
net stop "PlugPlay" /y >nul 2>&1 & sc config "PlugPlay" start= Disabled >nul 2>&1
net stop "SENS" /y >nul 2>&1 & sc config "SENS" start= Disabled >nul 2>&1
net stop "EventSystem" /y >nul 2>&1 & sc config "EventSystem" start= Disabled >nul 2>&1
net stop "ShellHWDetection" /y >nul 2>&1 & sc config "ShellHWDetection" start= Disabled >nul 2>&1
net stop "hidserv" /y >nul 2>&1 & sc config "hidserv" start= Disabled >nul 2>&1
net stop "DoSvc" /y >nul 2>&1 & sc config "DoSvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
net stop "ClipSVC" /y >nul 2>&1 & sc config "ClipSVC" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
net stop "cbdhsvc" /y >nul 2>&1 & sc config "cbdhsvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
net stop "SgrmBroker" /y >nul 2>&1 & sc config "SgrmBroker" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
net stop "OneSyncSvc" /y >nul 2>&1 & sc config "OneSyncSvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
net stop "dmwappushservice" /y >nul 2>&1 & sc config "dmwappushservice" start= Disabled >nul 2>&1
net stop "Parsec" /y >nul 2>&1 & sc config "Parsec" start= Disabled >nul 2>&1
net stop "LeapService" /y >nul 2>&1 & sc config "LeapService" start= Disabled >nul 2>&1
net stop "AdobeARMservice" /y >nul 2>&1 & sc config "AdobeARMservice" start= Disabled >nul 2>&1
net stop "McAfee WebAdvisor" /y >nul 2>&1 & sc config "McAfee WebAdvisor" start= Disabled >nul 2>&1
net stop "VBoxSDS" /y >nul 2>&1 & sc config "VBoxSDS" start= Disabled >nul 2>&1
net stop "brave" /y >nul 2>&1 & sc config "brave" start= Disabled >nul 2>&1
net stop "bravem" /y >nul 2>&1 & sc config "bravem" start= Disabled >nul 2>&1
net stop "BraveElevationService" /y >nul 2>&1 & sc config "BraveElevationService" start= Disabled >nul 2>&1
net stop "gupdate" /y >nul 2>&1 & sc config "gupdate" start= Disabled >nul 2>&1
net stop "gupdatem" /y >nul 2>&1 & sc config "gupdatem" start= Disabled >nul 2>&1
net stop "GoogleChromeElevationService" /y >nul 2>&1 & sc config "GoogleChromeElevationService" start= Disabled >nul 2>&1
net stop "MicrosoftEdgeElevationService" /y >nul 2>&1 & sc config "MicrosoftEdgeElevationService" start= Disabled >nul 2>&1
net stop "edgeupdate" /y >nul 2>&1 & sc config "edgeupdate" start= Disabled >nul 2>&1
net stop "edgeupdatem" /y >nul 2>&1 & sc config "edgeupdatem" start= Disabled >nul 2>&1
net stop "ArmouryCrateService" /y >nul 2>&1 & sc config "ArmouryCrateService" start= Disabled >nul 2>&1
net stop "asComSvc" /y >nul 2>&1 & sc config "asComSvc" start= Disabled >nul 2>&1
net stop "asus" /y >nul 2>&1 & sc config "asus" start= Disabled >nul 2>&1
net stop "asusm" /y >nul 2>&1 & sc config "asusm" start= Disabled >nul 2>&1
net stop "AsusCertService" /y >nul 2>&1 & sc config "AsusCertService" start= Disabled >nul 2>&1
net stop "AsusROGLSLService" /y >nul 2>&1 & sc config "AsusROGLSLService" start= Disabled >nul 2>&1
net stop "LightingService" /y >nul 2>&1 & sc config "LightingService" start= Disabled >nul 2>&1
net stop "ROG Live Service" /y >nul 2>&1 & sc config "ROG Live Service" start= Disabled >nul 2>&1
net stop "NahimicService" /y >nul 2>&1 & sc config "NahimicService" start= Disabled >nul 2>&1
net stop "ASUSSoftwareManager" /y >nul 2>&1 & sc config "ASUSSoftwareManager" start= Disabled >nul 2>&1
net stop "ASUSSwitch" /y >nul 2>&1 & sc config "ASUSSwitch" start= Disabled >nul 2>&1
net stop "ASUSSystemAnalysis" /y >nul 2>&1 & sc config "ASUSSystemAnalysis" start= Disabled >nul 2>&1
net stop "ASUSSystemDiagnosis" /y >nul 2>&1 & sc config "ASUSSystemDiagnosis" start= Disabled >nul 2>&1
net stop "Razer Chroma SDK Server" /y >nul 2>&1 & sc config "Razer Chroma SDK Server" start= Disabled >nul 2>&1
net stop "Razer Chroma SDK Service" /y >nul 2>&1 & sc config "Razer Chroma SDK Service" start= Disabled >nul 2>&1
net stop "Razer Chroma Stream Server" /y >nul 2>&1 & sc config "Razer Chroma Stream Server" start= Disabled >nul 2>&1
net stop "Razer Update Service" /y >nul 2>&1 & sc config "Razer Update Service" start= Disabled >nul 2>&1
net stop "RzKLService" /y >nul 2>&1 & sc config "RzKLService" start= Disabled >nul 2>&1
net stop "RzThxSrv" /y >nul 2>&1 & sc config "RzThxSrv" start= Disabled >nul 2>&1
net stop "Razer Game Scanner" /y >nul 2>&1 & sc config "Razer Game Scanner" start= Disabled >nul 2>&1
net stop "logi_lamparray_service" /y >nul 2>&1 & sc config "logi_lamparray_service" start= Disabled >nul 2>&1
net stop "nebula" /y >nul 2>&1 & sc config "nebula" start= Disabled >nul 2>&1
net stop "LGHUBUpdaterService" /y >nul 2>&1 & sc config "LGHUBUpdaterService" start= Disabled >nul 2>&1
net stop "HPPrintScanDoctorService" /y >nul 2>&1 & sc config "HPPrintScanDoctorService" start= Disabled >nul 2>&1
net stop "APNMCP" /y >nul 2>&1 & sc config "APNMCP" start= Disabled >nul 2>&1
net stop "BingDesktopUpdate" /y >nul 2>&1 & sc config "BingDesktopUpdate" start= Disabled >nul 2>&1
net stop "Steam Client Service" /y >nul 2>&1 & sc config "Steam Client Service" start= Disabled >nul 2>&1
net stop "CCleanerPerformanceOptimizerService" /y >nul 2>&1 & sc config "CCleanerPerformanceOptimizerService" start= Disabled >nul 2>&1
net stop "EABackgroundService" /y >nul 2>&1 & sc config "EABackgroundService" start= Disabled >nul 2>&1
net stop "aswbIDSAgent" /y >nul 2>&1 & sc config "aswbIDSAgent" start= Disabled >nul 2>&1
