@echo off
chcp 65001 >nul
title lain.bat & Color 03
mode con cols=90 lines=35

:: --- CONSTANTES : fichiers distants (dépôt lain.bat) ------------------------
set "CALL_URL=https://github.com/Nyaldee/lain.bat/raw/main/call"
set "URL_TWEAKS_REG=%CALL_URL%/Tweaks.reg"
set "URL_NETWORK=%CALL_URL%/Network.bat"
set "URL_POWERPLAN=%CALL_URL%/PowerPlan.bat"
set "URL_TWEAKS_BATTERY=%CALL_URL%/TweaksBattery.bat"
set "URL_DISABLE_SERVICES=%CALL_URL%/DisableServices.bat"
set "URL_RESTORE_SERVICES=%CALL_URL%/RestoreServices.bat"
set "URL_HOSTS_ADD=%CALL_URL%/CustomHostsAdd.bat"
set "URL_FIREWALL_ADD=%CALL_URL%/FirewallRulesAdd.bat"
set "URL_HOSTS_REMOVE=%CALL_URL%/CustomHostsRemove.bat"
set "URL_FIREWALL_REMOVE=%CALL_URL%/FirewallRulesRemove.bat"
set "URL_TIMER_RESOLUTION=%CALL_URL%/SetTimerResolutionService.exe"
set "URL_NVCLEANSTALL=%CALL_URL%/NVCleanstall.exe"
set "URL_NVIDIA_PROFILE_INSPECTOR=%CALL_URL%/nvidiaProfileInspector.exe"
set "URL_NVIDIA_BASE_PROFILE=%CALL_URL%/NvidiaBaseProfile.nip"
set "URL_MSI_UTIL=%CALL_URL%/MSI_util_v3.exe"
set "URL_LIBREWOLF_REGISTER=%CALL_URL%/LibreWolfRegister.bat"
set "URL_SAGESET_REG=%CALL_URL%/sageset.reg"

:: --- CONSTANTES : services Windows ------------------------------------------
set "SVC_BLUETOOTH=bthserv"
set "SVC_BLUETOOTH_AUDIO=BTAGService"
set "SVC_WIFI=WlanSvc"
set "SVC_TIMER_RESOLUTION=STR"
set "SVC_WIN_UPDATE_ORCHESTRATOR=UsoSvc"
set "SVC_WIN_UPDATE_AGENT=wuauserv"
set "SVC_WAAS_MEDIC=WaaSMedicSvc"

:: --- CONSTANTES : fichiers renommés (bascule .exe/.dll <-> .bak) ------------
set "FILE_SMARTSCREEN=%SystemRoot%\System32\smartscreen.exe"
set "FILE_SMARTSCREEN_BAK=%SystemRoot%\System32\smartscreen.bak"
set "FILE_WUAUENG=%SystemRoot%\System32\wuaueng.dll"
set "FILE_WUAUENG_BAK=%SystemRoot%\System32\wuaueng.bak"
set "FILE_WAASMEDIC=%SystemRoot%\System32\WaasMedicSvc.dll"
set "FILE_WAASMEDIC_BAK=%SystemRoot%\System32\WaasMedicSvc.bak"

:: --- CONSTANTES : identifiants (CLSID / GUID) -------------------------------
set "CLSID_CLASSIC_CONTEXT_MENU={86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
set "GUID_SCHEME_BALANCED=381b4222-f694-41f0-9685-ff5bb260df2e"
set "GUID_SCHEME_CUSTOM=77777777-7777-7777-7777-777777777777"
set "GUID_SCHEME_POWER_SAVER=8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
set "GUID_SCHEME_HIGH_PERFORMANCE=a1841308-3541-4fab-bc81-f71556f20b4a"
set "GUID_SCHEME_ULTIMATE_PERFORMANCE=e9a42b02-d5df-448d-aa00-03f14749eb61"

:: --- CONSTANTES : répertoires temporaires -----------------------------------
set "TEMP_DIR=%Temp%\TheWired"

echo [ INITIALIZATION ]
echo ══════════════════════════════════════════════════════════════════════════════════════════
fltmc >nul 2>&1
if errorlevel 1 (
    echo [!] ROOT ACCESS REQUIRED / ACCÈS ROOT REQUIS.
    pause
    exit /b
) else (
    echo [OK] ROOT ACCESS GRANTED / ACCÈS ROOT VALIDÉ.
)
:: Teste l'hôte réellement utilisé par le script (curl/HTTPS), pas juste l'ICMP :
:: un ping peut être bloqué sans casser HTTPS, et inversement un DNS cassé
:: n'empêcherait pas un ping vers une IP brute de réussir.
curl -s -o NUL --max-time 5 -I "https://github.com" >nul 2>&1
if errorlevel 1 (
    echo [!] NO NETWORK SIGNAL / SIGNAL RÉSEAU INEXISTANT.
    pause
    exit /b
) else (
    echo [OK] NETWORK LINK ESTABLISHED / SIGNAL RÉSEAU ACTIF.
    timeout /t 3 >nul
)
cls
echo.⠄⠄⠄⠄⢠⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣿⣯⢻⣿⣿⣿⣿⣆⠄⠄⠄
echo.⠄⠄⣼⢀⣿⣿⣿⣿⣏⡏⠄⠹⣿⣿⣿⣿⣿⣿⣿⣿⣧⢻⣿⣿⣿⣿⡆⠄⠄
echo.⠄⠄⡟⣼⣿⣿⣿⣿⣿⠄⠄⠄⠈⠻⣿⣿⣿⣿⣿⣿⣿⣇⢻⣿⣿⣿⣿⠄⠄     __      __          __          __ 
echo.⠄⢰⠃⣿⣿⠿⣿⣿⣿⠄⠄⠄⠄⠄⠄⠙⠿⣿⣿⣿⣿⣿⠄⢿⣿⣿⣿⡄⠄    / /___ _/_/___      / /_  ____ _/ /_
echo.⠄⢸⢠⣿⣿⣧⡙⣿⣿⡆⠄⠄⠄⠄⠄⠄⠄⠈⠛⢿⣿⣿⡇⠸⣿⡿⣸⡇⠄   / / __ `/ / __ \    / __ \/ __ `/ __/
echo.⠄⠈⡆⣿⣿⣿⣿⣦⡙⠳⠄⠄⠄⠄⠄⠄⢀⣠⣤⣀⣈⠙⠃⠄⠿⢇⣿⡇⠄  / / /_/ / / / / /__ / /_/ / /_/ / /_  
echo.⠄⠄⡇⢿⣿⣿⣿⣿⡇⠄⠄⠄⠄⠄⣠⣶⣿⣿⣿⣿⣿⣿⣷⣆⡀⣼⣿⡇⠄ /_/\__,_/_/_/ /_//_//_.___/\__,_/\__/  
echo.⠄⠄⢹⡘⣿⣿⣿⢿⣷⡀⠄⢀⣴⣾⣟⠉⠉⠉⠉⣽⣿⣿⣿⣿⠇⢹⣿⠃⠄ 
echo.⠄⠄⠄⢷⡘⢿⣿⣎⢻⣷⠰⣿⣿⣿⣿⣦⣀⣀⣴⣿⣿⣿⠟⢫⡾⢸⡟⠄.  🇳🇾🇦🇱🇩🇪🇪 🇴🇵🇹🇮🇲🇮🇿🇪🇷
echo.⠄⠄⠄⠄⠻⣦⡙⠿⣧⠙⢷⠙⠻⠿⢿⡿⠿⠿⠛⠋⠉⠄⠂⠘⠁⠞⠄⠄⠄
echo.⠄⠄⠄⠄⠄⠈⠙⠑⣠⣤⣴⡖⠄⠿⣋⣉⣉⡁⠄⢾⣦⠄⠄⠄⠄⠄⠄⠄⠄
echo.
echo Use at your own risk, without any warranty.
echo Back up your files and create a restore point beforehand.
echo Utilisation à vos propres risques, sans aucune garantie.
echo Sauvegardez vos fichiers et créez un point de restauration au préalable.
echo ══════════════════════════════════════════════════════════════════════════════════════════
echo Bios optimization :
echo  ► ENABLE : Re-Size BAR Support/4G Decoding, Precision Boost Overdrive, EXPO/XMP profile,
echo L1/L2 Prefetcher, CPPC/CPPC Preferred, SMT
echo  ► DISABLE : Internal Graphics, SVM/VMX Mode, Drivers Software, CSM Support,
echo Fastboot, High Precision Event Timer (?)
echo  ► CAUTION/NONE : Global C-state Control, ACPI_CST C1 Declaration
echo.
choice /C AR /N /M "══════════════════════════════════['A'ccept / 'R'eject]═══════════════════════════════════"
if errorlevel 2 exit /b
goto Main_menu

:Main_menu
cls
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                                                              ║
echo ║      ✦ lain.bat menu ✦   [ v1.0 ]                            ║
echo ║                                                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo   [01] ⚡ Create a restore point / Créer un point de restauration
echo   [02] ⚡ Configure NVIDIA / Configuration NVIDIA
echo   [03] ⚡ System Settings / Configuration globale (restart after)
echo   [04] ⚡ Network Settings / Paramètres réseau (not safe)
echo   [05] ⚡ Power Plan / Plan d’alimentation
echo   [06] ⚡ Install Runtime ^& Frameworks / Installer les runtimes et frameworks
echo   [07] ⚡ Install Timer Resolution Service / Installer le service Timer Resolution
echo   [08] ⚡ Disable Unnecessary Services / Désactiver les services inutiles
echo   [09] ⚡ Disable SmartScreen ^& Block Edge / Désactiver SmartScreen et bloquer Edge
echo   [10] ⚡ Disable Bluetooth drivers and services /
echo           Désactiver les drivers et services Bluetooth
echo   [11] ⚡ Disable Wifi drivers and services / Désactiver les drivers et services Wifi
echo   [12] ⚡ Block Tracking ^& Spyware IPs / Bloquer les IPs d’espionnage et de suivi
echo   [13] ⚡ Disable Windows Update / Désactiver Windows Update
echo   [14] ⚡ Miscellaneous / Divers
echo   [15] ⚡ Review Windows Settings / Vérifier les paramètres Windows
echo.
echo   [Q]  Quit / Quitter
echo.
set /p RESPONSE="Choose an option / Choisissez une option :"

if /i "%RESPONSE%"=="q" exit /b
if /i "%RESPONSE%"=="quit" exit /b
if /i "%RESPONSE%"=="exit" exit /b
if "%RESPONSE%"=="1" goto Option1
if "%RESPONSE%"=="2" goto NVIDIA_menu
if "%RESPONSE%"=="3" goto Option3
if "%RESPONSE%"=="4" goto Option4
if "%RESPONSE%"=="5" goto Option5
if "%RESPONSE%"=="6" goto Option6
if "%RESPONSE%"=="7" goto Option7
if "%RESPONSE%"=="8" goto Services_menu
if "%RESPONSE%"=="9" goto Option9
if "%RESPONSE%"=="10" goto Option10
if "%RESPONSE%"=="11" goto Option11
if "%RESPONSE%"=="12" goto Option12
if "%RESPONSE%"=="13" goto Option13
if "%RESPONSE%"=="14" goto Misc_menu
if "%RESPONSE%"=="15" goto Check_menu

echo Invalid choice / Choix invalide
pause
goto Main_menu

:: --- MENU PRINCIPAL ---------------------------------------------------
:Option1
(net start "VSS" /y & sc config "SENS" start= demand) >nul 2>&1
"%SystemRoot%\System32\SystemPropertiesProtection.exe"
goto Main_menu

:Option3
echo. Overall Windows configuration and optimization?
echo. Configuration et optimisation globale de Windows ?
call :AskChoice "['Y'es/'N'o/'V'iew modifications] :" YNV

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto config1
if /i "%RESPONSE%"=="v" goto config2
:config1
echo [ INITIALIZATION ] Please wait... A copy of the registry has been sent to the desktop
echo [ INITIALIZATION ] After this step, please restart the PC and relaunch the tool.
reg export HKLM %Temp%\Temp_HKLM.reg >nul 2>&1 & reg export HKCU %Temp%\Temp_HKCU.reg >nul 2>&1 & reg export HKCR %Temp%\Temp_HKCR.reg >nul 2>&1
copy /b %Temp%\Temp_HKLM.reg + %Temp%\Temp_HKCU.reg + %Temp%\Temp_HKCR.reg %USERPROFILE%\Desktop\Backup_Registry.reg >nul 2>&1
del %Temp%\Temp_HKLM.reg & del %Temp%\Temp_HKCU.reg & del %Temp%\Temp_HKCR.reg
call :Ansi
bcdedit /set quietboot Yes >nul 2>&1
bcdedit /set bootuxdisabled On >nul 2>&1
bcdedit /set tscsyncpolicy enhanced >nul 2>&1
bcdedit /set uselegacyapicmode No >nul 2>&1
bcdedit /set usephysicaldestination No >nul 2>&1
bcdedit /set disabledynamictick Yes >nul 2>&1
bcdedit /deletevalue useplatformclock >nul 2>&1
bcdedit /deletevalue useplatformtick >nul 2>&1
::bcdedit /set spectremitigation disabled >nul 2>&1
::bcdedit /set mitigations off >nul 2>&1
::bcdedit /set usefirmwarepcisettings false >nul 2>&1
::bcdedit /enum
dism /online /Disable-Feature /FeatureName:"Windows-Defender-ApplicationGuard" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"VirtualMachinePlatform" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"HypervisorPlatform" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"WorkFolders-Client" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"MediaPlayback" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Printing-PrintToPDFServices-Features" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Printing-Foundation-Features" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-All" /Quiet /NoRestart >nul 2>&1
lodctr /r >nul 2>&1 && lodctr /r >nul 2>&1
curl -s -L -o "%Temp%\Tweaks.reg" "%URL_TWEAKS_REG%"
reg import "%Temp%\Tweaks.reg" >nul 2>&1 & del "%Temp%\Tweaks.reg"
(
echo @echo off
echo taskkill /F /IM AppActions.exe ^>nul 2^>nul
echo taskkill /F /IM CompatTelRunner.exe ^>nul 2^>nul
echo taskkill /F /IM crashpad_handler.exe ^>nul 2^>nul
echo taskkill /F /IM CrossDeviceResume.exe ^>nul 2^>nul
echo taskkill /F /IM CrossDeviceService.exe ^>nul 2^>nul
echo taskkill /F /IM MicrosoftEdgeUpdate.exe ^>nul 2^>nul
echo taskkill /F /IM smartscreen.exe ^>nul 2^>nul
echo taskkill /F /IM SoftLandingTask.exe ^>nul 2^>nul
echo taskkill /F /IM UserOOBEBroker.exe ^>nul 2^>nul
echo taskkill /F /IM WidgetBoard.exe ^>nul 2^>nul
echo taskkill /F /IM WidgetService.exe ^>nul 2^>nul
echo exit
) > "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\taskkill.bat"
::schtasks /create /tn "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /xml "%SystemRoot%\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /f
::schtasks /create /tn "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /xml "%SystemRoot%\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /f
::schtasks /create /tn "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /xml "%SystemRoot%\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /f
::takeown /F "C:\Windows\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform" /A /R
::icacls "C:\Windows\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform" /grant "NETWORK SERVICE":(F) /T
::schtasks /create /tn "Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /tr "sc start sppsvc" /sc daily /ru "NETWORK SERVICE" /f
::curl -s -L -o "%Temp%\SetACL.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/SetACL.exe"
::%Temp%\SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -ot reg -actn setowner -ownr "n:Administrators" >nul 2>&1
::%Temp%\SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -ot reg -actn ace -ace "n:Administrators;p:full" >nul 2>&1

::%Temp%\SetACL.exe -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache" -ot reg -actn setowner -ownr "n:Administrators" >nul 2>&1
::%Temp%\SetACL.exe -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache" -ot reg -actn ace -ace "n:Administrators;p:full" >nul 2>&1
::del "%Temp%\SetACL.exe"
reg add "HKCR\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2689597440" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f >nul 2>&1
::curl -s -L -o "%Temp%\User Account Pictures.zip" "https://github.com/Nyaldee/lain.bat/raw/main/call/UserAccountPictures.zip"
powershell -Command "cmd /c assoc .ps1=Microsoft.PowerShellScript.1"
powershell -Command "cmd /c ftype Microsoft.PowerShellScript.1='%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe' '%1'"
powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force"
powershell -Command "Get-PnpDevice | Where-Object FriendlyName -like 'Remote Desktop Device Redirector Bus*' | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Get-PnpDevice | Where-Object { $_.FriendlyName -like 'Composite Bus Enumerator*' -or $_.FriendlyName -like 'High precision event timer*' -or $_.FriendlyName -like 'Microsoft Hyper-V Virtualization Infrastructure Driver*' -or $_.FriendlyName -like 'Microsoft Virtual Drive Enumerator*' -or $_.FriendlyName -like 'NDIS Virtual Network Adapter Enumerator*' -or $_.FriendlyName -like 'Numeric data processor*' -or $_.FriendlyName -like 'SM Bus Controller*' -or $_.FriendlyName -like 'Microsoft GS Wavetable Synth*' -or $_.FriendlyName -like 'System speaker*' -or $_.FriendlyName -like 'System timer*' -or $_.FriendlyName -like 'UMBus Root Bus Enumerator*' } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put() } > $null"
::powershell -Command "Expand-Archive -Path '%Temp%\User Account Pictures.zip' -DestinationPath '%ProgramData%\Microsoft\User Account Pictures' -Force"
call :Utf8
::del "%Temp%\User Account Pictures.zip"
wevtutil cl Application >nul 2>&1 & wevtutil cl Security >nul 2>&1 & wevtutil cl Setup >nul 2>&1 & wevtutil cl System >nul 2>&1
call :Done
goto Main_menu

:config2
mode con cols=90 lines=60
cls
echo. • Disable : Unsupported hardware notifications (SV1, SV2), Window animations (MinAnimate), Taskbar animations (TaskbarAnimations), ListView alpha select, ListView shadow, Aero Peek, Hibernate thumbnails, Active network probing (EnableActiveProbing), Remote Assistance (fAllowToGetHelp), LMHOSTS resolution (EnableLMHOSTS), SharedAccess control (EnableControl), Network throttling (SystemResponsiveness = 0), GameDVR/App capture/Game Bar, Background apps access (GlobalUserDisabled), Toast/Notifications (ToastEnabled + multiple Windows.SystemToast keys), Content delivery / Suggested apps / Preinstalled apps, Autoplay, News and Interests, Power hibernate / hiberboot, Windows Script Host, Game DVR policies, StorageSense global, Maps auto-update, Prefetcher, Logon background image, Lock screen, Maintenance scheduled task, Defender removable drive scanning, Many accessibility follow features (Magnifier/Narrator follow options), Beep sound, Startup apps (Run keys cleared), Several WMI autologgers (EventLog-System GUIDs), NV Tray start on login, FTS GR535 (nvlddmkm) disabled, Many autostart / scheduled tasks (EdgeUpdate, Defender taskcache, SyncCenter), Multiple Shell context handlers and modern sharing handlers, Copilot policies (HKCU/HKLM removals), Quick Access frequent/recent, PreInstalledAppsEnabled / SilentInstalledAppsEnabled, System toasts for SecurityAndMaintenance/CapabilityAccess/StartupApp disabled
echo.
echo. • Enable : 7-Zip cascaded menu (CascadedMenu), 7-Zip eliminate duplicate extraction (ElimDupExtract), Full window dragging (DragFullWindows), 7-Zip context menu (ContextMenu flag present), TCP optimizations (TcpAckFrequency = 1, TCPNoDelay = 1), Long paths support (LongPathsEnabled), PowerThrottlingOff (PowerThrottlingOff = 1), Global timer resolution requests, Game tasks scheduling priority/GPU priority tweaks, Allow graphics capture programmatic/without border, Empty/Allow microphone ^& webcam consent where set to Allow, Take Ownership context-menu entries (added), Enable “This PC” / Explorer launch to (LaunchTo = ^1)
echo.
echo. • Remove : MicrosoftEdgeUpdateTaskMachineCore, MicrosoftEdgeUpdateTaskMachineUA, HKCU Run entries, HKLM Run entries, Windows Defender scheduled task entry (TaskCache\Tree\Microsoft\Windows\Windows Defender), SyncCenter task entries, Multiple HomeFolderDesktop DelegateFolders namespaces, Many ShellEx/ContextMenuHandlers (SendTo, ModernSharing, Sharing, Library Location, PintoStartScreen, ShellImagePreview entries, etc.), Numerous SystemFileAssociations ShellEx handlers (image previews, 3D Edit entries), Several CLSID / DelegateFolders entries, WindowsCopilot policy keys (HKCU ^& HKLM), A set of specific Class/ContextMenu handlers listed with leading minus
echo.
echo. • Configure : 7-Zip menu/icons behavior (MenuIcons, ContextMenu flags), Explorer visual effects mode (VisualFXSetting), UserPreferencesMask (visual effects mask), Visual/theme settings (EnableTransparency, AppsUseLightTheme, SystemUsesLightTheme), Taskbar/Explorer advanced flags (IconsOnly, TaskbarMn, Hidden, ShowTaskViewButton, ShowCortanaButton), WindowMetrics and FontSmoothing, Mouse/keyboard repeat/hover/sensitivity settings, JPEG import quality, Startup delay/serialize (Startupdelayinmsec), Network stack tuning (AFD parameters: DefaultSendWindow/ReceiveWindow, buffer and receive/send flags, FastSend/Copy thresholds), NLA active probe hosts (ActiveDnsProbeHost, ActiveWebProbeHost) and probe content, Edge/Chrome policy flags (StartupBoostEnabled, HardwareAccelerationModeEnabled, BackgroundModeEnabled, HighEfficiencyModeEnabled), DeviceMetadata/CapabilityAccess consent values (many set to Deny or Allow), DWM/GraphicsDrivers tuning (HwSchMode, ShaderCacheMode, TdrDelay), SystemProfile multimedia/network throttling index, Prefetch/EnablePrefetcher, Power settings (HibernateEnabled, HiberbootEnabled, Power Throttling value), Windows Script Host disabled setting, GameConfigStore / GameDVR parameters, BackgroundAccessApplications setting, Input personalization / speech/voice activation preferences, Search settings (SearchboxTaskbarMode, IsMSACloudSearchEnabled, IsAADCloudSearchEnabled), Explorer QuickAccess / ShowFrequent / ShowRecent / ShowCloudFilesInQuickAccess, Shell extensions blocked list, Flyout menu settings (ShowSleepOption/ShowLockOption), WaitToKillServiceTimeout / AutoEndTasks / HungAppTimeout / MenuShowDelay / WaitToKillAppTimeout
pause
mode con cols=90 lines=35
goto Option3

:Option4
echo. Network configuration and optimization? (not recommended, may break the network)
echo. Configuration et optimisation du réseau ? (non recommandé)
call :AskChoice "['Y'es/'N'o] :" YN

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto Network

:Network
echo [ INITIALIZATION ] Please wait... Keep your hands up
call :Ansi
call :FetchRunDelete "%URL_NETWORK%" "Network.bat"
call :Utf8
call :Done
goto Main_menu

:Option5
echo. Optimize the power plan?
echo. Optimiser le plan d'alimentation ?
call :AskChoice "['Y'es/'N'o/'E'co/'K'eep Balanced/'R'eset] :" YNEKR

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto Power_1
if /i "%RESPONSE%"=="e" goto Power_2
if /i "%RESPONSE%"=="k" goto Power_3
if /i "%RESPONSE%"=="r" goto Power_4

:Power_1
call :FetchRunDelete "%URL_POWERPLAN%" "PowerPlan.bat"
powercfg /list
pause
goto Main_menu

:Power_2
call :FetchRunDelete "%URL_TWEAKS_BATTERY%" "TweaksBattery.bat"
powercfg /list
pause
goto Main_menu

:Power_3
powercfg -restoredefaultschemes >nul 2>&1
powercfg -duplicatescheme %GUID_SCHEME_BALANCED% %GUID_SCHEME_CUSTOM% >nul 2>&1
powercfg -setactive "%GUID_SCHEME_CUSTOM%" >nul 2>&1
powercfg -delete %GUID_SCHEME_BALANCED% >nul 2>&1
powercfg -delete %GUID_SCHEME_POWER_SAVER% >nul 2>&1
powercfg -delete %GUID_SCHEME_HIGH_PERFORMANCE% >nul 2>&1
powercfg -delete %GUID_SCHEME_ULTIMATE_PERFORMANCE% >nul 2>&1
powercfg /hibernate on >nul 2>&1
powercfg /list
pause
goto Main_menu

:Power_4
powercfg -restoredefaultschemes >nul 2>&1
powercfg /hibernate on >nul 2>&1
powercfg /list
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 100 /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683" /v "Attributes" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "Attributes" /t REG_DWORD /d 1 /f >nul 2>&1
pause
goto Main_menu

:Option6
echo [ INITIALIZATION ] Please wait... Keep your hands up
dism /online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart >nul 2>&1
dism /online /Enable-Feature /FeatureName:NetFx4-AdvSrvs /All /NoRestart >nul 2>&1
md "%TEMP_DIR%" >nul 2>&1
call :FetchOnly "https://github.com/stdin82/htfx/releases/download/v0.0.4/DirectX_Redist_Repack_x86_x64_v3.zip" "DirectX_Redist_Repack_x86_x64.zip" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
tar -xf "%TEMP_DIR%\DirectX_Redist_Repack_x86_x64.zip" -C "%TEMP_DIR%"
if not exist "%TEMP_DIR%\DirectX_Redist_Repack_x86_x64.exe" (
    echo [!] Extraction failed / Échec de l'extraction : DirectX_Redist_Repack_x86_x64.zip
    pause
    goto Main_menu
)
call :FetchOnly "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/7.0.20/windowsdesktop-runtime-7.0.20-win-x64.exe" "windowsdesktop-runtime-7.0.20-win-x64.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://dot.net/v1/dotnet-install.ps1" "dotnet-install.ps1" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" "vcredist2005_x86.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" "vcredist2005_x64.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" "vcredist2008_x86.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe" "vcredist2008_x64.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe" "vcredist2010_x86.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" "vcredist2010_x64.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe" "vcredist2012_x86.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" "vcredist2012_x64.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/2/e/6/2e61cfa4-993b-4dd4-91da-3737cd5cd6e3/vcredist_x86.exe" "vcredist2013_x86.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://download.microsoft.com/download/2/e/6/2e61cfa4-993b-4dd4-91da-3737cd5cd6e3/vcredist_x64.exe" "vcredist2013_x64.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://aka.ms/vs/17/release/vc_redist.x86.exe" "vcredist2022_x86.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
call :FetchOnly "https://aka.ms/vs/17/release/vc_redist.x64.exe" "vcredist2022_x64.exe" "%TEMP_DIR%"
if errorlevel 1 goto Main_menu
start /wait "" "%TEMP_DIR%\vcredist2005_x86.exe" /q
start /wait "" "%TEMP_DIR%\vcredist2005_x64.exe" /q
start /wait "" "%TEMP_DIR%\vcredist2008_x86.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2008_x64.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2010_x86.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2010_x64.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2012_x86.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2012_x64.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2013_x86.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2013_x64.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2022_x86.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\vcredist2022_x64.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\windowsdesktop-runtime-7.0.20-win-x64.exe" /quiet /norestart
start /wait "" "%TEMP_DIR%\DirectX_Redist_Repack_x86_x64.exe" /y
rd "%ProgramFiles%\dotnet" /s /q >nul 2>&1
rd "%LocalAppData%\Microsoft\dotnet" /s /q >nul 2>&1
call :Ansi
powershell -ExecutionPolicy Bypass -File "%TEMP_DIR%\dotnet-install.ps1" -Runtime dotnet -InstallDir "C:\Program Files\dotnet" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='C:\Program Files\dotnet';$k='Machine';$v=[Environment]::GetEnvironmentVariable('Path',$k);if($v -notlike '*'+$p+'*'){[Environment]::SetEnvironmentVariable('Path',($v.TrimEnd(';')+';'+$p),$k)}" >nul 2>&1
call :Utf8
:: where dotnet
:: setx PATH "%PATH%;C:\Program Files\dotnet\" >nul 2>&1
del "%USERPROFILE%\dotnet-install.ps1" /f /q >nul 2>&1
rd "%TEMP_DIR%" /s /q >nul 2>&1
call :Done
goto Main_menu

:Option7
echo. Install Timer Resolution Service?
echo. Installer le service de résolution des délais ?
call :AskChoice "['Y'es/'N'o/'R'emove Service] :" YNR

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto str1
if /i "%RESPONSE%"=="r" goto str2

:str1
curl -s -L -o "%SystemRoot%\SetTimerResolutionService.exe" "%URL_TIMER_RESOLUTION%"
sc create "%SVC_TIMER_RESOLUTION%" binPath= "%SystemRoot%\SetTimerResolutionService.exe" >nul 2>&1
sc config "%SVC_TIMER_RESOLUTION%" start= auto >nul 2>&1
sc description "%SVC_TIMER_RESOLUTION%" "Timer Resolution lets you change your default Windows timer's resolution in a matter of seconds and consequently improves the FPS for the games you are playing." >nul 2>&1
net start "%SVC_TIMER_RESOLUTION%" >nul 2>&1
sc query %SVC_TIMER_RESOLUTION% | findstr STATE
pause
goto Main_menu

:str2
net stop "%SVC_TIMER_RESOLUTION%" /y >nul 2>&1 & sc delete "%SVC_TIMER_RESOLUTION%" >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\%SVC_TIMER_RESOLUTION%" /f >nul 2>&1
sc query %SVC_TIMER_RESOLUTION% | findstr STATE
pause
goto Main_menu

:Option9
echo. Disable SmartScreen and block Edge?
echo. Désactiver SmartScreen et bloquer Edge ?
call :AskChoice "['Y'es/'N'o/'R'eset] :" YNR

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto disablesce1
if /i "%RESPONSE%"=="r" goto disablesce2

:disablesce1
takeown /s %computername% /u %username% /f "%FILE_SMARTSCREEN%" >nul 2>&1
icacls "%FILE_SMARTSCREEN%" /grant:r %username%:F
taskkill /im smartscreen.exe /f
ren "%FILE_SMARTSCREEN%" "smartscreen.bak"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "Edge" /t REG_SZ /d "msedge.exe" /f >nul 2>&1
call :Done
goto Main_menu

:disablesce2
takeown /s %computername% /u %username% /f "%FILE_SMARTSCREEN_BAK%" >nul 2>&1
if exist "%FILE_SMARTSCREEN_BAK%" ren "%FILE_SMARTSCREEN_BAK%" "smartscreen.exe"
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "Edge" /f
call :Done
goto Main_menu

:Option10
echo. Disable Bluetooth drivers and services?
echo. Désactiver les drivers et services Bluetooth ?
call :AskChoice "['Y'es/'N'o/'R'eset] :" YNR

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto disablebt1
if /i "%RESPONSE%"=="r" goto disablebt2

:disablebt1
net stop "%SVC_BLUETOOTH%" /y >nul 2>&1 & sc config "%SVC_BLUETOOTH%" start= disabled >nul 2>&1
net stop "%SVC_BLUETOOTH_AUDIO%" /y >nul 2>&1 & sc config "%SVC_BLUETOOTH_AUDIO%" start= disabled >nul 2>&1
call :Ansi
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
powershell -Command "& { Get-PnpDevice -Class 'Bluetooth' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
call :Utf8
call :Done
goto Main_menu

:disablebt2
net start "%SVC_BLUETOOTH%" >nul 2>&1 & sc config "%SVC_BLUETOOTH%" start= demand >nul 2>&1
net start "%SVC_BLUETOOTH_AUDIO%" >nul 2>&1 & sc config "%SVC_BLUETOOTH_AUDIO%" start= demand >nul 2>&1
call :Ansi
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
powershell -Command "& { Get-PnpDevice -Class 'Bluetooth' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
call :Utf8
call :Done
goto Main_menu

:Option11
echo. Disable Wifi drivers and services?
echo. Désactiver les drivers et services Wifi ?
call :AskChoice "['Y'es/'N'o/'R'eset] :" YNR

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto disablewifi1
if /i "%RESPONSE%"=="r" goto disablewifi2

:disablewifi1
net stop "%SVC_WIFI%" /y >nul 2>&1 & sc config "%SVC_WIFI%" start= disabled >nul 2>&1
call :Ansi
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Wi-Fi*' -or $_.FriendlyName -like '*Wireless*' } | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
call :Utf8
call :Done
goto Main_menu

:disablewifi2
net start "%SVC_WIFI%" >nul 2>&1 & sc config "%SVC_WIFI%" start= auto >nul 2>&1
call :Ansi
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Wi-Fi*' -or $_.FriendlyName -like '*Wireless*' } | ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
call :Utf8
call :Done
goto Main_menu

:Option12
echo. Block spying and tracking IPs (via WindowsSpyBlocker and the host file)? You will no longer receive Windows updates
echo. Bloquer l'espionnage et le suivi des IPs (via WindowsSpyBlocker et le fichier host) ? Vous ne recevrez plus les mises à jour Windows
call :AskChoice "['Y'es/'N'o/'R'eset/'C'lean all] :" YNRC

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto disablespy1
if /i "%RESPONSE%"=="r" goto disablespy2
if /i "%RESPONSE%"=="c" goto disablespy3

:disablespy1
call :FetchRunDelete "%URL_HOSTS_ADD%" "CustomHostsAdd.bat"
call :FetchRunDelete "%URL_FIREWALL_ADD%" "FirewallRulesAdd.bat"
call :Done
goto Main_menu

:disablespy2
call :FetchRunDelete "%URL_HOSTS_REMOVE%" "CustomHostsRemove.bat"
call :FetchRunDelete "%URL_FIREWALL_REMOVE%" "FirewallRulesRemove.bat"
call :Done
goto Main_menu

:disablespy3
netsh advfirewall reset
del %SystemRoot%\system32\drivers\etc\hosts
(
echo # localhost name resolution is handled within DNS itself.
echo # 127.0.0.1       localhost
echo # ::1             localhost
) > %SystemRoot%\System32\drivers\etc\hosts
call :Done
goto Main_menu

:Option13
echo. Disable Windows Update?
echo. Désactiver Windows Update ?
call :AskChoice "['Y'es/'N'o/'R'eset] :" YNR

if /i "%RESPONSE%"=="n" goto Main_menu
if /i "%RESPONSE%"=="y" goto disablewu1
if /i "%RESPONSE%"=="r" goto disablewu2

:disablewu1
net stop "%SVC_WIN_UPDATE_ORCHESTRATOR%" /y >nul 2>&1 & sc config "%SVC_WIN_UPDATE_ORCHESTRATOR%" start= disabled >nul 2>&1
net stop "%SVC_WIN_UPDATE_AGENT%" /y >nul 2>&1 & sc config "%SVC_WIN_UPDATE_AGENT%" start= disabled >nul 2>&1
net stop "%SVC_WAAS_MEDIC%" /y >nul 2>&1 & sc config "%SVC_WAAS_MEDIC%" start= disabled >nul 2>&1
takeown /F "%FILE_WUAUENG%" >nul 2>&1
icacls "%FILE_WUAUENG%" /grant:r %username%:F >nul 2>&1
ren "%FILE_WUAUENG%" "wuaueng.bak"
takeown /F "%FILE_WAASMEDIC%" >nul 2>&1
icacls "%FILE_WAASMEDIC%" /grant:r %username%:F >nul 2>&1
ren "%FILE_WAASMEDIC%" "WaasMedicSvc.bak"
call :Done
goto Main_menu

:disablewu2
takeown /F "%FILE_WUAUENG_BAK%" >nul 2>&1
if exist "%FILE_WUAUENG_BAK%" ren "%FILE_WUAUENG_BAK%" "wuaueng.dll"
takeown /F "%FILE_WAASMEDIC_BAK%" >nul 2>&1
if exist "%FILE_WAASMEDIC_BAK%" ren "%FILE_WAASMEDIC_BAK%" "WaasMedicSvc.dll"
net stop "%SVC_WIN_UPDATE_ORCHESTRATOR%" /y >nul 2>&1 & sc config "%SVC_WIN_UPDATE_ORCHESTRATOR%" start= demand >nul 2>&1
net start "%SVC_WIN_UPDATE_AGENT%" & sc config "%SVC_WIN_UPDATE_AGENT%" start= demand
net start "%SVC_WAAS_MEDIC%" & sc config "%SVC_WAAS_MEDIC%" start= demand
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v Start /t REG_DWORD /d 3 /f
call :Done
goto Main_menu

:: --- MENU NVIDIA --------------------------------------------------------------
:NVIDIA_menu
cls
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                                                              ║
echo ║                  ✦ NVIDIA Configuration ✦                    ║
echo ║                                                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo   [01] ⚡ * Install Drivers with NVCleanstall
echo   [02] ⚡ Applying low-latency optimized 3D settings
echo   [03] ⚡ NVIDIA Control Panel : configure the rest and check manually
echo   [04] ⚡ Check that Message Signaled Interrupt (MSI) is enabled on your GPU.
echo           If supported, enable it (see Google)
echo   [05] ⚡ Enable / disable Ansel
echo   [X]  ⚡ Back to menu / Retour
echo.
echo ════════════════════════════════════════════════════════════════
set /p RESPONSE="Choose an option / Choisissez une option :"

if /i "%RESPONSE%"=="q" goto Main_menu
if /i "%RESPONSE%"=="quit" goto Main_menu
if /i "%RESPONSE%"=="exit" goto Main_menu
if /i "%RESPONSE%"=="x" goto Main_menu
if "%RESPONSE%"=="1" goto NVIDIA_1
if "%RESPONSE%"=="2" goto NVIDIA_2
if "%RESPONSE%"=="3" goto NVIDIA_3
if "%RESPONSE%"=="4" goto NVIDIA_4
if "%RESPONSE%"=="5" goto NVIDIA_5

echo Invalid choice / Choix invalide
pause
goto NVIDIA_menu

:NVIDIA_1
:: https://techpowerup.com/download/techpowerup-nvcleanstall/
curl -s -L -o "%Temp%\NVCleanstall.exe" "%URL_NVCLEANSTALL%"
"%Temp%\NVCleanstall.exe" && del "%Temp%\NVCleanstall.exe"
goto NVIDIA_menu

:NVIDIA_2
:: https://github.com/Orbmu2k/nvidiaProfileInspector
curl -s -L -o "%Temp%\NVIDIA Profile Inspector.exe" "%URL_NVIDIA_PROFILE_INSPECTOR%"
curl -s -L -o "%Temp%\NvidiaBaseProfile.nip" "%URL_NVIDIA_BASE_PROFILE%"
"%Temp%\NVIDIA Profile Inspector.exe" "%Temp%\NvidiaBaseProfile.nip" & del "%Temp%\NVIDIA Profile Inspector.exe" & del "%Temp%\NvidiaBaseProfile.nip"
goto NVIDIA_menu

:NVIDIA_3
start "" "shell:appsFolder\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj!NVIDIACorp.NVIDIAControlPanel"
echo ══════════════════════════════════════════════════════════════════════════════════════════
echo. NVIDIA Control Panel
echo. • Configure Surround, PhysX : choosing your primary graphics card.
echo. • Change Resolution : Use NVIDIA color settings
echo. • Adjust desktop size and position : No scaling ^| Perform scaling on : Display
echo. • System Information : Check if Resizable BAR is enabled (GPU compatible^)
pause
goto NVIDIA_menu

:NVIDIA_4
:: https://forums.guru3d.com/threads/windows-line-based-vs-message-signaled-based-interrupts-msi-tool.378044/
curl -s -L -o "%Temp%\MSI utility v3.exe" "%URL_MSI_UTIL%"
"%Temp%\MSI utility v3.exe" && del "%Temp%\MSI utility v3.exe"
goto NVIDIA_menu

:NVIDIA_5
echo Enable or disable Ansel ? ['E'nable/'D'isable/'N'othing]
call :AskChoice "Choose an option / Choisissez une option :" EDN

if /i "%RESPONSE%"=="e" goto Ansel_on
if /i "%RESPONSE%"=="d" goto Ansel_off
if /i "%RESPONSE%"=="n" goto NVIDIA_menu

:Ansel_on
call :AnselSet on
goto NVIDIA_menu

:Ansel_off
call :AnselSet off
goto NVIDIA_menu

:: --- MENU SERVICES --------------------------------------------------------------
:Services_menu
cls
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                                                              ║
echo ║                 ✦ Services Configuration ✦                   ║
echo ║                                                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo   [01] ⚡ All services except system features
echo   [02] ⚡ Restore all
echo   [03] ⚡ Open Services window (sort by Startup Type)
echo   [X]  ⚡ Back to menu / Retour
echo.
echo ════════════════════════════════════════════════════════════════
set /p RESPONSE="Choose an option / Choisissez une option :"

if /i "%RESPONSE%"=="q" goto Main_menu
if /i "%RESPONSE%"=="quit" goto Main_menu
if /i "%RESPONSE%"=="exit" goto Main_menu
if /i "%RESPONSE%"=="x" goto Main_menu
if "%RESPONSE%"=="1" goto Services_1
if "%RESPONSE%"=="2" goto Services_2
if "%RESPONSE%"=="3" goto Services_3

echo Invalid choice / Choix invalide
pause
goto Services_menu

:Services_1
echo [ INITIALIZATION ] Please wait... A copy of the services has been sent to the desktop
set "OUTPUT=%USERPROFILE%\Desktop\Backup Services.bat"
if not exist "%OUTPUT%" (
echo @echo off>"%OUTPUT%"
call :Ansi
powershell -NoLogo -NoProfile -Command ^
 "$s = Get-CimInstance Win32_Service | Where-Object { $_.Name -notmatch '_[A-Fa-f0-9]{4,}$' }; " ^
 "foreach ($x in $s) { " ^
 "  $mode = switch ($x.StartMode) { 'Auto'{'auto'} 'Manual'{'demand'} 'Disabled'{'disabled'} Default{'demand'} }; " ^
 "  Add-Content '%OUTPUT%' ('sc config \"' + $x.Name + '\" start= ' + $mode + ' >nul 2>&1') " ^
 "}"
call :Utf8
)
echo [ INITIALIZATION ] Please wait... The changes will take effect after a reboot
call :FetchRunDelete "%URL_DISABLE_SERVICES%" "Disable services.bat"
call :Done
goto Services_menu

:Services_2
echo [ INITIALIZATION ] Please wait... The changes will take effect after a reboot
call :FetchRunDelete "%URL_RESTORE_SERVICES%" "Restore services.bat"
call :Done
goto Services_menu

:Services_3
%SystemRoot%\system32\services.msc
goto Services_menu

:: --- MENU MISCELLANEOUS --------------------------------------------------------------
:Misc_menu
cls
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                                                              ║
echo ║                      ✦ Miscellaneous ✦                       ║
echo ║                                                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo   [01] ⚡ Remove Windows sounds permanently
echo   [02] ⚡ Restore classic context menu
echo   [03] ⚡ Remove AI shit
echo   [04] ⚡ Remove Microsoft Edge
echo   [05] ⚡ Uninstall pre-installed applications
echo   [06] ⚡ Steam shortcut without a browser on desktop
echo   [07] 🐺 LibreWolf
echo   [08] ⚡ Making Valorant Work
echo   [09] ⚡ DISM + scannow
echo   [10] ⚡ Run the full Disk Cleanup tool on all disks
echo   [11] ⚡ ASCII Art
echo   [X]  ⚡ Back to menu / Retour
echo.
echo ════════════════════════════════════════════════════════════════
set /p RESPONSE="Choose an option / Choisissez une option :"

if /i "%RESPONSE%"=="q" goto Main_menu
if /i "%RESPONSE%"=="quit" goto Main_menu
if /i "%RESPONSE%"=="exit" goto Main_menu
if /i "%RESPONSE%"=="x" goto Main_menu
if "%RESPONSE%"=="1" reg delete "HKCU\AppEvents\Schemes\Apps" /f >nul 2>&1 & goto Misc_menu
if "%RESPONSE%"=="2" goto Misc_2
if "%RESPONSE%"=="3" goto Misc_3
if "%RESPONSE%"=="4" goto Misc_4
if "%RESPONSE%"=="5" goto Misc_5
if "%RESPONSE%"=="6" goto Misc_6
if "%RESPONSE%"=="7" goto Misc_7
if "%RESPONSE%"=="8" goto Misc_8
if "%RESPONSE%"=="9" goto Misc_9
if "%RESPONSE%"=="10" goto Misc_10
if "%RESPONSE%"=="11" goto Misc_11

echo Invalid choice / Choix invalide
pause
goto Misc_menu

:Misc_2
echo Restore classic context menu in Windows 11 ? ['Y'es/'N'o/'R'eset]
call :AskChoice "Choose an option / Choisissez une option :" YNR

if /i "%RESPONSE%"=="y" reg add "HKCU\Software\Classes\CLSID\%CLSID_CLASSIC_CONTEXT_MENU%\InprocServer32" /ve /t REG_SZ /d "" /f >nul 2>&1 && goto Misc_menu
if /i "%RESPONSE%"=="r" reg delete "HKCU\Software\Classes\CLSID\%CLSID_CLASSIC_CONTEXT_MENU%" /f >nul 2>&1 && goto Misc_menu
if /i "%RESPONSE%"=="n" goto Misc_menu

:Misc_3
:: https://github.com/zoicware/RemoveWindowsAI
call :Ansi
powershell -Command "& ([scriptblock]::Create((irm 'https://kutt.it/RWAI')))"
call :Utf8
call :Done
goto Misc_menu

:Misc_4
:: https://github.com/he3als/EdgeRemover
call :Ansi
powershell -Command "iex(irm https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@main/get.ps1)"
call :Utf8
call :Done
goto Misc_menu

:Misc_5
%SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1
dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.MSPaint~~~~0.0.1.0 /Quiet /NoRestart >nul 2>&1
dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.SnippingTool~~~~0.0.1.0 /Quiet /NoRestart >nul 2>&1
dism /online /Remove-Capability /CapabilityName:Media.WindowsMediaPlayer~~~~0.0.12.0 /Quiet /NoRestart >nul 2>&1
call :Ansi
powershell -Command "Get-AppxPackage -AllUsers '*OutlookForWindows*' | Remove-AppxPackage -AllUsers -ErrorAction Continue"
call :Utf8
goto Misc_menu

:Misc_6
call :Ansi
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%USERPROFILE%\Desktop\Steam - No browser.lnk'); $s.TargetPath='C:\Program Files (x86)\Steam\Steam.exe'; $s.Arguments='silent -noverifyfiles -no-browser +open steam://open/minigameslist'; $s.Save()"
call :Utf8
call :Done
goto Misc_menu

:Misc_7
start "" "https://librewolf.net/installation/windows/"
curl -s -L -o "%USERPROFILE%\Desktop\LibreWolf Register.bat" "%URL_LIBREWOLF_REGISTER%"
echo. Settings for normal use
echo. • Disable :
echo.    delete cookie when closed
echo.    Enable ResistFingerprinting
echo.    Support LibreWolf
echo.    Enforce OCSP hard-fail (?)
echo. • Enable :
echo.    Fix major site issues (recommended)
echo.    Fix minor site issues
echo.    Open previous windows and tabs (?)
echo.    Enable WebGL
echo.
echo. Register LibreWolf Portable :
echo. Move the LibreWolf Register.bat file from your desktop to the folder containing LibreWolf-Portable.exe, then run it.
pause
goto Misc_menu

:Misc_8
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f >nul 2>&1
goto Misc_menu

:Misc_9
dism /Online /Cleanup-Image /RestoreHealth && sfc /scannow
pause
goto Misc_menu

:Misc_10
curl -s -L -o "%Temp%\sageset.reg" "%URL_SAGESET_REG%"
reg import "%Temp%\sageset.reg" >nul 2>&1 & del "%Temp%\sageset.reg"
cleanmgr.exe /dc /sagerun:1
goto Misc_menu

:Misc_11
cls
echo. ⠀⠀⠀⠀⠀⠀⠀⠄⣀⠢⢀⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⡔⢀⠂⡜⢭⢻⣍⢯⡻⣝⣿⣿⡿⣟⠂
echo. ⠀⠀⠀⠀⠀⠀⠀⠄⠀⣦⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡔⡀⢂⠜⣪⢗⡾⣶⡽⣾⣟⣯⠛⠀⠀
echo. ⠀⠀⠀⠀⠀⠄⠀⠠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣔⠨⡸⡝⣯⣳⢏⣿⠳⠉⠀⢠⣬⡶
echo. ⠠⣓⢤⣂⣄⣀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠁⣞⡱⣝⠎⠀⢀⠠⣥⠳⡞⡹
echo. ⠀⡄⢉⠲⢿⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡔⣧⡽⠋⠀⣰⣶⣻⣶⣿⢾⣷
echo. ⢤⡈⠉⠲⢤⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⢀⡴⢏⡳⢮⡿⣽⣞⠻⡜
echo. ⠒⣭⠳⢶⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡙⠮⣜⣯⡽⣳⢌⡓⠈
echo. ⡸⣰⢋⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣻⢿⣻⣿⡽⣗⠋⠄⠀
echo. ⠣⢇⢟⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢟⡿⢣⣟⡻⠘⠀⠀⠀
echo. ⠱⡊⠤⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠨⠗⠋⣁⣤⠖⠊⢁⣀
echo. ⠀⠁⠂⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⣿⡂⠹⣿⣿⣿⣿⣿⠙⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⠒⢋⣉⡤⣔⣮⣽⣾
echo. ⢢⠣⣌⢼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⢰⣿⡅⠀⣿⣿⣿⣿⣿⠀⠸⢿⣹⣿⣿⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣻⣿⣿⣿⣿⣿⣿⣿
echo. ⢃⡉⠠⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣼⢹⠀⠀⠀⠀⣾⠿⡇⠀⣿⣿⣿⣿⡏⠀⠀⣞⣧⣻⠟⢿⣿⣿⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣧⠱⣌⣳⣽⣻⣿⣿⣻
echo. ⠀⢒⡕⣺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⡇⠈⣇⠀⠀⠀⠈⡆⢳⠀⠇⡟⠋⠉⠀⠀⠀⠃⢙⣠⣤⣤⣼⣯⣚⣟⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠌⠑⠌⢳⠛⡛⠏⠛⠉
echo. ⡘⢷⣌⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⢻⣀⣧⣤⣽⣦⣤⣄⠀⠰⡀⠃⠀⠀⠀⠀⠀⠀⡴⠟⠛⣉⣉⡉⠉⠈⠉⠉⠉⠋⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢈⠈⠈⠁⠛⠀⠀⠀⣒
echo. ⠉⢣⡛⣿⣿⣿⣿⣿⣿⣿⣿⣿⡧⠖⠛⠉⠉⠉⠀⠀⠐⠒⢢⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⣠⣲⣾⣿⢿⣷⢶⡄⠀⠀⣽⣿⣿⣿⣿⡿⠟⣿⣿⣿⣿⣿⠛⢁⣤⡶⠿⠛⠋
echo. ⠀⠀⠌⢽⣿⣿⣿⣿⣿⣿⣿⣿⡷⠀⠀⠀⣠⣶⣶⣿⣟⣿⣶⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⢿⣿⣿⣿⣿⠀⣿⡀⠀⢻⣬⣙⡻⡿⣡⣾⣿⣿⡍⠈⣀⣤⣬⣤⣶⣲⣶⣿
echo. ⠀⢈⠐⡀⢻⣫⢿⣿⣿⣿⣿⠘⢧⠁⠀⣻⡏⠸⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⢄⣉⣛⣋⣡⡴⠃⠀⠀⣿⣿⣿⠟⣠⡛⢿⣿⣿⣷⣲⣽⣿⣿⣷⣾⣷⣿⣿
echo. ⠀⠀⢀⠐⡀⢃⡈⣿⢿⣿⣿⣟⡆⠀⠀⠉⠿⣦⣈⣉⣉⠤⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⣡⣶⣿⣿⣾⣿⣿⣿⢿⡿⣿⣿⡿⠿⠛⣋⣡
echo. ⠠⠐⡀⢢⣶⣿⢧⠻⣯⣿⣯⡛⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠘⠐⠂⡁⠤⠔⢂⣉⣤⡴
echo. ⣀⠥⠌⣳⢯⣟⣮⣗⣾⣟⣿⣿⣦⣭⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠂⣈⠥⡔⡤⣍⠣⣝⢾⡹
echo. ⠀⠀⠀⠠⠈⠉⠈⠉⠉⠉⣨⣿⣿⣿⣯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⡟⠻⢞⣿⣝⣳⢎⢳⢻⡮⣕
echo. ⠀⠀⢀⠀⡀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡗⢠⠘⡼⣽⣛⡞⠦⣧⢻⣽
echo. ⠀⢈⠀⡀⡀⢤⠞⡉⢭⣹⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⣍⣣⢾⣵⣯⣷⣽⣦⣑⣯⢿
echo. ⠀⠂⣴⣾⡟⣧⠊⡔⢢⠛⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠒⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⣯⢹⣽⢻⣿⣿⣿⣿⣿⣿⣿⣿
echo. ⣶⣟⠳⣏⡿⣎⠳⣈⡜⣺⣿⠿⢿⣝⡿⣫⢟⣽⣿⣿⠻⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠔⠛⣿⠿⣟⢩⢾⣿⣿⣿⣿⣇⠾⣜⡧⣯⣟⣿⣿⣿⣿⣿⣿⣿⣿
echo. ⠋⢀⢱⣫⣟⢾⡹⢴⡸⣵⡏⣂⢾⡿⣽⣹⣟⣾⣿⡟⢠⡇⠀⣹⠂⠄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⣣⢟⡿⣾⣿⣿⣿⣿⢌⠫⢝⡻⣵⢻⡟⣿⢿⣿⢿⡿⣿⠿
echo. ⠀⢢⠞⣴⢯⢯⣝⣦⢳⡝⡶⣭⣿⣽⣳⣟⡾⣽⡟⢀⡟⠀⢀⡿⠀⠀⠀⠁⠠⠤⠀⠀⠀⠤⠐⠀⠀⠀⠀⠀⠀⠀⢸⡗⠈⠭⣿⣿⣿⣿⡿⢌⠣⡀⡐⢈⠃⠚⠦⣉⠂⠣⠜⡄⢋
echo. ⣜⣷⢻⡜⣯⣾⡞⣥⣓⢾⡽⢎⡷⢯⡷⣯⢟⣽⠃⣸⠁⠀⡼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⢹⣿⣿⣿⣿⢃⡮⡑⢰⢠⣂⡜⣦⡴⣱⣎⣴⣩⡜⣦
echo. ⣿⣯⢷⡻⣏⣷⣟⠶⣙⠮⡙⢪⠜⣯⢽⣯⣿⠃⠄⢃⣠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣾⣿⣿⣿⡇⠢⢡⡙⢦⡓⡼⣽⣾⣿⣿⣿⣿⣷⣿⣿
echo. ⣿⡹⢇⡳⡹⣞⠘⡈⢅⠢⢁⠂⡘⠤⣋⣶⣡⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠰⡁⢆⠘⣡⠻⣽⣳⣿⣿⣿⣿⢿⣿⣿⣿
echo. ⢣⠝⡢⢍⠱⢈⣂⣌⡤⠦⠶⠶⠞⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⠛⠷⣭⣂⠌⢠⠓⡴⣻⣿⣿⣿⣿⣿⣿⣯⣿
echo. ⣇⢾⡱⠞⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠉⠛⠳⠿⣶⣽⣿⣿⣿⣿⣿⣿⣿⣿
pause
goto Misc_menu

:: --- MENU CHECK --------------------------------------------------------------
:Check_menu
cls
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                                                              ║
echo ║                 ✦ Check Windows Settings ✦                   ║
echo ║                                                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo   [01] ⚡ Adjust display scale
echo   [02] ⚡ → Disable unwanted startup programs
echo   [03] ⚡ → Check Update
echo   [04] ⚡ → Sound
echo   [05] ⚡ Check Windows Activation
echo   [06] ⚡ Language Time Region
echo   [07] ⚡ Rename this PC
echo   [08] ⚡ Cursor appearance
echo   [09] ⚡ Device Manager
echo   [10] ⚡ Networks Connections
echo   [11] ⚡ Power Options
echo   [12] ⚡ Disk Management
echo   [13] ⚡ Environment Variables
echo   [14] ⚡ Services
echo   [15] ⚡ Turn Windows features on or off
echo   [16] ⚡ Event Viewer
echo   [17] ⚡ Show IP / DNS
echo   [18] ⚡ MSInfo32
echo   [19] ⚡ Optimize Drives
echo   [X]  ⚡ Back to menu / Retour
echo.
echo ════════════════════════════════════════════════════════════════
set /p RESPONSE="Choose an option / Choisissez une option :"

if /i "%RESPONSE%"=="q" goto Main_menu
if /i "%RESPONSE%"=="quit" goto Main_menu
if /i "%RESPONSE%"=="exit" goto Main_menu
if /i "%RESPONSE%"=="x" goto Main_menu
if "%RESPONSE%"=="1" start ms-settings:display & goto Check_menu
if "%RESPONSE%"=="2" start ms-settings:startupapps & goto Check_menu
if "%RESPONSE%"=="3" start ms-settings:windowsupdate & goto Check_menu
if "%RESPONSE%"=="4" goto Check_4
if "%RESPONSE%"=="5" start ms-settings:activation & goto Check_menu
if "%RESPONSE%"=="6" start ms-settings:regionlanguage & goto Check_menu
if "%RESPONSE%"=="7" start ms-settings:about & goto Check_menu
if "%RESPONSE%"=="8" start ms-settings:mousetouchpad & goto Check_menu
if "%RESPONSE%"=="9" start control hdwwiz.cpl & goto Check_menu
if "%RESPONSE%"=="10" %SystemRoot%\System32\ncpa.cpl & goto Check_menu
if "%RESPONSE%"=="11" %SystemRoot%\System32\powercfg.cpl & goto Check_menu
if "%RESPONSE%"=="12" %SystemRoot%\System32\diskmgmt.msc & goto Check_menu
if "%RESPONSE%"=="13" %SystemRoot%\System32\rundll32.exe sysdm.cpl,EditEnvironmentVariables & goto Check_menu
if "%RESPONSE%"=="14" %SystemRoot%\System32\services.msc & goto Check_menu
if "%RESPONSE%"=="15" optionalfeatures & goto Check_menu
if "%RESPONSE%"=="16" %SystemRoot%\system32\eventvwr.msc /s & goto Check_menu
if "%RESPONSE%"=="17" goto Check_15
if "%RESPONSE%"=="18" %SystemRoot%\System32\msinfo32.exe & goto Check_menu
if "%RESPONSE%"=="19" %SystemRoot%\System32\dfrgui.exe & goto Check_menu

echo Invalid choice / Choix invalide
pause
goto Check_menu

:Check_4
start control mmsys.cpl
echo. • Disable devices that are not in use.
echo. • Right click → Properties on all devices :
echo.    Levels : set the volume to 100.
echo.    Enhancement : check Disable all enhancements.
echo.    Advanced : uncheck Allow applications to take exclusive control of this device.
pause
goto Check_menu

:Check_15
set "ip="
set "dns="
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /i "IPv4"') do if not defined ip set ip=%%i
for /f "tokens=2 delims=:" %%i in ('nslookup 127.0.0.1 ^| findstr /i "Address"') do if not defined dns set dns=%%i
echo IPv4: %ip: =%
echo DNS : %dns: =%
pause
goto Check_menu

:: --- SOUS-ROUTINES ---------------------------------------------------------

:: Prompts until a valid single-character answer is given (one of %2).
:: Usage : call :AskChoice "message :" YNR    -> result in %RESPONSE%
:AskChoice
setlocal EnableDelayedExpansion
set "prompt=%~1"
set "valid=%~2"
:AskChoice_Loop
set "RESPONSE="
set /p "RESPONSE=%prompt%"
if not defined RESPONSE goto AskChoice_Retry
set "matched="
for /l %%i in (0,1,50) do (
    if not defined matched (
        set "c=!valid:~%%i,1!"
        if not "!c!"=="" if /i "!RESPONSE!"=="!c!" set "matched=1"
    )
)
if defined matched goto AskChoice_Done
:AskChoice_Retry
echo Invalid choice / Choix invalide
pause
goto AskChoice_Loop
:AskChoice_Done
endlocal & set "RESPONSE=%RESPONSE%"
goto :eof

:: Message de confirmation standard affiché après une opération.
:Done
echo [OK] Operation completed / Opération terminée.
pause
goto :eof

:: Bascule de page de code : plusieurs outils externes (PowerShell, etc.)
:: s'affichent mal sous la page UTF-8 (65001) utilisée par ce script.
:Ansi
chcp 437>nul
goto :eof

:Utf8
chcp 65001>nul
goto :eof

:: Télécharge un fichier dans %Temp%, l'exécute, puis le supprime.
:: Usage : call :FetchRunDelete "<url>" "<nom local>"
:FetchRunDelete
curl -s -L -o "%Temp%\%~2" "%~1"
if not exist "%Temp%\%~2" (
    echo [!] Download failed / Échec du téléchargement : %~1
    pause
    goto :eof
)
call "%Temp%\%~2"
del "%Temp%\%~2" >nul 2>&1
goto :eof

:: Télécharge un fichier dans un dossier donné sans l'exécuter ; affiche
:: une erreur et renvoie errorlevel 1 si le téléchargement échoue.
:: Usage : call :FetchOnly "<url>" "<nom local>" "<dossier>"
:FetchOnly
curl -s -L -o "%~3\%~2" "%~1"
if not exist "%~3\%~2" (
    echo [!] Download failed / Échec du téléchargement : %~1
    pause
    exit /b 1
)
goto :eof

:: Active/désactive Ansel sur tous les emplacements connus du pilote NVIDIA.
:: Usage : call :AnselSet on|off
:AnselSet
setlocal
set "mode=%~1"
set "ANSEL="
C:
cd %SystemRoot%\System32\DriverStore\FileRepository\nv_dispi.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe %mode%
cd %SystemRoot%\System32\DriverStore\FileRepository\nv_dispig.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe %mode%
cd %SystemRoot%\System32\DriverStore\FileRepository\nvmdi.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe %mode%
cd %SystemRoot%\System32\DriverStore\FileRepository\nvami.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe %mode%
cd "%ProgramFiles%\NVIDIA Corporation\Ansel\Tools" 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe %mode%
cd "%ProgramFiles%\NVIDIA Corporation\Ansel" 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe %mode%
for /f %%i in ('NvCameraEnable.exe') do set ANSEL=%%i
if "%ANSEL%"=="0" (
    echo Ansel Disabled
) else (
    echo Ansel Enabled
)
endlocal
pause
goto :eof