@echo off
chcp 65001 >nul
title lain.bat & Color 03
mode con cols=90 lines=35
echo [ INITIALIZATION ]
echo ══════════════════════════════════════════════════════════════════════════════════════════
icacls "%SystemRoot%\System32\config\system" >nul 2>&1
if errorlevel 1 (
    echo [!] ACCÈS ROOT REQUIS / ROOT ACCESS REQUIRED.
    pause
    exit /b
) else (
    echo [OK] ACCÈS ROOT VALIDÉ / ROOT ACCESS GRANTED.
)
ping 1.1.1.1 -n 1 >nul 2>&1
if errorlevel 1 (
    echo [!] SIGNAL RÉSEAU INEXISTANT / NO NETWORK SIGNAL.
    pause
    exit /b
) else (
    echo [OK] SIGNAL RÉSEAU ACTIF / NETWORK LINK ESTABLISHED.
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
echo Utilisation à vos propres risques, sans aucune garantie.
echo Sauvegardez vos fichiers et créez un point de restauration au préalable.
echo Use at your own risk, without any warranty.
echo Back up your files and create a restore point beforehand.
echo ══════════════════════════════════════════════════════════════════════════════════════════
echo Bios optimization :
echo  ► ENABLE : Re-Size BAR Support/4G Decoding, Precision Boost Overdrive, EXPO/XMP profile,
echo L1/L2 Prefetcher, CPPC/CPPC Preferred
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
echo   [03] ⚡ System Settings / Configuration globale
echo   [04] ⚡ Network Settings / Paramètres réseau (not safe)
echo   [05] ⚡ Power Plan (Desktop Only) / Plan d’alimentation (PC fixe uniquement)
echo   [06] ⚡ Install Runtime ^& Frameworks / Installer les runtimes et frameworks
echo   [07] ⚡ Install Timer Resolution Service / Installer le service Timer Resolution
echo   [08] ⚡ Disable Unnecessary Services / Désactiver les services inutiles
echo   [09] ⚡ Disable SmartScreen ^& Block Edge / Désactiver SmartScreen et bloquer Edge
echo   [10] ⚡ Disable Bluetooth drivers and services
echo   [11] ⚡ Block Tracking ^& Spyware IPs / Bloquer les IPs d’espionnage et de suivi
echo   [12] ⚡ Disable Windows Update / Désactiver Windows Update
echo   [13] ⚡ Miscellaneous / Divers
echo   [14] ⚡ Review Windows Settings / Vérifier les paramètres Windows
echo.
set /p choix="Choisissez une option / Choose an option :"

if /i "%choix%"=="q" exit /b
if /i "%choix%"=="quit" exit /b
if /i "%choix%"=="exit" exit /b
if "%choix%"=="1" goto Option1
if "%choix%"=="2" goto NVIDIA_menu
if "%choix%"=="3" goto Option3
if "%choix%"=="4" goto Option4
if "%choix%"=="5" goto Option5
if "%choix%"=="6" goto Option6
if "%choix%"=="7" goto Option7
if "%choix%"=="8" goto Services_menu
if "%choix%"=="9" goto Option9
if "%choix%"=="10" goto Option10
if "%choix%"=="11" goto Option11
if "%choix%"=="12" goto Option12
if "%choix%"=="13" goto Misc_menu
if "%choix%"=="14" goto Check_menu

echo Choix invalide / Invalid choice
pause
goto Main_menu

:: --- ACTIONS MENU PRINCIPAL ---------------------------------------------------
:Option1
"%SystemRoot%\System32\SystemPropertiesProtection.exe"
goto Main_menu

:Option3
echo.Configuration et optimisation globale de Windows ?
set /p choix="Overall Windows configuration and optimization ? ['Y'es/'N'o/'V'iew modifications] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto config1
if /i "%choix%"=="v" goto config2

echo Choix invalide / Invalid choice
pause
goto Option3
:config1
echo [ INITIALIZATION ] Please wait... A copy of the registry has been sent to the desktop
reg export HKLM %Temp%\Temp_HKLM.reg >nul 2>&1 & reg export HKCU %Temp%\Temp_HKCU.reg >nul 2>&1 & reg export HKCR %Temp%\Temp_HKCR.reg >nul 2>&1
copy /b %Temp%\Temp_HKLM.reg + %Temp%\Temp_HKCU.reg + %Temp%\Temp_HKCR.reg %USERPROFILE%\Desktop\Backup.reg >nul 2>&1
del %Temp%\Temp_HKLM.reg & del %Temp%\Temp_HKCU.reg & del %Temp%\Temp_HKCR.reg
chcp 437>nul
bcdedit /set quietboot Yes >nul 2>&1
bcdedit /set bootuxdisabled On >nul 2>&1
bcdedit /set disabledynamictick Yes >nul 2>&1
bcdedit /set useplatformtick Yes >nul 2>&1
bcdedit /set tscsyncpolicy enhanced >nul 2>&1
bcdedit /set uselegacyapicmode No >nul 2>&1
bcdedit /set usephysicaldestination No >nul 2>&1
bcdedit /deletevalue useplatformclock >nul 2>&1
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
curl -s -L -o "%Temp%\Tweaks.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/Tweaks.reg"
reg import "%Temp%\Tweaks.reg" >nul 2>&1 & del "%Temp%\Tweaks.reg"
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
powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force"
powershell -Command "Get-PnpDevice | Where-Object FriendlyName -like 'Remote Desktop Device Redirector Bus*' | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Get-PnpDevice | Where-Object { $_.FriendlyName -like 'Composite Bus Enumerator*' -or $_.FriendlyName -like 'High precision event timer*' -or $_.FriendlyName -like 'UMBus Root Bus Enumerator*' -or $_.FriendlyName -like 'Numeric data processor*' -or $_.FriendlyName -like 'SM Bus Controller*' -or $_.FriendlyName -like 'Microsoft GS Wavetable Synth*' -or $_.FriendlyName -like 'Microsoft Virtual Drive Enumerator*' -or $_.FriendlyName -like 'System speaker*' } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put() } > $null"
::powershell -Command "Expand-Archive -Path '%Temp%\User Account Pictures.zip' -DestinationPath '%ProgramData%\Microsoft\User Account Pictures' -Force"
chcp 65001>nul
::del "%Temp%\User Account Pictures.zip"
wevtutil cl Application >nul 2>&1 & wevtutil cl Security >nul 2>&1 & wevtutil cl Setup >nul 2>&1 & wevtutil cl System >nul 2>&1
pause
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
echo.Configuration et optimisation du réseau ? (non recommandé)
set /p choix="Network configuration and optimization ? (not recommended, may break the network) ['Y'es/'N'o] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto Network

echo Choix invalide / Invalid choice
pause
goto Option4

:Network
echo [ INITIALIZATION ] Please wait... Keep your hands up
curl -s -L -o "%Temp%\Network.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/Network.bat"
call "%Temp%\Network.bat" & del "%Temp%\Network.bat"
goto Main_menu

:Option5
echo. Optimiser et activer le plan d'alimentation Ultimate Performance ?
echo. Optimize and activate the Ultimate Performance power plan ? 
set /p choix="['Y'es/'N'o/'K'eep Balanced/'R'eset] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto Power_1
if /i "%choix%"=="k" goto Power_2
if /i "%choix%"=="r" goto Power_3

echo Choix invalide / Invalid choice
pause
goto Option5
:Power_1
curl -s -L -o "%Temp%\PowerPlan.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/PowerPlan.bat"
call "%Temp%\PowerPlan.bat" & del "%Temp%\PowerPlan.bat"
powercfg /list
pause
goto Main_menu

:Power_2
powercfg -restoredefaultschemes >nul 2>&1
powercfg -duplicatescheme 381b4222-f694-41f0-9685-ff5bb260df2e 77777777-7777-7777-7777-777777777777 >nul 2>&1
powercfg -setactive "77777777-7777-7777-7777-777777777777" >nul 2>&1
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e >nul 2>&1
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a >nul 2>&1
powercfg -delete e9a42b02-d5df-448d-aa00-03f14749eb61 >nul 2>&1
powercfg /hibernate on >nul 2>&1
powercfg /list
pause
goto Main_menu

:Power_3
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
md "%Temp%\Bonjour" >nul 2>&1
curl -s -L -o "%Temp%\Bonjour\DirectX_Redist_Repack_x86_x64.zip" "https://github.com/stdin82/htfx/releases/download/v0.0.4/DirectX_Redist_Repack_x86_x64_v3.zip"
tar -xf "%Temp%\Bonjour\DirectX_Redist_Repack_x86_x64.zip" -C "%Temp%\Bonjour"
curl -s -L -o "%Temp%\Bonjour\dotnet-install.ps1" "https://dot.net/v1/dotnet-install.ps1"
curl -s -L -o "%Temp%\Bonjour\vcredist2005_x86.exe" "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE"
curl -s -L -o "%Temp%\Bonjour\vcredist2005_x64.exe" "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE"
curl -s -L -o "%Temp%\Bonjour\vcredist2008_x86.exe" "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe"
curl -s -L -o "%Temp%\Bonjour\vcredist2008_x64.exe" "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe"
curl -s -L -o "%Temp%\Bonjour\vcredist2010_x86.exe" "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe"
curl -s -L -o "%Temp%\Bonjour\vcredist2010_x64.exe" "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"
curl -s -L -o "%Temp%\Bonjour\vcredist2012_x86.exe" "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"
curl -s -L -o "%Temp%\Bonjour\vcredist2012_x64.exe" "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"
curl -s -L -o "%Temp%\Bonjour\vcredist2013_x86.exe" "https://aka.ms/highdpimfc2013x86enu"
curl -s -L -o "%Temp%\Bonjour\vcredist2013_x64.exe" "https://aka.ms/highdpimfc2013x64enu"
curl -s -L -o "%Temp%\Bonjour\vcredist2022_x86.exe" "https://aka.ms/vs/17/release/vc_redist.x86.exe"
curl -s -L -o "%Temp%\Bonjour\vcredist2022_x64.exe" "https://aka.ms/vs/17/release/vc_redist.x64.exe"
start /wait "" "%Temp%\Bonjour\vcredist2005_x86.exe" /q
start /wait "" "%Temp%\Bonjour\vcredist2005_x64.exe" /q
start /wait "" "%Temp%\Bonjour\vcredist2008_x86.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2008_x64.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2010_x86.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2010_x64.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2012_x86.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2012_x64.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2013_x86.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2013_x64.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2022_x86.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\vcredist2022_x64.exe" /quiet /norestart
start /wait "" "%Temp%\Bonjour\DirectX_Redist_Repack_x86_x64.exe" /y
rd "%ProgramFiles%\dotnet" /s /q >nul 2>&1
rd "%LocalAppData%\Microsoft\dotnet" /s /q >nul 2>&1
chcp 437>nul
powershell -ExecutionPolicy Bypass -File "%Temp%\Bonjour\dotnet-install.ps1" -Runtime dotnet -InstallDir "C:\Program Files\dotnet" >nul 2>&1
chcp 65001>nul
setx PATH "%PATH%;C:\Program Files\dotnet\" >nul
del "%USERPROFILE%\dotnet-install.ps1" /f /q >nul 2>&1
rd "%Temp%\Bonjour" /s /q >nul 2>&1
goto Main_menu

:Option7
echo.Installer le service de résolution des délais ?
set /p choix="Install Timer Resolution Service ? ['Y'es/'N'o/'R'emove Service] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto str1
if /i "%choix%"=="r" goto str2

echo Choix invalide / Invalid choice
pause
goto Option7
:str1
curl -s -L -o "%SystemRoot%\SetTimerResolutionService.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/SetTimerResolutionService.exe"
sc create "STR" binPath= "%SystemRoot%\SetTimerResolutionService.exe" >nul 2>&1
sc config "STR" start= auto >nul 2>&1
sc description "STR" "Timer Resolution lets you change your default Windows timer's resolution in a matter of seconds and consequently improves the FPS for the games you are playing." >nul 2>&1
net start "STR" >nul 2>&1
sc query STR | findstr STATE
pause
goto Main_menu

:str2
net stop "STR" /y >nul 2>&1 & sc delete "STR" >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\STR" /f >nul 2>&1
sc query STR | findstr STATE
pause
goto Main_menu

:Option9
echo. Désactiver SmartScreen et bloquer Edge ?
echo. Disable SmartScreen and block Edge ?
set /p choix="['Y'es/'N'o/'R'eset] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto disablesce1
if /i "%choix%"=="r" goto disablesce2

echo Choix invalide / Invalid choice
pause
goto Option9
:disablesce1
takeown /s %computername% /u %username% /f "%SystemRoot%\System32\smartscreen.exe" >nul 2>&1
icacls "%SystemRoot%\System32\smartscreen.exe" /grant:r %username%:F
taskkill /im smartscreen.exe /f
ren "%SystemRoot%\System32\smartscreen.exe" "smartscreen.bak"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "Edge" /t REG_SZ /d "msedge.exe" /f >nul 2>&1
goto Main_menu

:disablesce2
takeown /s %computername% /u %username% /f "%SystemRoot%\System32\smartscreen.bak" >nul 2>&1
ren "%SystemRoot%\System32\smartscreen.bak" "smartscreen.exe"
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "Edge" /f
goto Main_menu

:Option10
echo. Désactiver les drivers et services Bluetooth ?
echo. Disable Bluetooth drivers and services ?
set /p choix="['Y'es/'N'o/'R'eset] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto disablebt1
if /i "%choix%"=="r" goto disablebt2

echo Choix invalide / Invalid choice
pause
goto Option10
:disablebt1
net stop "bthserv" /y >nul 2>&1 & sc config "bthserv" start= Disabled >nul 2>&1
net stop "BTAGService" /y >nul 2>&1 & sc config "BTAGService" start= Disabled >nul 2>&1
chcp 437>nul
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
powershell -Command "& { Get-PnpDevice -Class 'Bluetooth' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
chcp 65001>nul
goto Main_menu

:disablebt2
net start "bthserv" >nul 2>&1 & sc config "bthserv" start= Demand >nul 2>&1
net start "BTAGService" >nul 2>&1 & sc config "BTAGService" start= Demand >nul 2>&1
chcp 437>nul
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
powershell -Command "& { Get-PnpDevice -Class 'Bluetooth' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
chcp 65001>nul
goto Main_menu

:Option11
echo. Bloquer l'espionnage et le suivi des IPs (via WindowsSpyBlocker et le fichier host) ? Vous ne recevrez plus les majs Windows
echo. Block spying and tracking IPs (via WindowsSpyBlocker and host file) ? You will no longer receive Windows updates
set /p choix="['Y'es/'N'o/'R'eset/'C'lean all] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto disablespy1
if /i "%choix%"=="r" goto disablespy2
if /i "%choix%"=="c" goto disablespy3

echo Choix invalide / Invalid choice
pause
goto Option11
:disablespy1
curl -s -L -o "%Temp%\CustomHostsAdd.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/CustomHostsAdd.bat"
call "%Temp%\CustomHostsAdd.bat" & del "%Temp%\CustomHostsAdd.bat"
curl -s -L -o "%Temp%\FirewallRulesAdd.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/FirewallRulesAdd.bat"
call "%Temp%\FirewallRulesAdd.bat" & del "%Temp%\FirewallRulesAdd.bat"
goto Main_menu

:disablespy2
curl -s -L -o "%Temp%\CustomHostsRemove.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/CustomHostsRemove.bat"
call "%Temp%\CustomHostsRemove.bat" & del "%Temp%\CustomHostsRemove.bat"
curl -s -L -o "%Temp%\FirewallRulesRemove.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/FirewallRulesRemove.bat"
call "%Temp%\FirewallRulesRemove.bat" & del "%Temp%\FirewallRulesRemove.bat"
goto Main_menu

:disablespy3
netsh advfirewall reset
del %SystemRoot%\system32\drivers\etc\hosts
(
echo # localhost name resolution is handled within DNS itself.
echo # 127.0.0.1       localhost
echo # ::1             localhost
) > %SystemRoot%\System32\drivers\etc\hosts
goto Main_menu

:Option12
echo. Désactiver Windows Update ?
echo. Disable Windows Update ?
set /p choix="['Y'es/'N'o/'R'eset] :"

if /i "%choix%"=="n" goto Main_menu
if /i "%choix%"=="y" goto disablewu1
if /i "%choix%"=="r" goto disablewu2

echo Choix invalide / Invalid choice
pause
goto Option11
:disablewu1
net stop "UsoSvc" /y >nul 2>&1 & sc config "UsoSvc" start= Disabled >nul 2>&1
net stop "wuauserv" /y >nul 2>&1 & sc config "wuauserv" start= Disabled >nul 2>&1
net stop "WaaSMedicSvc" /y >nul 2>&1 & sc config "WaaSMedicSvc" start= Disabled >nul 2>&1
takeown /F "%SystemRoot%\System32\wuaueng.dll" >nul 2>&1
icacls "%SystemRoot%\System32\wuaueng.dll" /grant:r %username%:F >nul 2>&1
ren "%SystemRoot%\System32\wuaueng.dll" "wuaueng.bak"
takeown /F "%SystemRoot%\System32\WaasMedicSvc.dll" >nul 2>&1
icacls "%SystemRoot%\System32\WaasMedicSvc.dll" /grant:r %username%:F >nul 2>&1
ren "%SystemRoot%\System32\WaasMedicSvc.dll" "WaasMedicSvc.bak"
goto Main_menu

:disablewu2
takeown /F "%SystemRoot%\System32\wuaueng.bak" >nul 2>&1
ren "%SystemRoot%\System32\wuaueng.bak" "wuaueng.dll"
takeown /F "%SystemRoot%\System32\WaasMedicSvc.bak" >nul 2>&1
ren "%SystemRoot%\System32\WaasMedicSvc.bak" "WaasMedicSvc.dll"
net stop "UsoSvc" /y >nul 2>&1 & sc config "UsoSvc" start= Demand >nul 2>&1
net start "wuauserv" & sc config "wuauserv" start= Demand
net start "WaaSMedicSvc" & sc config "WaaSMedicSvc" start= Demand
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
set /p choix="Choisissez une option / Choose an option :"

if /i "%choix%"=="q" goto Main_menu
if /i "%choix%"=="quit" goto Main_menu
if /i "%choix%"=="exit" goto Main_menu
if /i "%choix%"=="x" goto Main_menu
if "%choix%"=="1" goto NVIDIA_1
if "%choix%"=="2" goto NVIDIA_2
if "%choix%"=="3" goto NVIDIA_3
if "%choix%"=="4" goto NVIDIA_4
if "%choix%"=="5" goto NVIDIA_5

echo Choix invalide / Invalid choice
pause
goto NVIDIA_menu

:NVIDIA_1
:: https://techpowerup.com/download/techpowerup-nvcleanstall/
curl -s -L -o "%Temp%\NVCleanstall.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/NVCleanstall.exe"
"%Temp%\NVCleanstall.exe" && del "%Temp%\NVCleanstall.exe"
goto NVIDIA_menu

:NVIDIA_2
:: https://github.com/Orbmu2k/nvidiaProfileInspector
curl -s -L -o "%Temp%\NVIDIA Profile Inspector.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/nvidiaProfileInspector.exe"
curl -s -L -o "%Temp%\NvidiaBaseProfile.nip" "https://github.com/Nyaldee/lain.bat/raw/main/call/NvidiaBaseProfile.nip"
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
curl -s -L -o "%Temp%\MSI utility v3.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/MSI_util_v3.exe"
"%Temp%\MSI utility v3.exe" && del "%Temp%\MSI utility v3.exe"
goto NVIDIA_menu

:NVIDIA_5
echo Enable or disable Ansel ? ['E'nable/'D'isable/'N'othing]
set /p choix="Choisissez une option / Choose an option :"

if /i "%choix%"=="e" goto Ansel_on
if /i "%choix%"=="d" goto Ansel_off
if /i "%choix%"=="n" goto NVIDIA_menu

echo Choix invalide / Invalid choice
pause
goto NVIDIA_5

:Ansel_on
C:
cd %SystemRoot%\System32\DriverStore\FileRepository\nv_dispi.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe on
cd %SystemRoot%\System32\DriverStore\FileRepository\nv_dispig.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe on
cd %SystemRoot%\System32\DriverStore\FileRepository\nvmdi.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe on
cd %SystemRoot%\System32\DriverStore\FileRepository\nvami.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe on
cd "%ProgramFiles%\NVIDIA Corporation\Ansel\Tools" 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe on
cd "%ProgramFiles%\NVIDIA Corporation\Ansel" 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe on
for /f %%i in ('NvCameraEnable.exe') do set ANSEL=%%i
if "%ANSEL%"=="0" (
    echo Ansel Disabled
) else (
    echo Ansel Enabled
)
pause
goto NVIDIA_menu

:Ansel_off
C:
cd %SystemRoot%\System32\DriverStore\FileRepository\nv_dispi.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe off
cd %SystemRoot%\System32\DriverStore\FileRepository\nv_dispig.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe off
cd %SystemRoot%\System32\DriverStore\FileRepository\nvmdi.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe off
cd %SystemRoot%\System32\DriverStore\FileRepository\nvami.inf* 2>nul
cd NvCamera 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe off
cd "%ProgramFiles%\NVIDIA Corporation\Ansel\Tools" 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe off
cd "%ProgramFiles%\NVIDIA Corporation\Ansel" 2>nul
if exist NvCameraEnable.exe NvCameraEnable.exe off
for /f %%i in ('NvCameraEnable.exe') do set ANSEL=%%i
if "%ANSEL%"=="0" (
    echo Ansel Disabled
) else (
    echo Ansel Enabled
)
pause
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
set /p choix="Choisissez une option / Choose an option :"

if /i "%choix%"=="q" goto Main_menu
if /i "%choix%"=="quit" goto Main_menu
if /i "%choix%"=="exit" goto Main_menu
if /i "%choix%"=="x" goto Main_menu
if "%choix%"=="1" goto Services_1
if "%choix%"=="2" goto Services_2
if "%choix%"=="3" goto Services_3

echo Choix invalide / Invalid choice
pause
goto Services_menu

:Services_1
echo [ INITIALIZATION ] Please wait... The changes will take effect after a reboot
curl -s -L -o "%Temp%\Disable services.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/DisableServices.bat"
call "%Temp%\Disable services.bat" & del "%Temp%\Disable services.bat"
goto Services_menu

:Services_2
echo [ INITIALIZATION ] Please wait... The changes will take effect after a reboot
curl -s -L -o "%Temp%\PowerRun.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/PowerRun.exe"
curl -s -L -o "%Temp%\RestoreServices.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/RestoreServices.reg"
%Temp%\PowerRun.exe Regedit.exe /S %Temp%\RestoreServices.reg
del "%Temp%\PowerRun.exe" & del "%Temp%\RestoreServices.reg"
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
echo   [03] ⚡ Remove Microsoft Edge
echo   [04] ⚡ Uninstall pre-installed applications
echo   [05] ⚡ Steam shortcut without a browser on desktop
echo   [06] 🐺 LibreWolf
echo   [07] ⚡ Run the full Disk Cleanup tool on all disks
echo   [08] ⚡ ASCII Art
echo   [X]  ⚡ Back to menu / Retour
echo.
echo ════════════════════════════════════════════════════════════════
set /p choix="Choisissez une option / Choose an option :"

if /i "%choix%"=="q" goto Main_menu
if /i "%choix%"=="quit" goto Main_menu
if /i "%choix%"=="exit" goto Main_menu
if /i "%choix%"=="x" goto Main_menu
if "%choix%"=="1" reg delete "HKCU\AppEvents\Schemes\Apps" /f >nul 2>&1 & goto Misc_menu
if "%choix%"=="2" goto Misc_2
if "%choix%"=="3" goto Misc_3
if "%choix%"=="4" goto Misc_4
if "%choix%"=="5" goto Misc_5
if "%choix%"=="6" start "" "https://librewolf.net/installation/windows/" & goto Misc_menu
if "%choix%"=="7" goto Misc_7
if "%choix%"=="8" goto Misc_8

echo Choix invalide / Invalid choice
pause
goto Misc_menu

:Misc_2
echo Restore classic context menu in Windows 11 ? ['Y'es/'N'o/'R'eset]
set /p choix="Choisissez une option / Choose an option :"

if /i "%choix%"=="y" reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f >nul 2>&1 && goto Misc_menu
if /i "%choix%"=="r" reg delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f >nul 2>&1 && goto Misc_menu
if /i "%choix%"=="n" goto Misc_menu

echo Choix invalide / Invalid choice
pause
goto Misc_2

:Misc_3
:: https://github.com/he3als/EdgeRemover
chcp 437>nul
powershell -Command "iex(irm https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@main/get.ps1)"
chcp 65001>nul
goto Misc_menu

:Misc_4
%SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1
dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.MSPaint~~~~0.0.1.0 /Quiet /NoRestart >nul 2>&1
dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.SnippingTool~~~~0.0.1.0 /Quiet /NoRestart >nul 2>&1
chcp 437>nul
Powershell Get-AppxPackage -AllUsers ^*OutlookForWindows^* ^| Remove-AppxPackage -AllUsers -ErrorAction Continue
chcp 65001>nul
goto Misc_menu

:Misc_5
chcp 437>nul
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%USERPROFILE%\Desktop\Steam - No browser.lnk'); $s.TargetPath='C:\Program Files (x86)\Steam\Steam.exe'; $s.Arguments='silent -noverifyfiles -no-browser +open steam://open/minigameslist'; $s.Save()"
chcp 65001>nul
goto Misc_menu

:Misc_7
curl -s -L -o "%Temp%\sageset.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/sageset.reg"
reg import "%Temp%\sageset.reg" >nul 2>&1 & del "%Temp%\sageset.reg"
cleanmgr.exe /dc /sagerun:1
goto Misc_menu

:Misc_8
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
set /p choix="Choisissez une option / Choose an option :"

if /i "%choix%"=="q" goto Main_menu
if /i "%choix%"=="quit" goto Main_menu
if /i "%choix%"=="exit" goto Main_menu
if /i "%choix%"=="x" goto Main_menu
if "%choix%"=="1" start ms-settings:display & goto Check_menu
if "%choix%"=="2" start ms-settings:startupapps & goto Check_menu
if "%choix%"=="3" start ms-settings:windowsupdate & goto Check_menu
if "%choix%"=="4" goto Check_4
if "%choix%"=="5" start ms-settings:activation & goto Check_menu
if "%choix%"=="6" start ms-settings:regionlanguage & goto Check_menu
if "%choix%"=="7" start ms-settings:about & goto Check_menu
if "%choix%"=="8" start ms-settings:mousetouchpad & goto Check_menu
if "%choix%"=="9" start control hdwwiz.cpl & goto Check_menu
if "%choix%"=="10" %SystemRoot%\System32\ncpa.cpl & goto Check_menu
if "%choix%"=="11" %SystemRoot%\System32\powercfg.cpl & goto Check_menu
if "%choix%"=="12" %SystemRoot%\System32\diskmgmt.msc & goto Check_menu
if "%choix%"=="13" %SystemRoot%\System32\rundll32.exe sysdm.cpl,EditEnvironmentVariables & goto Check_menu
if "%choix%"=="14" %SystemRoot%\System32\services.msc & goto Check_menu
if "%choix%"=="15" optionalfeatures & goto Check_menu
if "%choix%"=="16" %SystemRoot%\system32\eventvwr.msc /s & goto Check_menu
if "%choix%"=="17" goto Check_15
if "%choix%"=="18" %SystemRoot%\System32\msinfo32.exe & goto Check_menu
if "%choix%"=="19" %SystemRoot%\System32\dfrgui.exe & goto Check_menu

echo Choix invalide / Invalid choice
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
for /f "tokens=14" %%i in ('ipconfig ^| findstr /i "IPv4"') do set ip=%%i
for /f "tokens=2 delims=:" %%i in ('nslookup 127.0.0.1 ^| findstr /i "Address"') do if not defined dns set dns=%%i
echo IPv4: %ip: =%
echo DNS : %dns: =%
pause
goto Check_menu
