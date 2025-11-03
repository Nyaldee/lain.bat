@echo off
chcp 65001>nul
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo You must run this script as administrator.
    echo Vous devez exécuter ce script en tant qu'administrateur.
    pause
    exit
)
Title lain.bat & Color 03
:START
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
echo. → Ce script batch nécessite des privilèges d'administrateur et une connexion internet.
echo. Utilisation à vos risques et périls, sans garantie d'aucune sorte, faites une sauvegarde
echo. de vos fichiers et créez un point de restauration au préalable si besoin.
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo. → This batch script requires administrator privileges and an internet connection.
echo. Use at your own risk, without any warranty, make a backup of your files
echo. before proceeding and create a restore point before if necessary.
echo.
echo. Bios optimization :
echo. Enable : Re-Size BAR Support/4G Decoding, Precision Boost Overdrive, EXPO/XMP profile, L1/L2 Prefetcher,
echo. CPPC/CPPC Preferred
echo. Disable : Internal Graphics, SVM/VMX Mode, Drivers Software, CSM Support, Fastboot, High Precision Event Timer (?)
echo. Don't disable/try before : Global C-state Control, ACPI_CST C1 Declaration
echo.
choice /C:AR /N /M "+-+-+-+-+-+-+-+-+-+-+-+-+-+[ 'A'ccept / 'R'eject ]+-+-+-+-+-+-+-+-+-+-+-+-+-+"
if errorlevel 2 exit

echo.===============================================================================
echo.Voulez-vous créer un point de restauration ?
choice /C:YN /N /M "Do you want to create a restore point ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
start /wait "" "%windir%\System32\SystemPropertiesProtection.exe"
goto :END

:END
echo.===============================================================================
echo.Avez-vous une carte graphique Nvidia et souhaitez vous configurer les drivers ?
choice /C:YN /N /M "Do you have an Nvidia graphics card and want to configure the drivers ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
:NVIDIA
cls
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.                           NVIDIA Drivers setup
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.
echo. → Important
echo. * Optional
echo.
echo. [1]   * Hide certain driver in Windows Update
echo. [2]   * Uninstall Drivers (DDU)
echo. [3]   * Install Drivers with NVCleanstall (enable PhysX, disable ANSEL)
echo. [4]   → Check Message Signaled Interrupt on GPU is enabled (enable it if your card
echo. supports it, check on Google)
echo. [5]   → Use custom 3D settings (prioritizes latency over graphics)
echo. [6]   → NVIDIA Control Panel : configure the rest and check manually
echo. [7]   Disable ANSEL (Other : Ansel flags for enabled applications → 0)
echo.
echo. [X]   Quit
choice /C:1234567X /N /M "Enter Your Choice : "
if errorlevel 8 goto :END
if errorlevel 7 (
:: https://github.com/Orbmu2k/nvidiaProfileInspector
curl -s -L -o "%Temp%\NVIDIA Profile Inspector.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/nvidiaProfileInspector.exe"
start /wait "" "%Temp%\NVIDIA Profile Inspector.exe"
del "%Temp%\NVIDIA Profile Inspector.exe"
goto :NVIDIA
)
if errorlevel 6 (
start "" "shell:appsFolder\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj!NVIDIACorp.NVIDIAControlPanel"
echo.===============================================================================
echo. NVIDIA Control Panel
echo. • Configure Surround, PhysX : choosing your primary graphics card.
echo. • Change Resolution : Use NVIDIA color settings
echo. • Adjust desktop size and position : No scaling ^| Perform scaling on : Display
echo. • System Information : Check if Resizable BAR is enabled (GPU compatible^)
pause
goto :NVIDIA
)
if errorlevel 5 (
:: https://github.com/Orbmu2k/nvidiaProfileInspector
curl -s -L -o "%Temp%\NVIDIA Profile Inspector.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/nvidiaProfileInspector.exe"
curl -s -L -o "%Temp%\NvidiaBaseProfile.nip" "https://github.com/Nyaldee/lain.bat/raw/main/call/NvidiaBaseProfile.nip"
"%Temp%\NVIDIA Profile Inspector.exe" "%Temp%\NvidiaBaseProfile.nip" & del "%Temp%\NVIDIA Profile Inspector.exe" & del "%Temp%\NvidiaBaseProfile.nip"
goto :NVIDIA
)
if errorlevel 4 (
:: https://forums.guru3d.com/threads/windows-line-based-vs-message-signaled-based-interrupts-msi-tool.378044/
curl -s -L -o "%Temp%\MSI utility v3.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/MSI_util_v3.exe"
start /wait "" "%Temp%\MSI utility v3.exe" & del "%Temp%\MSI utility v3.exe"
goto :NVIDIA
)
if errorlevel 3 (
:: https://techpowerup.com/download/techpowerup-nvcleanstall/
curl -s -L -o "%Temp%\NVCleanstall.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/NVCleanstall.exe"
start /wait "" "%Temp%\NVCleanstall.exe" & del "%Temp%\NVCleanstall.exe"
goto :NVIDIA
)
if errorlevel 2 (
echo.Installer Display Driver Uninstaller dans %SystemDrive%\Apps\DDU ?
choice /C:YN /N /M "Install Display Driver Uninstaller in %SystemDrive%\Apps\DDU ? ['Y'es/'N'o] : "
if errorlevel 2 goto :NVIDIA
:: https://wagnardsoft.com/display-driver-uninstaller-ddu-
curl -s -L -o "%Temp%\DDU.exe" "https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.7.7.exe"
rd "%SystemDrive%\Apps\DDU" /s /q
start /wait "" "%Temp%\DDU.exe" -o"%SystemDrive%\Apps" -y
ren "%SystemDrive%\Apps\DDU v18.0.7.7" "DDU"
del "%Temp%\DDU.exe"
start "" "%SystemDrive%\Apps\DDU\Display Driver Uninstaller.exe"
goto :NVIDIA
)
if errorlevel 1 (
curl -s -L -o "%Temp%\wushowhide.diagcab" "https://download.microsoft.com/download/f/2/2/f22d5fdb-59cd-4275-8c95-1be17bf70b21/wushowhide.diagcab"
start /wait "" "%Temp%\wushowhide.diagcab" & del "%Temp%\wushowhide.diagcab" & rd "%Temp%\msdtadmin" /s /q
goto :NVIDIA
)

:END
echo.===============================================================================
echo.Désactiver certains services ?
choice /C:YN /N /M "Disable certain services ? ['Y'es/'N'o] : "
if errorlevel 2 goto :REG
echo.
:SERVICES
cls
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.                           Disable services
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo. * Not recommended
echo.
echo. [A]   All services (except system features, recommended)
echo. [B]   Windows Update Medic Service
echo. [C]   Windows Modules Installer (break Turn Windows features and NSudo)
echo. [D]   WLAN AutoConfig (If you don't use wifi)
echo. [E]   Bluetooth Support Service
echo. [F]   Dnscache (If you don't use VM)
echo. [G]   * Audio notification in taskbar (break wifi ?)
echo. [H]   * Network management (cause wifi problem ?)
echo. [I]   * AppXSVC (Break Personalization / About menu and some programs, I don't recommend disabling it)
echo. [J]   * UdkUserSvc (break search in start menu)
echo.
echo. [U]   Restore all
echo. [V]   Open Services window (sort by Startup Type)
echo. [W]   Enable menu (checking is recommended)
echo. [X]   Quit
choice /C:ABCDEFGHIJUVWX /N /M "Enter Your Choice : "
if errorlevel 14 goto :REG
if errorlevel 13 goto :ESERVICES
if errorlevel 12 (
start %windir%\system32\services.msc
goto :SERVICES
)
if errorlevel 11 (
curl -s -L -o "%Temp%\PowerRun.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/PowerRun.exe"
curl -s -L -o "%Temp%\RestoreServices.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/RestoreServices.reg"
%Temp%\PowerRun.exe Regedit.exe /S %Temp%\RestoreServices.reg
echo. The changes will take effect after a reboot.
pause
del "%Temp%\PowerRun.exe" & del "%Temp%\RestoreServices.reg"
goto :SERVICES
)
if errorlevel 10 (
:: UdkUserSvc (break search in start menu)
net stop "UdkUserSvc" /y >nul 2>&1 & sc config "UdkUserSvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 9 (
:: AppX Deployment Service (AppXSVC) (Break Personalization menu and Flow Launcher)
net stop "AppXSvc" /y >nul 2>&1 & sc config "AppXSvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 8 (
:: Radio Management Service (no internet icon)
net stop "RmSvc" /y >nul 2>&1 & sc config "RmSvc" start= Disabled >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 7 (
:: CNG Key Isolation (for CDPSvc)
net stop "KeyIso" /y >nul 2>&1 & sc config "KeyIso" start= Disabled >nul 2>&1
:: Connected Devices Platform Service (no sound click notification)
net stop "CDPSvc" /y >nul 2>&1 & sc config "CDPSvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: Network Connection Broker (CDPSvc depend)
net stop "NcbService" /y >nul 2>&1 & sc config "NcbService" start= Disabled >nul 2>&1
:: Connected Devices Platform User Service (no sound click notification)
net stop "CDPUserSvc" /y >nul 2>&1 & sc config "CDPUserSvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: Web Account Manager (no sound click notification)
net stop "TokenBroker" /y >nul 2>&1 & sc config "TokenBroker" start= Disabled >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 6 (
:: DNS Client (VirtualBox Internet)
net stop "Dnscache" /y >nul 2>&1 & sc config "Dnscache" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 5 (
:: Bluetooth Support Service
net stop "bthserv" /y >nul 2>&1 & sc config "bthserv" start= Disabled >nul 2>&1
net stop "BTAGService" /y >nul 2>&1 & sc config "BTAGService" start= Disabled >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 4 (
:: WLAN AutoConfig
net stop "WlanSvc" /y >nul 2>&1 & sc config "WlanSvc" start= Disabled >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 3 (
:: TrustedInstaller
net stop "TrustedInstaller" /y >nul 2>&1 & sc config "TrustedInstaller" start= Disabled >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 2 (
:: WaaSMedicSvc
net stop "WaaSMedicSvc" /y >nul 2>&1 & sc config "WaaSMedicSvc" start= Disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 1 (
echo.Veuillez patienter...
echo.Please wait...
curl -s -L -o "%Temp%\Disable services.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/DisableServices.bat"
call "%Temp%\Disable services.bat" & del "%Temp%\Disable services.bat"
pause
goto :SERVICES
)

:ESERVICES
cls
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.                           Enable services
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo. → Il faut parfois activer deux fois et redémarrer pour que ça fonctionne.
echo. → Sometimes you have to activate twice and restart for it to work.
echo.
echo. [A]   All services
echo. [B]   Windows Update Medic Service
echo. [C]   Windows Modules Installer
echo. [D]   WLAN AutoConfig (If you use wifi)
echo. [E]   Bluetooth Support Service
echo. [F]   Dnscache (If you use VM)
echo. [G]   Audio notification in taskbar (and wifi maybe)
echo. [H]   Network management (restore wifi maybe ?)
echo. [I]   AppXSVC (Personalization menu and some programs work)
echo. [J]   UdkUserSvc (repair search in start menu)
echo. [K]   Print Spooler service / imprimantes
echo. [L]   Superfetch (Sysmain) (HDD recommended)
echo. [M]   Search indexing (HDD recommended)
echo. [N]   TabletInputService
echo.
echo. [V]   Open Services window (sort by Startup Type)
echo. [W]   Disable menu
echo. [X]   Quit
choice /C:ABCDEFGHIJKLMNVWX /N /M "Enter Your Choice : "
if errorlevel 17 goto :REG
if errorlevel 16 goto :SERVICES
if errorlevel 15 (
start %windir%\system32\services.msc
goto :ESERVICES
)
if errorlevel 14 (
net start "TabletInputService" & sc config "TabletInputService" start= Demand
pause
goto :ESERVICES
)
if errorlevel 13 (
net start "WSearch" & sc config "WSearch" start= Auto
pause
goto :ESERVICES
)
if errorlevel 12 (
net start "SysMain" & sc config "SysMain" start= Auto
pause
goto :ESERVICES
)
if errorlevel 11 (
:: Print Spooler
net start "Spooler" & sc config "Spooler" start= Auto
pause
goto :ESERVICES
)
if errorlevel 10 (
:: UdkUserSvc (break search in start menu)
net start "UdkUserSvc" & sc config "UdkUserSvc" start= Auto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UdkUserSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
pause
goto :ESERVICES
)
if errorlevel 9 (
:: AppX Deployment Service (AppXSVC)
net start "AppXSvc" & sc config "AppXSvc" start= Auto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
pause
goto :ESERVICES
)
if errorlevel 8 (
:: Radio Management Service (no internet icon)
net start "RmSvc" & sc config "RmSvc" start= Demand
pause
goto :ESERVICES
)
if errorlevel 7 (
:: CNG Key Isolation (for CDPSvc)
net start "KeyIso" & sc config "KeyIso" start= Auto
:: Connected Devices Platform Service (no sound click notification)
net start "CDPSvc" & sc config "CDPSvc" start= Auto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPSvc" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
:: Network Connection Broker (CDPSvc depend)
net start "NcbService" & sc config "NcbService" start= Auto
:: Connected Devices Platform User Service (no sound click notification)
net start "CDPUserSvc" & sc config "CDPUserSvc" start= Auto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
:: Web Account Manager (no sound click notification)
net start "TokenBroker" & sc config "TokenBroker" start= Auto
pause
goto :ESERVICES
)
if errorlevel 6 (
:: DNS Client (VirtualBox Internet)
net start "Dnscache" & sc config "Dnscache" start= Auto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
pause
goto :ESERVICES
)
if errorlevel 5 (
:: Bluetooth Support Service
net start "bthserv" >nul 2>&1 & sc config "bthserv" start= Demand >nul 2>&1
net start "BTAGService" >nul 2>&1 & sc config "BTAGService" start= Demand >nul 2>&1
pause
goto :ESERVICES
)
if errorlevel 4 (
:: WLAN AutoConfig (disable Wifi)
net start "WlanSvc" & sc config "WlanSvc" start= Auto
pause
goto :ESERVICES
)
if errorlevel 3 (
:: WLAN AutoConfig
net start "WlanSvc" & sc config "WlanSvc" start= Demand
pause
goto :SERVICES
)
if errorlevel 2 (
:: WaaSMedicSvc
net start "WaaSMedicSvc" & sc config "WaaSMedicSvc" start= Demand
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
pause
goto :SERVICES
)
if errorlevel 1 (
curl -s -L -o "%Temp%\PowerRun.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/PowerRun.exe"
curl -s -L -o "%Temp%\RestoreServices.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/RestoreServices.reg"
%Temp%\PowerRun.exe Regedit.exe /S %Temp%\RestoreServices.reg
echo. The changes will take effect after a reboot.
pause
del "%Temp%\PowerRun.exe" & del "%Temp%\RestoreServices.reg"
goto :ESERVICES
)

:REG
echo.===============================================================================
echo.Configuration et optimisation globale de Windows ?
choice /C:YNV /N /M "Overall Windows configuration and optimization ? ['Y'es/'N'o/'V'iew modifications] : "
if errorlevel 3 (
cls
echo.===============================================================================
echo. • Disable : Sound Scheme, Startup sound, Reduce the volume (communications activity^), Transparency,
echo. Delay of Running Startup Apps, menu show delay, Enhance pointer precision and set default Sensitivity,
echo. Gaming features, Bandwidth throttling, Power throttling, UAC, Windows Defender Scan Removable Drives,
echo. Automatic maintenance, Prefetcher, LockScreen, LogonBackgroundImage, Logons programs, Scheduled tasks, 
echo. Ease of access, Hibernate, Delivery Optimization, fix timer resolution, remote assistance,
echo. Sign in User Account Picture, Certains Privavy ^& security features, Notifications, Explorer search history,
echo. 3D Objects, Shortcut Text, Program Compatibility Assistant, Impact Telemetry (AIT^),
echo. Frequent Recent files, Frequent Places, Recent Items, Context menu (Include in library, Pin to Quick access,
echo. Quick Access, Pin to Start, Send To, Cast to Device, Share with, Troubleshoot Compatibility, Edit,
echo. Edit with Paint 3D, Previous Versions^), Previous Versions Tab, Rotate left/right, Disable driver power saving,
echo. Automatic Installation of Suggested Apps, Network Discovery, Let's finish setting up your device
echo.
echo. • Enable : Dark Theme, Dark Theme for apps, shutting down quickly, HAGS, File Paths Over 260 Characters,
echo. Cab Update Context Menu, Shift+Right Click Take Ownership to context menu
echo.
echo. • Configure : Games scheduling, Debian NCSI, Show File Name Extensions, Show hidden files folders and drives,
echo. Open File Explorer to This PC, Hide TaskView, Search, Chat buttons, Prioritize apps in the foreground, 
echo. Performance Options, No GUI boot

goto :REG
)
if errorlevel 2 goto :END
reg export HKLM %Temp%\Temp_HKLM.reg >nul 2>&1 & reg export HKCU %Temp%\Temp_HKCU.reg >nul 2>&1 & reg export HKCR %Temp%\Temp_HKCR.reg >nul 2>&1
copy /b %Temp%\Temp_HKLM.reg + %Temp%\Temp_HKCU.reg + %Temp%\Temp_HKCR.reg %USERPROFILE%\Desktop\Backup.reg >nul 2>&1
del %Temp%\Temp_HKLM.reg & del %Temp%\Temp_HKCU.reg & del %Temp%\Temp_HKCR.reg
echo.Une copie du registre a été envoyé sur le bureau
echo.A copy of the registry has been sent to the desktop
echo.Veuillez patienter...
echo.Please wait...
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
lodctr /r >nul 2>&1 && lodctr /r >nul 2>&1
curl -s -L -o "%Temp%\Tweaks.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/Tweaks.reg"
reg import "%Temp%\Tweaks.reg" >nul 2>&1 & del "%Temp%\Tweaks.reg"
curl -s -L -o "%Temp%\SetACL.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/SetACL.exe"
%Temp%\SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -ot reg -actn setowner -ownr "n:Administrators" >nul 2>&1
%Temp%\SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -ot reg -actn ace -ace "n:Administrators;p:full" >nul 2>&1
del "%Temp%\SetACL.exe"
reg add "HKCR\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2689597440" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f >nul 2>&1
curl -s -L -o "%Temp%\User Account Pictures.zip" "https://github.com/Nyaldee/lain.bat/raw/main/call/UserAccountPictures.zip"
powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force"
powershell -Command "Get-PnpDevice | Where-Object FriendlyName -like 'Remote Desktop Device Redirector Bus*' | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Get-PnpDevice | Where-Object { $_.FriendlyName -like 'Composite Bus Enumerator*' -or $_.FriendlyName -like 'High precision event timer*' -or $_.FriendlyName -like 'UMBus Root Bus Enumerator*' -or $_.FriendlyName -like 'Numeric data processor*' -or $_.FriendlyName -like 'SM Bus Controller*' -or $_.FriendlyName -like 'Microsoft GS Wavetable Synth*' -or $_.FriendlyName -like 'Microsoft Virtual Drive Enumerator*' -or $_.FriendlyName -like 'System speaker*' } | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
powershell -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put() } > $null"
powershell -Command "Expand-Archive -Path '%Temp%\User Account Pictures.zip' -DestinationPath '%ProgramData%\Microsoft\User Account Pictures' -Force"
chcp 65001>nul
del "%Temp%\User Account Pictures.zip"
wevtutil cl Application >nul 2>&1 & wevtutil cl Security >nul 2>&1 & wevtutil cl Setup >nul 2>&1 & wevtutil cl System >nul 2>&1

:END
echo.===============================================================================
echo.Configuration et optimisation du réseau ? (non recommandé)
choice /C:YN /N /M "Network configuration and optimization ? (not recommended, may break the network) ['Y'es/'N'o] : "
if errorlevel 2 goto :END
chcp 437>nul
curl -s -L -o "%Temp%\Network.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/Network.bat"
call "%Temp%\Network.bat" & del "%Temp%\Network.bat"
chcp 65001>nul

:END
echo.===============================================================================
echo.Désactiver les drivers et services Bluetooth ?
choice /C:YNRB /N /M "Disable Bluetooth drivers and services ? ['Y'es/'N'o/'R'eset] : "
if errorlevel 3 (
net start "bthserv" >nul 2>&1 & sc config "bthserv" start= Demand >nul 2>&1
net start "BTAGService" >nul 2>&1 & sc config "BTAGService" start= Demand >nul 2>&1
chcp 437>nul
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
powershell -Command "& { Get-PnpDevice -Class 'Bluetooth' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Enable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
chcp 65001>nul
)
if errorlevel 2 goto :END
if errorlevel 1 (
net stop "bthserv" /y >nul 2>&1 & sc config "bthserv" start= Disabled >nul 2>&1
net stop "BTAGService" /y >nul 2>&1 & sc config "BTAGService" start= Disabled >nul 2>&1
chcp 437>nul
powershell -Command "& { Get-PnpDevice -Class 'Net' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
powershell -Command "& { Get-PnpDevice -Class 'Bluetooth' | Where-Object { $_.FriendlyName -like '*Bluetooth*' } | ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue } }"
chcp 65001>nul
)

:END
echo.===============================================================================
echo.Optimiser et activer le plan d'alimentation Ultimate Performance ? (recommandé sur PC fixe)
choice /C:YNKR /N /M "Optimize and activate the Ultimate Performance power plan ? (Desktop recommended) ['Y'es/'N'o/'K'eep Balanced/'R'eset] : "
if errorlevel 4 (
powercfg -restoredefaultschemes >nul 2>&1
powercfg /hibernate on >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 100 /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683" /v "Attributes" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "Attributes" /t REG_DWORD /d 1 /f >nul 2>&1
echo Power plans have been restored
)
if errorlevel 3 (
powercfg -restoredefaultschemes >nul 2>&1
curl -s -L -o "%Temp%\KeepBalancedPP.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/KeepBalancedPP.bat"
call "%Temp%\KeepBalancedPP.bat" & del "%Temp%\KeepBalancedPP.bat"
powercfg /hibernate off >nul 2>&1
powercfg /list
)
if errorlevel 2 goto :END
if errorlevel 1 (
powercfg -restoredefaultschemes >nul 2>&1
curl -s -L -o "%Temp%\PowerPlan.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/PowerPlan.bat"
call "%Temp%\PowerPlan.bat" & del "%Temp%\PowerPlan.bat"
powercfg /hibernate off >nul 2>&1
powercfg /list
)

:END
echo.===============================================================================
echo.Les fonctionnalités suivantes seront désactivés :
echo.The following features will be disabled :
echo. • Windows-Defender-ApplicationGuard
echo. • VirtualMachinePlatform
echo. • HypervisorPlatform
echo. • Windows PowerShell 2.0
echo. • Work Folders Client
echo. • SMB1Protocol
echo.
echo.Désactiver VBS (Virtualization-based security) et d'autres fonctionnalités inutiles ?
choice /C:YN /N /M "Disable VBS and other unnecessary features ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
dism /online /Disable-Feature /FeatureName:"Windows-Defender-ApplicationGuard" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"VirtualMachinePlatform" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"HypervisorPlatform" /Quiet /NoRestart >nul 2>&1
:: Others
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"WorkFolders-Client" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"MediaPlayback" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Printing-PrintToPDFServices-Features" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Printing-Foundation-Features" /Quiet /NoRestart >nul 2>&1
dism /online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-All" /Quiet /NoRestart >nul 2>&1

:END
echo.===============================================================================
echo.Les programmes suivants seront désinstallés :
echo.The following programs will be uninstalled :
echo. • Microsoft OneDrive
echo. • Microsoft Paint
echo. • Snipping Tool
echo. • Outlook
echo.
echo.Désinstaller ces programmes ?
choice /C:YN /N /M "Uninstall these programs ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
%SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1
dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.MSPaint~~~~0.0.1.0 /Quiet /NoRestart >nul 2>&1
dism /online /Remove-Capability /CapabilityName:Microsoft.Windows.SnippingTool~~~~0.0.1.0 /Quiet /NoRestart >nul 2>&1
chcp 437>nul
Powershell Get-AppxPackage -AllUsers ^*OutlookForWindows^* ^| Remove-AppxPackage -AllUsers -ErrorAction Continue
chcp 65001>nul

:END
echo.===============================================================================
echo.Supprimer Microsoft Edge ?
choice /C:YN /N /M "Remove Microsoft Edge ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
chcp 437>nul
:: https://github.com/he3als/EdgeRemover
powershell -Command "iex(irm https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@main/get.ps1)"
chcp 65001>nul

:END
echo.===============================================================================
echo.Les fichiers suivants seront installés :
echo.The following files will be installed :
echo. • .NET Framework 3.5/4.8
echo. • .NET 9.0 Runtime
echo. • Microsoft DirectX® End-User Runtime
echo. • Microsoft Visual C++ Redistributable Runtimes
echo.
echo.Installer les fichiers (nécessaire pour le service de résolution des délais) ?
choice /C:YN /N /M "Install the files ? (required for Timer Resolution Service) ['Y'es/'N'o] : "
if errorlevel 2 goto :END

dism /online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart
dism /online /Enable-Feature /FeatureName:NetFx4-AdvSrvs /All /NoRestart
md "%Temp%\Bonjour" >nul 2>&1
curl -s -L -o "%Temp%\Bonjour\DirectX_Redist_Repack_x86_x64.zip" "https://github.com/stdin82/htfx/releases/download/v0.0.4/DirectX_Redist_Repack_x86_x64_v3.zip"
tar -xf "%Temp%\Bonjour\DirectX_Redist_Repack_x86_x64.zip" -C "%Temp%\Bonjour"
curl -s -L -o "%Temp%\Bonjour\.NET 9.0.exe" "https://builds.dotnet.microsoft.com/dotnet/Runtime/9.0.10/dotnet-runtime-9.0.10-win-x64.exe"
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
start /wait "" "%Temp%\Bonjour\vcredist2008_x86.exe" /qb
start /wait "" "%Temp%\Bonjour\vcredist2008_x64.exe" /qb
start /wait "" "%Temp%\Bonjour\vcredist2010_x86.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\vcredist2010_x64.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\vcredist2012_x86.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\vcredist2012_x64.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\vcredist2013_x86.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\vcredist2013_x64.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\vcredist2022_x86.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\vcredist2022_x64.exe" /passive /norestart
start /wait "" "%Temp%\Bonjour\DirectX_Redist_Repack_x86_x64.exe" /y
start /wait "" "%Temp%\Bonjour\.NET 9.0.exe" /install /quiet /norestart
rd "%Temp%\Bonjour" /s /q >nul 2>&1

:END
echo.===============================================================================
echo.Installer le service de résolution des délais ?
choice /C:YNR /N /M "Install Timer Resolution Service ? ['Y'es/'N'o/'R'emove Service] : "
if errorlevel 3 (
net stop "STR" /y >nul 2>&1 & sc delete "STR" >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\STR" /f >nul 2>&1
goto :END
)
if errorlevel 2 goto :END
curl -s -L -o "%SystemRoot%\SetTimerResolutionService.exe" "https://github.com/Nyaldee/lain.bat/raw/main/call/SetTimerResolutionService.exe"
sc create "STR" binPath= "%SystemRoot%\SetTimerResolutionService.exe" >nul 2>&1
sc config "STR" start= auto >nul 2>&1
sc description "STR" "Timer Resolution lets you change your default Windows timer’s resolution in a matter of seconds and consequently improves the FPS for the games you are playing." >nul 2>&1
net start "STR" >nul 2>&1
goto :END

:END
echo.===============================================================================
echo.Supprimer définitivement les sons Windows ?
choice /C:YN /N /M "Remove Windows sounds permanently ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
reg delete "HKCU\AppEvents\Schemes\Apps" /f >nul 2>&1

:END
echo.===============================================================================
echo.Restaurer le menu contextuel classique sur Windows 11 ?
choice /C:YNR /N /M "Restore classic context menu in Windows 11 ? ['Y'es/'N'o/'R'eset] : "
if errorlevel 3 (
reg delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f >nul 2>&1
goto :END
)
if errorlevel 2 goto :END
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f >nul 2>&1

:END
echo.===============================================================================
echo.Désactiver SmartScreen et bloquer Edge ?
choice /C:YNR /N /M "Disable SmartScreen and block Edge ? ['Y'es/'N'o/'R'eset] : "
if errorlevel 3 (
takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.bak" >nul 2>&1
ren "%WinDir%\System32\smartscreen.bak" "smartscreen.exe"
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "Edge" /f
goto :END
)
if errorlevel 2 goto :END
takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe" >nul 2>&1
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
taskkill /im smartscreen.exe /f
ren "%WinDir%\System32\smartscreen.exe" "smartscreen.bak"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "Edge" /t REG_SZ /d "msedge.exe" /f >nul 2>&1

:END
echo.===============================================================================
echo.Désactiver Windows Update ?
choice /C:YNR /N /M "Disable Windows Update ? ['Y'es/'N'o/'R'eset] : "
if errorlevel 3 (
takeown /F "%WinDir%\System32\wuaueng.bak" >nul 2>&1
ren "%WinDir%\System32\wuaueng.bak" "wuaueng.dll"
takeown /F "%WinDir%\System32\WaasMedicSvc.bak" >nul 2>&1
ren "%WinDir%\System32\WaasMedicSvc.bak" "WaasMedicSvc.dll"
net stop "UsoSvc" /y >nul 2>&1 & sc config "UsoSvc" start= Demand >nul 2>&1
net start "wuauserv" & sc config "wuauserv" start= Demand
net start "WaaSMedicSvc" & sc config "WaaSMedicSvc" start= Demand
goto :END
)
if errorlevel 2 goto :END
net stop "UsoSvc" /y >nul 2>&1 & sc config "UsoSvc" start= Disabled >nul 2>&1
net stop "wuauserv" /y >nul 2>&1 & sc config "wuauserv" start= Disabled >nul 2>&1
net stop "WaaSMedicSvc" /y >nul 2>&1 & sc config "WaaSMedicSvc" start= Disabled >nul 2>&1
takeown /F "%WinDir%\System32\wuaueng.dll" >nul 2>&1
icacls "%WinDir%\System32\wuaueng.dll" /grant:r %username%:F >nul 2>&1
ren "%WinDir%\System32\wuaueng.dll" "wuaueng.bak"
takeown /F "%WinDir%\System32\WaasMedicSvc.dll" >nul 2>&1
icacls "%WinDir%\System32\WaasMedicSvc.dll" /grant:r %username%:F >nul 2>&1
ren "%WinDir%\System32\WaasMedicSvc.dll" "WaasMedicSvc.bak"

:END
echo.===============================================================================
echo.Lancer l'outil nettoyage de disque complet sur tous les disques (peu utile et cela peut prendre un certain temps) ?
choice /C:YN /N /M "Run the full Disk Cleanup tool on all disks ? (not very useful and may take some time) ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
curl -s -L -o "%Temp%\sageset.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/sageset.reg"
reg import "%Temp%\sageset.reg" >nul 2>&1 & del "%Temp%\sageset.reg"
cleanmgr.exe /dc /sagerun:1

:END
echo.===============================================================================
:: https://gist.github.com/AveYo/80fc6677b9f34939e44364880fbf3768
echo.Avez vous un écran OLED et souhaitez vous activer le préréglage du noir AMOLED ?
choice /C:YVNR /N /M "Do you have an OLED screen and would like to enable the AMOLED black preset ? ['Y'es/'V'iolet/'N'o/'R'eset themes] : "
if errorlevel 4 (
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /f >nul 2>&1
reg delete "HKU\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /f >nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f >nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Windows\DWM" /f >nul 2>&1
reg delete "HKU\.DEFAULT\SOFTWARE\Microsoft\Windows\DWM" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /f >nul 2>&1
reg delete "HKU\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f >nul 2>&1
reg delete "HKCU\Control Panel\Colors" /f >nul 2>&1
reg delete "HKU\.DEFAULT\Control Panel\Colors" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Background" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f >nul 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "PersonalColors_Background" /f >nul 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "PersonalColors_Accent" /f >nul 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f >nul 2>&1
goto :END
)
if errorlevel 3 goto :END
if errorlevel 2 (
curl -s -L -o "%Temp%\BlackViolet.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/VioletBlackTheme.reg"
reg import "%Temp%\BlackViolet.reg" >nul 2>&1 & del "%Temp%\BlackViolet.reg"
goto :END
)
curl -s -L -o "%Temp%\Pitch Black Theme.reg" "https://github.com/Nyaldee/lain.bat/raw/main/call/PitchBlackTheme.reg"
reg import "%Temp%\Pitch Black Theme.reg" >nul 2>&1 & del "%Temp%\Pitch Black Theme.reg"

:END
echo.===============================================================================
echo.Créer un raccourci sur le bureau pour lancer Steam sans navigateur ?
choice /C:YN /N /M "Create a desktop shortcut to launch Steam without a browser ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
chcp 437>nul
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%USERPROFILE%\Desktop\Steam - No browser.lnk'); $s.TargetPath='C:\Program Files (x86)\Steam\Steam.exe'; $s.Arguments='silent -noverifyfiles -no-browser +open steam://open/minigameslist'; $s.Save()"
chcp 65001>nul

:END
echo.===============================================================================
echo.Bloquer l'espionnage et le suivi des IPs (via WindowsSpyBlocker et le fichier host) ? Vous ne recevrez plus les majs Windows.
choice /C:YNR /N /M "Block spying and tracking IPs (via WindowsSpyBlocker and host file) ? You will no longer receive Windows updates. ['Y'es/'N'o/'R'eset] : "
:: https://github.com/crazy-max/WindowsSpyBlocker
if errorlevel 3 (
curl -s -L -o "%Temp%\CustomHostsRemove.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/CustomHostsRemove.bat"
call "%Temp%\CustomHostsRemove.bat" & del "%Temp%\CustomHostsRemove.bat"
curl -s -L -o "%Temp%\FirewallRulesRemove.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/FirewallRulesRemove.bat"
call "%Temp%\FirewallRulesRemove.bat" & del "%Temp%\FirewallRulesRemove.bat"
)

if errorlevel 2 goto :END
curl -s -L -o "%Temp%\CustomHostsAdd.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/CustomHostsAdd.bat"
call "%Temp%\CustomHostsAdd.bat" & del "%Temp%\CustomHostsAdd.bat"
curl -s -L -o "%Temp%\FirewallRulesAdd.bat" "https://github.com/Nyaldee/lain.bat/raw/main/call/FirewallRulesAdd.bat"
call "%Temp%\FirewallRulesAdd.bat" & del "%Temp%\FirewallRulesAdd.bat"

:END
echo.===============================================================================
echo.Modifier et vérifier les paramètres de Windows ?
choice /C:YN /N /M "Change and check Windows Settings ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
echo.
:WSETTINGS
cls
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.                           Windows Settings
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.
echo. → Important
echo.
echo. [1]   Adjust display scale
echo. [2]   → Disable unwanted startup programs
echo. [3]   → Check Update
echo. [4]   → Sound
echo. [5]   → Network adapters
echo. [6]   Check Windows Activation
echo. [7]   Language Time Region
echo. [8]   Rename this PC
echo. [9]   Cursor appearance
echo. [0]   Environment Variables
echo.
echo. [X]   Quit
choice /C:1234567890X /N /M "Enter Your Choice : "
if errorlevel 11 goto :END
if errorlevel 10 (
start /wait "" "%windir%\System32\rundll32.exe" sysdm.cpl,EditEnvironmentVariables
goto :WSETTINGS
)
if errorlevel 9 (
start ms-settings:mousetouchpad
goto :WSETTINGS
)
if errorlevel 8 (
start ms-settings:about
goto :WSETTINGS
)
if errorlevel 7 (
start ms-settings:regionlanguage
goto :WSETTINGS
)
if errorlevel 6 (
start ms-settings:activation
goto :WSETTINGS
)
if errorlevel 5 (
start control hdwwiz.cpl
:: start control ncpa.cpl
echo.===============================================================================
echo. Device Manager
echo. • Disable devices that are not in use.
echo. • Right click → Properties on the adapter you use :
echo.    Advanced : check the connection before and after on speedtest.net
echo.    return if the connection is less good
echo.    Disable everything except :
echo.      • Priority ^& VLAN
echo.      • Interrupt Moderation, can limit the connection to 100mbps.
echo.      • TCP Checksum Offload
echo.
pause
goto :WSETTINGS
)
if errorlevel 4 (
start control mmsys.cpl
echo.===============================================================================
echo. • Disable devices that are not in use.
echo. • Right click → Properties on all devices :
echo.    Levels : set the volume to 100.
echo.    Enhancement : check Disable all enhancements.
echo.    Advanced : uncheck Allow applications to take exclusive control of this device.
pause
goto :WSETTINGS
)
if errorlevel 3 (
start ms-settings:windowsupdate
goto :WSETTINGS
)
if errorlevel 2 (
start ms-settings:startupapps
goto :WSETTINGS
)
if errorlevel 1 (
start ms-settings:display
goto :WSETTINGS
)

:END
echo.===============================================================================
echo.Voulez-vous vérifier manuellement certains changements ?
choice /C:YN /N /M "Do you want to check some changes manually ? ['Y'es/'N'o] : "
if errorlevel 2 goto :END
:CHECK
cls
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.                           Verification of changes
echo.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
echo.
echo.
echo. [A]   Virtualization-based security is Not enabled
echo. [B]   Power plan is Ultimate Performance
echo. [C]   Optimizations / Hardware-accelerated GPU scheduling is on
echo. [D]   Game Bar is off
echo. [E]   Game Mode is on
echo. [F]   Game Captures is off
echo. [G]   Enhance pointer precision is uncheck
echo. [H]   No GUI boot is check
echo. [I]   Delivery Optimization is off
echo. [J]   View used DNS
echo. [K]   View Windows Apps
echo. [L]   View Services
echo. [M]   Windows Features
echo.
echo. [X]   Quit
choice /C:ABCDEFGHIJKLMX /N /M "Enter Your Choice : "
if errorlevel 14 goto :END
if errorlevel 13 (
start %windir%\system32\OptionalFeatures.exe
goto :CHECK
)
if errorlevel 12 (
start %windir%\system32\services.msc
goto :CHECK
)
if errorlevel 11 (
start ms-settings:appsfeatures
goto :CHECK
)
if errorlevel 10 (
start ms-settings:network
goto :CHECK
)
if errorlevel 9 (
start ms-settings:delivery-optimization
goto :CHECK
)
if errorlevel 8 (
start %windir%\system32\msconfig.exe
goto :CHECK
)
if errorlevel 7 (
start control main.cpl,,2
goto :CHECK
)
if errorlevel 6 (
start ms-settings:gaming-gamedvr
goto :CHECK
)
if errorlevel 5 (
start ms-settings:gaming-gamemode
goto :CHECK
)
if errorlevel 4 (
start ms-settings:gaming-gamebar
goto :CHECK
)
if errorlevel 3 (
start ms-settings:display-advancedgraphics
goto :CHECK
)
if errorlevel 2 (
start %windir%\system32\powercfg.cpl
goto :CHECK
)
if errorlevel 1 (
start %windir%\System32\msinfo32.exe
goto :CHECK
)

:END
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
echo.
echo.La configuration est terminée, les modifications prendront effet après un redémarrage.
echo.Configuration is complete, the changes will take effect after a reboot.
rd "%Temp%\Bonjour" /s /q >nul 2>&1
echo.Recommencer la configuration ?
choice /C:YN /N /M "Start the configuration again ? ['Y'es/'N'o] : "
if errorlevel 2 exit
goto :START
