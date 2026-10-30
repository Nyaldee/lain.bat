@echo off
REM Set NAME/APP below to your browser's name and exe, place this script
REM next to it.
REM
REM This registers the browser as a "Default Apps" choice via
REM RegisteredApplications/Capabilities -- it does not force it as the
REM default, it just makes it selectable. The Settings page opened at
REM the end is where you actually pick it.
set "NAME=LibreWolf"
set "APP=%~dp0LibreWolf-Portable.exe"

if not exist "%APP%" (
    echo ERROR: "%APP%" not found -- edit APP above to point to the right exe.
    pause
    exit /b 1
)

fltmc >nul 2>&1
if errorlevel 1 (
    echo ERROR: this script must be run as Administrator.
    pause
    exit /b 1
)

reg add "HKLM\SOFTWARE\RegisteredApplications" /v "%NAME%" /d "Software\\Clients\\StartMenuInternet\\%NAME%\\Capabilities" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%" /ve /d "%NAME%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%" /v "ApplicationIcon" /d "%APP%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\DefaultIcon" /ve /d "%APP%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\shell\open\command" /ve /d "\"%APP%\"" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities" /v "ApplicationName" /d "%NAME%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities" /v "ApplicationDescription" /d "%NAME% Browser" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities" /v "ApplicationCompany" /d "%NAME% Community" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities" /v "ApplicationIcon" /d "%APP%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\StartMenu" /v "StartMenuInternet" /d "%NAME%" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".atom" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".htm" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".html" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".mht" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".mhtml" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".rss" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".shtml" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".xht" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".xhtml" /d "%NAME%HTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\FileAssociations" /v ".pdf" /d "%NAME%PDF" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\URLAssociations" /v "http" /d "%NAME%URL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\URLAssociations" /v "https" /d "%NAME%URL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\URLAssociations" /v "ftp" /d "%NAME%URL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\URLAssociations" /v "mailto" /d "%NAME%URL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\URLAssociations" /v "webcal" /d "%NAME%URL" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\MIMEAssociations" /v "application/pdf" /d "%NAME%PDF" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\%NAME%\Capabilities\MIMEAssociations" /v "text/html" /d "%NAME%HTML" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%HTML" /ve /d "HTML File (%NAME%)" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\%NAME%HTML" /v "Content Type" /d "text/html" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%HTML\DefaultIcon" /ve /d "%APP%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%HTML\shell\open\command" /ve /d "\"%APP%\" \"%%1\"" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%PDF" /ve /d "PDF File (%NAME%)" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\%NAME%PDF" /v "Content Type" /d "application/pdf" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%PDF\DefaultIcon" /ve /d "%APP%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%PDF\shell\open\command" /ve /d "\"%APP%\" \"%%1\"" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%URL" /ve /d "URL:%NAME%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\%NAME%URL" /v "URL Protocol" /d "" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\%NAME%URL" /v "Content Type" /d "application/x-mswinurl" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%URL\DefaultIcon" /ve /d "%APP%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\%NAME%URL\shell\open\command" /ve /d "\"%APP%\" \"%%1\"" /f >nul 2>&1
start ms-settings:defaultapps
pause
