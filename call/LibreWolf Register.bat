@echo off
SET "st3Path=%~dp0LibreWolf-Portable.exe"

reg add "HKLM\SOFTWARE\RegisteredApplications" /v "LibreWolf" /d "Software\\Clients\\StartMenuInternet\\LibreWolf\\Capabilities" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf" /ve /d "LibreWolf" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf" /v "ApplicationIcon" /d "%st3Path%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\DefaultIcon" /ve /d "%st3Path%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\shell\open\command" /ve /d "\"%st3Path%\"" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities" /v "ApplicationName" /d "LibreWolf" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities" /v "ApplicationDescription" /d "LibreWolf Browser" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities" /v "ApplicationCompany" /d "LibreWolf Community" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities" /v "ApplicationIcon" /d "%st3Path%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\StartMenu" /v "StartMenuInternet" /d "LibreWolf" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".atom" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".htm" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".html" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".mht" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".mhtml" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".rss" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".shtml" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".xht" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".xhtml" /d "LibreWolfHTML" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\FileAssociations" /v ".pdf" /d "LibreWolfPDF" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\URLAssociations" /v "http" /d "LibreWolfURL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\URLAssociations" /v "https" /d "LibreWolfURL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\URLAssociations" /v "ftp" /d "LibreWolfURL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\URLAssociations" /v "mailto" /d "LibreWolfURL" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\URLAssociations" /v "webcal" /d "LibreWolfURL" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\MIMEAssociations" /v "application/pdf" /d "LibreWolfPDF" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Clients\StartMenuInternet\LibreWolf\Capabilities\MIMEAssociations" /v "text/html" /d "LibreWolfHTML" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfHTML" /ve /d "HTML File (LibreWolf)" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\LibreWolfHTML" /v "Content Type" /d "text/html" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfHTML\DefaultIcon" /ve /d "%st3Path%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfHTML\shell\open\command" /ve /d "\"%st3Path%\" \"%%1\"" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfPDF" /ve /d "PDF File (LibreWolf)" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\LibreWolfPDF" /v "Content Type" /d "application/pdf" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfPDF\DefaultIcon" /ve /d "%st3Path%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfPDF\shell\open\command" /ve /d "\"%st3Path%\" \"%%1\"" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfURL" /ve /d "URL:LibreWolf" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\LibreWolfURL" /v "URL Protocol" /d "" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Classes\LibreWolfURL" /v "Content Type" /d "application/x-mswinurl" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfURL\DefaultIcon" /ve /d "%st3Path%,0" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Classes\LibreWolfURL\shell\open\command" /ve /d "\"%st3Path%\" \"%%1\"" /f >nul 2>&1
