@echo off

curl -s -L -o "%Temp%\BlockedHosts.txt" "%URL_HOSTS_LIST%"
if not exist "%Temp%\BlockedHosts.txt" (
    echo [!] Echec du telechargement de la liste de hosts.
    exit /b 1
)

copy /y "%SystemRoot%\System32\Drivers\Etc\Hosts" "%Temp%\Hosts.tmp" >nul 2>&1
for /f "usebackq delims=" %%a in ("%Temp%\BlockedHosts.txt") do (
    findstr /v /i "%%a" "%Temp%\Hosts.tmp" > "%Temp%\Hosts.tmp.new" & move /y "%Temp%\Hosts.tmp.new" "%Temp%\Hosts.tmp" >nul 2>&1
)
move /y "%Temp%\Hosts.tmp" "%WINDIR%\System32\Drivers\Etc\Hosts" >nul 2>&1

del "%Temp%\BlockedHosts.txt" >nul 2>&1
