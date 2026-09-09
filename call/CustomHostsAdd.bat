@echo off

curl -s -L -o "%Temp%\BlockedHosts.txt" "%URL_HOSTS_LIST%"
if not exist "%Temp%\BlockedHosts.txt" (
    echo [!] Echec du telechargement de la liste de hosts.
    exit /b 1
)

copy /y "%WINDIR%\System32\Drivers\Etc\Hosts" "%Temp%\Hosts.tmp" >nul 2>&1

for /f "usebackq delims=" %%a in ("%Temp%\BlockedHosts.txt") do (
    findstr /i /c:"0.0.0.0 %%a" "%Temp%\Hosts.tmp" >nul 2>nul || (echo 0.0.0.0 %%a >> "%Temp%\Hosts.tmp")
)

move /y "%Temp%\Hosts.tmp" "%WINDIR%\System32\Drivers\Etc\Hosts" >nul 2>&1

del "%Temp%\BlockedHosts.txt" >nul 2>&1
