@echo off
title Game Launcher (OpenSSL Fix) & Color 0A

echo Drag and drop your game's .exe file into this window, then press ENTER:
set /p "game_path="

:: Remove quotes if present
set "game_path=%game_path:"=%"

:: Set the variable and launch the game
set "OPENSSL_ia32cap=~0x20000000"
start "" "%game_path%"
