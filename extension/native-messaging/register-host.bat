@echo off
REM VELA Native Messaging Host Registration Script for Chrome/Edge
REM Run this as Administrator

SET APP_PATH=%~dp0
SET APP_PATH=%APP_PATH:~0,-1%

echo VELA Native Messaging Host Registration
echo ======================================
echo.

REM Chrome registration (current user)
echo Registering for Chrome...
reg add "HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chrome\manifest.json" /f

REM Edge registration (current user)
echo Registering for Edge...
reg add "HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chrome\manifest.json" /f

echo.
echo Registration complete!
echo Please restart Chrome/Edge and reload the extension.
pause
