@echo off
REM VELA Native Messaging Host Registration Script
REM Registers for all Chromium-based browsers: Chrome, Edge, Brave, Thorium, Helium, and others
REM Run this as Administrator or current user

SET APP_PATH=%~dp0
SET APP_PATH=%APP_PATH:~0,-1%

echo VELA Native Messaging Host Registration
echo ======================================
echo.

REM === Google Chrome ===
echo Registering for Chrome...
reg add "HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

REM === Microsoft Edge ===
echo Registering for Edge...
reg add "HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

REM === Brave ===
echo Registering for Brave...
reg add "HKCU\SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

REM === Thorium ===
echo Registering for Thorium...
reg add "HKCU\SOFTWARE\Thorium\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

REM === Helium ===
echo Registering for Helium...
reg add "HKCU\SOFTWARE\Helium\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

REM === Vivaldi ===
echo Registering for Vivaldi...
reg add "HKCU\SOFTWARE\Vivaldi\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

REM === Opera (uses Chrome registry path on older versions, and its own on newer) ===
echo Registering for Opera...
reg add "HKCU\SOFTWARE\Opera Software\Opera Stable\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

REM === Arc (Chromium-based) ===
echo Registering for Arc...
reg add "HKCU\SOFTWARE\The Browser Company\Arc\NativeMessagingHosts\vela-desktop" /ve /d "%APP_PATH%\chromium\manifest.json" /f 2>nul

echo.
echo Registration complete!
echo Restart your browser(s) and reload the VELA extension.
pause
