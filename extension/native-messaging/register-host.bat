@echo off
REM VELA Native Messaging Host Registration Script
REM Registers for all Chromium-based browsers: Chrome, Edge, Brave, Thorium, Helium, and others
REM Run this as Administrator or current user

SET APP_PATH=%~dp0
SET APP_PATH=%APP_PATH:~0,-1%
SET MANIFEST_PATH=%APP_PATH%\chromium\manifest.local.json
SET HOST_EXE=%APP_PATH%\vela-native-messaging-host.exe
SET HOST_SCRIPT=%APP_PATH%\vela-native-messaging-host.py
SET HOST_WRAPPER_SOURCE=%APP_PATH%\vela-native-messaging-host-win.rs
SET HOST_NAME=com.vela.desktop

IF "%VELA_CHROME_EXTENSION_ID%"=="" (
  echo ERROR: set VELA_CHROME_EXTENSION_ID to the audited Chromium extension ID before registration.
  exit /b 1
)

IF NOT EXIST "%HOST_SCRIPT%" (
  echo ERROR: native messaging host script not found: %HOST_SCRIPT%
  exit /b 1
)

IF NOT EXIST "%HOST_EXE%" (
  where rustc >nul 2>&1
  if %errorlevel% neq 0 (
    echo ERROR: %HOST_EXE% not found and rustc is not available to build it.
    exit /b 1
  )
  rustc "%HOST_WRAPPER_SOURCE%" -O -o "%HOST_EXE%"
  if %errorlevel% neq 0 exit /b %errorlevel%
)

SET MANIFEST_HOST_PATH=%HOST_EXE:\=\\%

echo VELA Native Messaging Host Registration
echo ======================================
echo.

(
  echo {
  echo   "name": "%HOST_NAME%",
  echo   "description": "VELA Desktop Password Manager Native Messaging Host",
  echo   "path": "%MANIFEST_HOST_PATH%",
  echo   "type": "stdio",
  echo   "allowed_origins": ["chrome-extension://%VELA_CHROME_EXTENSION_ID%/"]
  echo }
) > "%MANIFEST_PATH%"

REM === Google Chrome ===
echo Registering for Chrome...
reg delete "HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

REM === Microsoft Edge ===
echo Registering for Edge...
reg delete "HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

REM === Brave ===
echo Registering for Brave...
reg delete "HKCU\SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

REM === Thorium ===
echo Registering for Thorium...
reg delete "HKCU\SOFTWARE\Thorium\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\Thorium\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

REM === Helium ===
echo Registering for Helium...
reg delete "HKCU\SOFTWARE\Helium\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\Helium\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

REM === Vivaldi ===
echo Registering for Vivaldi...
reg delete "HKCU\SOFTWARE\Vivaldi\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\Vivaldi\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

REM === Opera (uses Chrome registry path on older versions, and its own on newer) ===
echo Registering for Opera...
reg delete "HKCU\SOFTWARE\Opera Software\Opera Stable\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\Opera Software\Opera Stable\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

REM === Arc (Chromium-based) ===
echo Registering for Arc...
reg delete "HKCU\SOFTWARE\The Browser Company\Arc\NativeMessagingHosts\vela-desktop" /f 2>nul
reg add "HKCU\SOFTWARE\The Browser Company\Arc\NativeMessagingHosts\%HOST_NAME%" /ve /d "%MANIFEST_PATH%" /f 2>nul

echo.
echo Registration complete!
echo Host name: %HOST_NAME%
echo Host path: %HOST_EXE%
echo Restart your browser(s) and reload the VELA extension.
pause
