@echo off
REM VELA Native Messaging Host Registration Script
REM Registers for Firefox and all Gecko-based forks: Zen Browser, Waterfox, Floorp, LibreWolf

SET SCRIPT_DIR=%~dp0
SET SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

echo VELA Native Messaging Host Registration for Gecko Browsers
echo ============================================================
echo.

set HOST_EXE=%VELA_NM_HOST_PATH%
IF "%HOST_EXE%"=="" SET HOST_EXE=%SCRIPT_DIR%\vela-native-messaging-host.exe
set HOST_NAME=com.vela.desktop

REM The compiled Rust host (vela-nm-host). Build it with:
REM   cd desktopVELA && cargo build --release -p vela-nm-host
if not exist "%HOST_EXE%" (
  echo ERROR: native messaging host binary not found: %HOST_EXE%
  echo Build it with: cd desktopVELA ^&^& cargo build --release -p vela-nm-host
  echo or set VELA_NM_HOST_PATH to its location.
  exit /b 1
)

set MANIFEST_HOST_PATH=%HOST_EXE:\=\\%

REM Create manifest content
set MANIFEST_CONTENT={"name":"%HOST_NAME%","description":"VELA Desktop Password Manager Native Messaging Host","path":"%MANIFEST_HOST_PATH%","type":"stdio","allowed_extensions":["vela@vela.app"]}

REM === Firefox ===
echo Registering for Firefox...
set NM_DIR=%APPDATA%\Mozilla\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
del "%NM_DIR%\vela-desktop.json" >nul 2>&1
echo %MANIFEST_CONTENT%> "%NM_DIR%\%HOST_NAME%.json"
reg delete "HKCU\SOFTWARE\Mozilla\NativeMessagingHosts\vela-desktop" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Mozilla\NativeMessagingHosts\%HOST_NAME%" /ve /d "%NM_DIR%\%HOST_NAME%.json" /f >nul 2>&1

REM === Zen Browser ===
echo Registering for Zen Browser...
set NM_DIR=%APPDATA%\zen\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
del "%NM_DIR%\vela-desktop.json" >nul 2>&1
echo %MANIFEST_CONTENT%> "%NM_DIR%\%HOST_NAME%.json"

REM === Waterfox ===
echo Registering for Waterfox...
set NM_DIR=%APPDATA%\Waterfox\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
del "%NM_DIR%\vela-desktop.json" >nul 2>&1
echo %MANIFEST_CONTENT%> "%NM_DIR%\%HOST_NAME%.json"

REM === Floorp ===
echo Registering for Floorp...
set NM_DIR=%APPDATA%\Floorp\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
del "%NM_DIR%\vela-desktop.json" >nul 2>&1
echo %MANIFEST_CONTENT%> "%NM_DIR%\%HOST_NAME%.json"

REM === LibreWolf ===
echo Registering for LibreWolf...
set NM_DIR=%APPDATA%\librewolf\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
del "%NM_DIR%\vela-desktop.json" >nul 2>&1
echo %MANIFEST_CONTENT%> "%NM_DIR%\%HOST_NAME%.json"

echo.
echo Registration complete!  Host: %HOST_NAME%
echo Host path: %HOST_EXE%
echo Restart your browser(s) and reload the VELA extension.
pause
