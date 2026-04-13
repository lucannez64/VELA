@echo off
REM VELA Native Messaging Host Registration Script
REM Registers for Firefox and all Gecko-based forks: Zen Browser, Waterfox, Floorp, LibreWolf

SET SCRIPT_DIR=%~dp0
SET SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

echo VELA Native Messaging Host Registration for Gecko Browsers
echo ============================================================
echo.

set HOST_SCRIPT=%SCRIPT_DIR%\vela-native-messaging-host.py

REM Find Python
set PYTHON_PATH=
where python3 >nul 2>&1
if %errorlevel% equ 0 (
    for /f "delims=" %%i in ('where python3') do set PYTHON_PATH=%%i
    goto :found_python
)
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "delims=" %%i in ('where python') do set PYTHON_PATH=%%i
    goto :found_python
)
echo ERROR: Python not found on PATH
exit /b 1

:found_python

REM Create manifest content
set MANIFEST_CONTENT={"name":"vela-desktop","description":"VELA Desktop Password Manager Native Messaging Host","path":"%PYTHON_PATH:\=\\%","type":"stdio","allowed_extensions":["vela@vela.app"]}

REM === Firefox ===
echo Registering for Firefox...
set NM_DIR=%APPDATA%\Mozilla\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
echo %MANIFEST_CONTENT%> "%NM_DIR%\vela-desktop.json"

REM === Zen Browser ===
echo Registering for Zen Browser...
set NM_DIR=%APPDATA%\zen\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
echo %MANIFEST_CONTENT%> "%NM_DIR%\vela-desktop.json"

REM === Waterfox ===
echo Registering for Waterfox...
set NM_DIR=%APPDATA%\Waterfox\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
echo %MANIFEST_CONTENT%> "%NM_DIR%\vela-desktop.json"

REM === Floorp ===
echo Registering for Floorp...
set NM_DIR=%APPDATA%\Floorp\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
echo %MANIFEST_CONTENT%> "%NM_DIR%\vela-desktop.json"

REM === LibreWolf ===
echo Registering for LibreWolf...
set NM_DIR=%APPDATA%\librewolf\NativeMessagingHosts
if not exist "%NM_DIR%" mkdir "%NM_DIR%"
echo %MANIFEST_CONTENT%> "%NM_DIR%\vela-desktop.json"

echo.
echo Registration complete!  Python: %PYTHON_PATH%
echo Restart your browser(s) and reload the VELA extension.
pause
