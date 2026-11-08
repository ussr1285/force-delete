@echo off
rem force-delete: kill the processes locking a folder/file, then delete it.
rem Drag folders/files onto this file, or run it and type a path.
rem Options (pass after the path): -ListOnly  -KeepRoot  -Yes
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0force-delete.ps1" %*
set "rc=%errorlevel%"
echo.
pause
exit /b %rc%
