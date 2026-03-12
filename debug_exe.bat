@echo off
echo ========================================
echo Attendance System - Debug Mode
echo ========================================
echo.
echo Current directory: %CD%
echo.
cd /d C:\Users\USER\Documents\apps\AMS\dist
echo Changed to: %CD%
echo.
echo Running AttendanceSystem.exe...
echo ========================================
echo.

AttendanceSystem.exe

echo.
echo ========================================
echo Application exited with code %errorlevel%
echo.
pause