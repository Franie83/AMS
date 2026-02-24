@echo off
echo Building Attendance System Executable...
echo.

REM Clean previous builds
rmdir /s /q build dist 2>nul

REM Run PyInstaller
pyinstaller ams.spec --onefile --clean

echo.
if %errorlevel% equ 0 (
    echo ✅ Build successful!
    echo Executable created at: dist\AttendanceSystem.exe
) else (
    echo ❌ Build failed!
)

pause