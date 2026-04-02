@echo off
echo ========================================
echo Creating Final Distribution Package
echo ========================================
echo.

REM Create final distribution folder
if exist final_dist rmdir /s /q final_dist
mkdir final_dist

REM Copy the executable
if exist "dist\AttendanceSystem.exe" (
    echo ✓ Copying AttendanceSystem.exe...
    copy dist\AttendanceSystem.exe final_dist\
) else (
    echo ✗ Executable not found in dist folder!
    exit /b 1
)

REM Copy required folders
echo ✓ Copying templates...
xcopy templates final_dist\templates\ /E /I /Y /Q >nul
echo ✓ Copying static...
xcopy static final_dist\static\ /E /I /Y /Q >nul
echo ✓ Copying uploads...
xcopy uploads final_dist\uploads\ /E /I /Y /Q >nul

REM Copy app.py as backup
copy app.py final_dist\ >nul

REM Create easy launcher
echo @echo off > final_dist\Launch_Attendance.bat
echo title Attendance Management System >> final_dist\Launch_Attendance.bat
echo color 0A >> final_dist\Launch_Attendance.bat
echo echo ======================================== >> final_dist\Launch_Attendance.bat
echo echo    Attendance Management System >> final_dist\Launch_Attendance.bat
echo echo ======================================== >> final_dist\Launch_Attendance.bat
echo echo. >> final_dist\Launch_Attendance.bat
echo echo Starting system... >> final_dist\Launch_Attendance.bat
echo start http://127.0.0.1:5000 >> final_dist\Launch_Attendance.bat
echo AttendanceSystem.exe >> final_dist\Launch_Attendance.bat
echo pause >> final_dist\Launch_Attendance.bat

REM Create README
echo Attendance Management System > final_dist\README.txt
echo. >> final_dist\README.txt
echo ======================================== >> final_dist\README.txt
echo INSTALLATION INSTRUCTIONS >> final_dist\README.txt
echo ======================================== >> final_dist\README.txt
echo. >> final_dist\README.txt
echo 1. Extract all files to any folder on your computer >> final_dist\README.txt
echo 2. Double-click "Launch_Attendance.bat" to start the system >> final_dist\README.txt
echo 3. The application will open automatically in your browser >> final_dist\README.txt
echo. >> final_dist\README.txt
echo ======================================== >> final_dist\README.txt
echo LOGIN CREDENTIALS >> final_dist\README.txt
echo ======================================== >> final_dist\README.txt
echo Super Admin: >> final_dist\README.txt
echo   Email: sadmin@gmail.com >> final_dist\README.txt
echo   Password: sadmin123 >> final_dist\README.txt
echo. >> final_dist\README.txt
echo Admin: >> final_dist\README.txt
echo   Email: admin@gmail.com >> final_dist\README.txt
echo   Password: admin123 >> final_dist\README.txt
echo. >> final_dist\README.txt
echo ======================================== >> final_dist\README.txt
echo SYSTEM REQUIREMENTS >> final_dist\README.txt
echo ======================================== >> final_dist\README.txt
echo - Windows 7/8/10/11 (64-bit) >> final_dist\README.txt
echo - Webcam for face recognition >> final_dist\README.txt
echo - Minimum 4GB RAM >> final_dist\README.txt
echo - 500MB free disk space >> final_dist\README.txt
echo. >> final_dist\README.txt

echo.
echo ========================================
echo FINAL DISTRIBUTION PACKAGE CREATED!
echo ========================================
echo.
echo Location: final_dist\
echo.
echo Files in package:
dir final_dist
echo.
echo ========================================
echo TO TEST:
echo ========================================
echo cd final_dist
echo Launch_Attendance.bat
echo.
echo ========================================
echo TO DISTRIBUTE:
echo ========================================
echo Zip the entire "final_dist" folder and share it.
echo.

pause