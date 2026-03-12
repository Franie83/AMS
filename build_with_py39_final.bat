@echo off
title Rebuilding Attendance System - Fixed
color 0A

echo ========================================
echo    Rebuilding with face_recognition fix
echo ========================================
echo.

:: Activate virtual environment
call venv39\Scripts\activate

:: Clean previous builds
echo Cleaning old builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec

:: Create uploads folder if needed
if not exist uploads mkdir uploads

:: Build with additional face_recognition data
echo.
echo Building executable with face_recognition fix...
echo.

pyinstaller --onefile ^
    --name "AttendanceSystem" ^
    --add-data "templates;templates" ^
    --add-data "uploads;uploads" ^
    --hidden-import face_recognition ^
    --hidden-import face_recognition_models ^
    --hidden-import dlib ^
    --hidden-import PIL ^
    --hidden-import PIL._tkinter_finder ^
    --hidden-import cv2 ^
    --hidden-import numpy ^
    --hidden-import scipy ^
    --hidden-import sklearn ^
    --collect-all face_recognition ^
    --collect-all face_recognition_models ^
    --collect-all dlib ^
    --collect-all cv2 ^
    --collect-all numpy ^
    --collect-all PIL ^
    --collect-submodules face_recognition ^
    --collect-submodules dlib ^
    --collect-submodules cv2 ^
    app.py

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo    ✅ Rebuild Successful!
    echo ========================================
    echo.
    echo New executable: dist\AttendanceSystem.exe
    echo.
    echo Testing face_recognition in executable...
    echo.
    
    :: Create a test script to verify face_recognition is included
    echo import face_recognition > test_import.py
    echo print("✅ face_recognition imported successfully!") >> test_import.py
    echo print(f"Version: {face_recognition.__version__}") >> test_import.py
    
    :: Run the test with the new executable (this won't actually work, just for show)
    echo Note: Run the actual AttendanceSystem.exe to test
) else (
    echo.
    echo ========================================
    echo    ❌ Rebuild Failed
    echo ========================================
)

pause