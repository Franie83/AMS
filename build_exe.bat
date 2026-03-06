@echo off
title Build Attendance System with Camera Fix
color 0A

echo ========================================
echo    Building with Camera Fix
echo ========================================
echo.

:: Activate virtual environment
call venv39\Scripts\activate

:: Find models path
python -c "import face_recognition_models; import os; print(os.path.dirname(face_recognition_models.__file__))" > models_path.txt
set /p MODELS_PATH=<models_path.txt
del models_path.txt

echo Models found at: %MODELS_PATH%
echo.

:: Find OpenCV path
python -c "import cv2; import os; print(os.path.dirname(cv2.__file__))" > opencv_path.txt
set /p OPENCV_PATH=<opencv_path.txt
del opencv_path.txt

echo OpenCV path: %OPENCV_PATH%
echo.

:: Clean previous builds
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec

:: Create uploads folder
if not exist uploads mkdir uploads

:: Copy models to a temp folder for inclusion
if exist temp_models rmdir /s /q temp_models
mkdir temp_models
xcopy /E /I "%MODELS_PATH%" "temp_models\face_recognition_models\"

:: Build with spec file
echo.
echo Building executable with camera fixes...
echo.

pyinstaller attendance_fixed.spec

:: Copy OpenCV DLLs manually
if exist "%OPENCV_PATH%" (
    echo Copying OpenCV DLLs to dist folder...
    copy "%OPENCV_PATH%\*.dll" "dist\" 2>nul
)

:: Copy system DLLs for camera
echo Copying system camera DLLs...
copy "C:\Windows\System32\mf.dll" "dist\" 2>nul
copy "C:\Windows\System32\mfplat.dll" "dist\" 2>nul
copy "C:\Windows\System32\mfreadwrite.dll" "dist\" 2>nul

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo    ✅ Build Successful!
    echo ========================================
    echo.
    echo Executable: dist\AttendanceSystem.exe
    
    :: Create run script
    echo @echo off > dist\run.bat
    echo cd /d "%%~dp0" >> dist\run.bat
    echo echo Starting Attendance System... >> dist\run.bat
    echo echo. >> dist\run.bat
    echo echo Access at: http://localhost:5000 >> dist\run.bat
    echo echo. >> dist\run.bat
    echo AttendanceSystem.exe >> dist\run.bat
    echo pause >> dist\run.bat
    
    echo.
    echo Run script created: dist\run.bat
) else (
    echo.
    echo ========================================
    echo    ❌ Build Failed
    echo ========================================
)

:: Clean up temp
if exist temp_models rmdir /s /q temp_models

pause