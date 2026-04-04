@echo off
title AMS - Complete One-Click Setup
color 0A
setlocal enabledelayedexpansion

:: Get the script's directory
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ================================================================================
echo              ATTENDANCE MANAGEMENT SYSTEM - ONE CLICK SETUP
echo ================================================================================
echo.
echo This installer will do everything automatically:
echo   1. Install Python 3.10 (if not present)
echo   2. Create virtual environment with system packages access
echo   3. Install all dependencies from local files
echo   4. Launch the application
echo.
echo No internet connection required!
echo.
pause

:: ================================================================================
:: STEP 1: CHECK/INSTALL PYTHON
:: ================================================================================
echo.
echo [1/6] Checking Python installation...

set "PYTHON_EXE="

:: Check common Python 3.10 locations
if exist "C:\Program Files\Python310\python.exe" (
    set "PYTHON_EXE=C:\Program Files\Python310\python.exe"
    goto :python_found
)
if exist "C:\Python310\python.exe" (
    set "PYTHON_EXE=C:\Python310\python.exe"
    goto :python_found
)
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    goto :python_found
)

:: Check PATH
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%i in ('where python') do (
        set "PYTHON_EXE=%%i"
        goto :python_found
    )
)

:: Install Python if not found
echo Python 3.10 not found. Installing...
if exist "%SCRIPT_DIR%python-3.10.0-amd64.exe" (
    echo Installing Python 3.10.0 (silent install)...
    start /wait "%SCRIPT_DIR%python-3.10.0-amd64.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    set "PYTHON_EXE=C:\Program Files\Python310\python.exe"
    echo ✅ Python installed
) else (
    echo ❌ python-3.10.0-amd64.exe not found!
    echo Please ensure the Python installer is in the same folder.
    pause
    exit /b 1
)

:python_found
echo ✅ Python found: !PYTHON_EXE!
"!PYTHON_EXE!" --version

:: ================================================================================
:: STEP 2: CREATE VIRTUAL ENVIRONMENT WITH SYSTEM PACKAGES
:: ================================================================================
echo.
echo [2/6] Creating virtual environment (with system packages access)...

if exist "%SCRIPT_DIR%venv" (
    echo Removing old virtual environment...
    rmdir /s /q "%SCRIPT_DIR%venv"
)

:: This is the KEY - --system-site-packages allows access to installed packages
"!PYTHON_EXE!" -m venv "%SCRIPT_DIR%venv" --system-site-packages

if not exist "%SCRIPT_DIR%venv\Scripts\python.exe" (
    echo ❌ Failed to create virtual environment!
    pause
    exit /b 1
)
echo ✅ Virtual environment created with system packages access

:: ================================================================================
:: STEP 3: ACTIVATE VIRTUAL ENVIRONMENT
:: ================================================================================
echo.
echo [3/6] Activating virtual environment...

call "%SCRIPT_DIR%venv\Scripts\activate.bat"
echo ✅ Virtual environment activated

:: ================================================================================
:: STEP 4: UPGRADE PIP
:: ================================================================================
echo.
echo [4/6] Upgrading pip...

python -m pip install --upgrade pip --no-cache-dir
echo ✅ Pip upgraded

:: ================================================================================
:: STEP 5: INSTALL REQUIRED PACKAGES
:: ================================================================================
echo.
echo [5/6] Installing required packages...

:: Install core packages (if not already in system)
echo Installing Flask and extensions...
pip install Flask Flask-Login Flask-SQLAlchemy --no-cache-dir

:: Install Flask-WTF and WTForms (critical for your app)
echo Installing Flask-WTF and WTForms...
pip install Flask-WTF WTForms --no-cache-dir

:: Install image processing packages
echo Installing image processing packages...
pip install opencv-python Pillow numpy --no-cache-dir

:: Install face recognition
echo Installing face recognition...
pip install dlib face-recognition --no-cache-dir

:: Install data processing packages
echo Installing data processing packages...
pip install pandas reportlab imagehash scipy --no-cache-dir

:: Install from local wheel files if available (for offline)
if exist "%SCRIPT_DIR%offline_packages" (
    echo Installing additional packages from local wheels...
    pip install --no-index --find-links=offline_packages dlib_bin face_recognition_models 2>nul
)

echo ✅ All packages installed

:: ================================================================================
:: STEP 6: VERIFY AND LAUNCH
:: ================================================================================
echo.
echo [6/6] Verifying installation...

echo.
python -c "import flask; print('   ✅ Flask')" 2>nul
python -c "import flask_wtf; print('   ✅ Flask-WTF')" 2>nul
python -c "import cv2; print('   ✅ OpenCV')" 2>nul
python -c "import dlib; print('   ✅ dlib')" 2>nul
python -c "import face_recognition; print('   ✅ face_recognition')" 2>nul

echo.
echo ================================================================================
echo    SETUP COMPLETE! STARTING ATTENDANCE MANAGEMENT SYSTEM...
echo ================================================================================
echo.
echo Server will start at: http://127.0.0.1:5000
echo Press Ctrl+C to stop the server
echo.

:: Launch the application
python run.py

pause
exit /b 0