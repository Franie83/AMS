@echo off
title Face Recognition System Installer
color 0A
setlocal

echo ===================================================
echo    FACE RECOGNITION SYSTEM INSTALLER
echo ===================================================
echo.

:: ===================================================
:: STEP 1: PYTHON + VENV
:: ===================================================
echo [1/6] Setting up Python environment...

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found. Install Python 3.10 first.
    pause
    exit /b 1
)

if exist venv (
    echo ✅ Virtual environment exists
) else (
    echo 📦 Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate
echo ✅ Virtual environment activated

python -m pip install --upgrade pip

:: ===================================================
:: STEP 2: INSTALL CORE PACKAGES
:: ===================================================
echo.
echo [2/6] Installing core packages...

pip install dlib-bin
if %errorlevel% neq 0 (
    echo ❌ Failed to install dlib-bin
    pause
    exit /b 1
)

pip install face-recognition --no-deps
pip install face-recognition-models

:: ===================================================
:: STEP 3: INSTALL OTHER DEPENDENCIES
:: ===================================================
echo.
echo [3/6] Installing dependencies...

pip install ^
numpy ^
opencv-python ^
Pillow ^
Flask ^
Flask-Login ^
Flask-SQLAlchemy ^
Flask-WTF ^
WTForms ^
pandas ^
reportlab ^
imagehash ^
SQLAlchemy ^
click ^
itsdangerous ^
Jinja2 ^
MarkupSafe ^
Werkzeug ^
python-dateutil ^
pytz ^
six ^
typing-extensions ^
colorama ^
blinker ^
greenlet ^
scipy ^
PyWavelets ^
tzdata

if %errorlevel% neq 0 (
    echo ⚠️ Some packages failed, continuing...
)

:: ===================================================
:: STEP 4: CREATE REQUIREMENTS FILE
:: ===================================================
echo.
echo [4/6] Creating clean requirements.txt...

(
echo numpy
echo opencv-python
echo Pillow
echo Flask
echo Flask-Login
echo Flask-SQLAlchemy
echo Flask-WTF
echo WTForms
echo pandas
echo reportlab
echo imagehash
echo SQLAlchemy
echo dlib-bin
echo face-recognition
echo face-recognition-models
echo click
echo itsdangerous
echo Jinja2
echo MarkupSafe
echo Werkzeug
echo python-dateutil
echo pytz
echo six
echo typing-extensions
echo colorama
echo blinker
echo greenlet
echo scipy
echo PyWavelets
echo tzdata
) > requirements.txt

echo ✅ requirements.txt created

:: ===================================================
:: STEP 5: VERIFY INSTALLATION
:: ===================================================
echo.
echo [5/6] Verifying installation...

python -c "import dlib, face_recognition, flask, cv2, numpy, PIL; print('✅ ALL PACKAGES OK')" 
if %errorlevel% neq 0 (
    echo ❌ Verification failed
    pause
    exit /b 1
)

:: ===================================================
:: STEP 6: CREATE RUN SCRIPT
:: ===================================================
echo.
echo [6/6] Creating run script...

(
echo @echo off
echo cd /d "%%~dp0"
echo call venv\Scripts\activate
echo echo Starting Face Recognition System...
echo echo http://127.0.0.1:5000
echo python app.py
echo pause
) > run.bat

echo ✅ run.bat created

:: ===================================================
:: DONE
:: ===================================================
echo.
echo ===================================================
echo    INSTALLATION COMPLETE
echo ===================================================
echo.
echo Run your app:
echo    run.bat
echo.

pause
exit /b 0