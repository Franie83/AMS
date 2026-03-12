@echo off
title Face Recognition System Installer
color 0A
echo ===================================================
echo    FACE RECOGNITION SYSTEM INSTALLATION
echo ===================================================
echo.

:: Check Python installation
echo 🔍 Checking Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Python not found! Please install Python 3.7-3.10
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Display Python version
for /f "tokens=*" %%i in ('python --version') do set pyver=%%i
echo ✅ %pyver% found

:: Create virtual environment
echo.
echo 📦 Creating virtual environment...
python -m venv venv
if %errorLevel% neq 0 (
    echo ❌ Failed to create virtual environment
    pause
    exit /b 1
)

:: Activate virtual environment
call venv\Scripts\activate.bat
echo ✅ Virtual environment activated

:: Upgrade pip
echo.
echo 🔧 Upgrading pip...
python -m pip install --upgrade pip

echo.
echo ===================================================
echo    PHASE 1: INSTALLING CORE DEPENDENCIES
echo ===================================================
echo.

:: ===== STEP 1: Core Scientific Libraries =====
echo [1/4] Installing core scientific libraries...
pip install numpy
if %errorLevel% neq 0 (
    echo ❌ Failed to install numpy
    pause
    exit /b 1
)
echo ✅ NumPy installed

:: ===== STEP 2: Image Processing =====
echo.
echo [2/4] Installing image processing libraries...
pip install Pillow
pip install opencv-python
echo ✅ Image processing libraries installed

:: ===== STEP 3: Web Framework & Database =====
echo.
echo [3/4] Installing web framework and database libraries...
pip install Flask
pip install Flask-Login
pip install Flask-SQLAlchemy
pip install Flask-WTF
pip install WTForms
pip install pandas
pip install reportlab
pip install imagehash
pip install SQLAlchemy
echo ✅ Web framework installed

:: ===== STEP 4: Build Tools (if needed for dlib) =====
echo.
echo [4/4] Installing build tools (if needed)...
pip install cmake
pip install wheel
echo ✅ Build tools installed

echo.
echo ===================================================
echo    PHASE 2: INSTALLING FACE RECOGNITION
echo ===================================================
echo.
echo ⏳ This may take a few minutes...

:: Try multiple methods for dlib/face_recognition

:: Method 1: Try dlib-bin first (easiest on Windows)
echo.
echo Attempting Method 1: dlib-bin (pre-compiled)...
pip install dlib-bin
if %errorLevel% equ 0 (
    echo ✅ dlib-bin installed successfully
    goto :install_face_recognition
)

:: Method 2: If dlib-bin fails, try building dlib
echo.
echo Method 1 failed. Attempting Method 2: Building dlib...
pip install dlib
if %errorLevel% equ 0 (
    echo ✅ dlib installed successfully
    goto :install_face_recognition
)

:: Method 3: Try specific wheel for Python version
echo.
echo Method 2 failed. Attempting Method 3: Installing from wheel...
if "%pyver%"=="Python 3.10" (
    echo Detected Python 3.10, trying compatible wheel...
    pip install https://github.com/z-mahmud22/Dlib_Windows_Python3.x/raw/main/dlib-19.24.2-cp310-cp310-win_amd64.whl
    if %errorLevel% equ 0 (
        echo ✅ dlib wheel installed successfully
        goto :install_face_recognition
    )
)

:: Method 4: Try conda if available
echo.
echo Checking if conda is available...
conda --version >nul 2>&1
if %errorLevel% equ 0 (
    echo ✅ Conda found, installing dlib via conda...
    conda install -c conda-forge dlib -y
    if %errorLevel% equ 0 (
        echo ✅ dlib installed via conda
        goto :install_face_recognition
    )
)

:: If we get here, dlib installation failed
echo.
echo ⚠️  WARNING: Could not install dlib automatically
echo.
echo Please install dlib manually from one of these sources:
echo 1. https://github.com/z-mahmud22/Dlib_Windows_Python3.x
echo 2. Using conda: conda install -c conda-forge dlib
echo 3. Install Visual C++ Build Tools and run: pip install dlib
echo.
echo After installing dlib manually, run this script again.
pause
exit /b 1

:install_face_recognition
:: ===== STEP 5: Install face_recognition =====
echo.
echo ===================================================
echo    PHASE 3: INSTALLING FACE RECOGNITION LIBRARY
echo ===================================================
echo.

:: Install face_recognition (this will automatically pull the models)
echo Installing face_recognition...
pip install face-recognition

if %errorLevel% equ 0 (
    echo ✅ face_recognition installed successfully
) else (
    echo ⚠️  face_recognition installation failed, trying GitHub version...
    pip install git+https://github.com/ageitgey/face_recognition.git
    if %errorLevel% equ 0 (
        echo ✅ face_recognition installed from GitHub
    ) else (
        echo ❌ face_recognition installation failed
        echo You may need to install it manually
    )
)

:: ===== STEP 6: Verify face_recognition_models =====
echo.
echo ===================================================
echo    PHASE 4: VERIFYING MODELS
echo ===================================================
echo.

:: face_recognition_models should have been installed automatically
echo Checking face_recognition_models installation...
python -c "import face_recognition_models; print('✅ face_recognition_models:', face_recognition_models.__file__)" 2>nul
if %errorLevel% equ 0 (
    echo ✅ face_recognition_models is installed
) else (
    echo Installing face_recognition_models manually...
    pip install face-recognition-models
)

:: Final verification
echo.
echo ===================================================
echo    VERIFYING ALL INSTALLATIONS
echo ===================================================
echo.

python -c "import numpy; print('✅ NumPy:', numpy.__version__)" 2>nul || echo ❌ NumPy not working
python -c "import cv2; print('✅ OpenCV:', cv2.__version__)" 2>nul || echo ❌ OpenCV not working
python -c "import PIL; print('✅ Pillow:', PIL.__version__)" 2>nul || echo ❌ Pillow not working
python -c "import flask; print('✅ Flask:', flask.__version__)" 2>nul || echo ❌ Flask not working

:: Test face_recognition and models
python -c "import face_recognition; print('✅ face_recognition:', face_recognition.__version__)" 2>nul
if %errorLevel% equ 0 (
    echo ✅ face_recognition is working
    python -c "from face_recognition import face_locations; print('✅ face_recognition functions available')" 2>nul
) else (
    echo ⚠️  face_recognition not fully installed
)

:: Create requirements.txt
echo.
echo Creating requirements.txt...
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
echo cmake
echo dlib
echo face-recognition
) > requirements.txt

echo.
echo ===================================================
echo    INSTALLATION COMPLETE!
echo ===================================================
echo.
echo ✅ Virtual environment created in 'venv' folder
echo ✅ All core dependencies installed
echo ✅ face_recognition and models installed
echo ✅ requirements.txt created
echo.
echo To activate the environment:
echo   venv\Scripts\activate
echo.
echo To run the application:
echo   python app.py
echo.
echo Default login credentials:
echo   Super Admin: sadmin@gmail.com / sadmin123
echo   Admin: admin@gmail.com / admin123
echo.
echo If you see any warnings above, you may need to:
echo   1. Install Visual C++ Build Tools
echo   2. Download dlib wheel from GitHub
echo   3. Run: pip install -r requirements.txt
echo.
pause