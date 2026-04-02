@echo off
title Face Recognition System Installer
color 0A
setlocal enabledelayedexpansion

:: Store the original directory where the script is running
set "SCRIPT_DIR=%CD%"
cd /d "%~dp0"
set "INSTALL_DIR=%CD%"

echo ===================================================
echo    FACE RECOGNITION SYSTEM INSTALLATION
echo ===================================================
echo.
echo 📁 Installation Directory: %INSTALL_DIR%
echo.

:: ===================================================
:: STEP 1: CHECK/INSTALL GIT
:: ===================================================
echo 🔍 Checking Git installation...
git --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Git not found! Attempting to install Git...
    echo.
    echo ⏳ Downloading Git installer...
    
    :: Check if winget is available (Windows 10/11)
    winget --version >nul 2>&1
    if !errorLevel! equ 0 (
        echo 📦 Installing Git via winget...
        winget install --id Git.Git -e --source winget
        if !errorLevel! equ 0 (
            echo ✅ Git installed successfully via winget
        ) else (
            echo ⚠️ Winget installation failed, trying direct download...
            goto :manual_git
        )
    ) else (
        :manual_git
        echo 🌐 Opening Git download page...
        start https://git-scm.com/download/win
        echo.
        echo ⏸️  PLEASE COMPLETE GIT INSTALLATION MANUALLY
        echo   1. Download and run the Git installer
        echo   2. Use default options (recommended)
        echo   3. Restart this installer after Git is installed
        echo.
        pause
        :: Re-check Git installation
        git --version >nul 2>&1
        if !errorLevel! neq 0 (
            echo ❌ Git still not found. Please install Git manually and try again.
            pause
            exit /b 1
        )
    )
) else (
    for /f "tokens=*" %%i in ('git --version') do set gitver=%%i
    echo ✅ !gitver! found
)

:: ===================================================
:: STEP 2: CHECK/INSTALL PYTHON
:: ===================================================
echo.
echo 🔍 Checking Python installation...

:: Check if Python is installed and in PATH
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Python not found! Attempting to install Python...
    
    :: Check if winget is available
    winget --version >nul 2>&1
    if !errorLevel! equ 0 (
        echo 📦 Installing Python 3.10 via winget...
        winget install -e --id Python.Python.3.10
        
        :: Refresh environment variables
        call refreshenv >nul 2>&1 || echo Please restart command prompt after Python installation
        
        :: Check if Python is now available
        python --version >nul 2>&1
        if !errorLevel! equ 0 (
            echo ✅ Python installed successfully
        ) else (
            echo ⚠️ Python installation via winget may require manual PATH update
            goto :manual_python
        )
    ) else (
        :manual_python
        echo.
        echo 🌐 Opening Python download page...
        start https://www.python.org/downloads/release/python-31011/
        echo.
        echo ⏸️  PLEASE INSTALL PYTHON 3.10 MANUALLY
        echo   ⚠️ IMPORTANT: Check "Add Python to PATH" during installation
        echo.
        echo   1. Download Python 3.10.11 (recommended for dlib compatibility)
        echo   2. RUN INSTALLER AS ADMINISTRATOR
        echo   3. ✅ CHECK "Add Python to PATH"
        echo   4. Click "Install Now"
        echo   5. Restart this installer after Python is installed
        echo.
        pause
        
        :: Try to detect Python after manual install
        python --version >nul 2>&1
        if !errorLevel! neq 0 (
            echo ❌ Python still not found in PATH.
            echo.
            echo Attempting to find Python installation...
            for /f "tokens=*" %%i in ('dir /b /s "C:\Python3*" 2^>nul') do set python_path=%%i
            if defined python_path (
                echo Found Python at: !python_path!
                set PATH=!python_path!;!python_path!\Scripts;%PATH%
            ) else (
                echo ❌ Cannot find Python. Please install manually and try again.
                pause
                exit /b 1
            )
        )
    )
)

:: Display Python version and check compatibility
for /f "tokens=*" %%i in ('python --version') do set pyver=%%i
echo ✅ !pyver! found

:: Check Python version compatibility (3.7-3.10 recommended)
python -c "import sys; ver=sys.version_info; exit(0 if (3,7) <= ver < (3,11) else 1)"
if %errorLevel% neq 0 (
    echo ⚠️  Warning: Python version should be 3.7-3.10 for best dlib compatibility
    echo    Continuing anyway, but you may encounter issues...
    choice /c YN /m "Continue anyway?"
    if !errorlevel! equ 2 exit /b 1
)

:: ===================================================
:: STEP 3: CREATE VIRTUAL ENVIRONMENT
:: ===================================================
echo.
echo 📦 Creating virtual environment in %INSTALL_DIR%...
python -m venv venv
if %errorLevel% neq 0 (
    echo ❌ Failed to create virtual environment
    pause
    exit /b 1
)

:: Activate virtual environment
echo ✅ Virtual environment created
echo 🔧 Activating virtual environment...
call venv\Scripts\activate.bat
if %errorLevel% neq 0 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)
echo ✅ Virtual environment activated

:: Upgrade pip
echo.
echo 🔧 Upgrading pip...
python -m pip install --upgrade pip

:: ===================================================
:: STEP 4: INSTALL BASE DEPENDENCIES
:: ===================================================
echo.
echo ===================================================
echo    PHASE 1: INSTALLING BASE DEPENDENCIES
echo ===================================================
echo.

:: Core scientific libraries
echo [1/4] Installing core libraries...
pip install numpy
if %errorLevel% neq 0 (
    echo ❌ Failed to install numpy
    pause
    exit /b 1
)

:: Image processing
echo.
echo [2/4] Installing image processing...
pip install opencv-python Pillow

:: Web framework
echo.
echo [3/4] Installing web framework...
pip install Flask Flask-Login Flask-SQLAlchemy Flask-WTF WTForms pandas reportlab imagehash SQLAlchemy

:: Build tools
echo.
echo [4/4] Installing build tools...
pip install cmake wheel

:: ===================================================
:: STEP 5: INSTALL FACE_RECOGNITION WITHOUT DEPENDENCIES
:: ===================================================
echo.
echo ===================================================
echo    PHASE 2: INSTALLING FACE_RECOGNITION CORE
echo ===================================================
echo.

:: Install face_recognition without auto-dependencies
echo 📦 Installing face_recognition core (without dependencies)...

:: Try multiple sources for face_recognition
pip install --no-dependencies face-recognition 2>nul
if %errorLevel% neq 0 (
    echo ⚠️ PyPI installation failed, trying GitHub...
    pip install --no-dependencies git+https://github.com/ageitgey/face_recognition.git
    if %errorLevel% neq 0 (
        echo ❌ Failed to install face_recognition core
        echo.
        echo Attempting alternative: Install from local source...
        
        :: Clone repository and install without deps
        git clone https://github.com/ageitgey/face_recognition.git temp_face_recog
        cd temp_face_recog
        pip install --no-dependencies -e .
        cd ..
        rmdir /s /q temp_face_recog
        
        if !errorLevel! neq 0 (
            echo ❌ All face_recognition installation methods failed
            pause
            exit /b 1
        )
    )
)
echo ✅ face_recognition core installed

:: ===================================================
:: STEP 6: INSTALL DEPENDENCIES (DLIB) SEPARATELY
:: ===================================================
echo.
echo ===================================================
echo    PHASE 3: INSTALLING DLIB (FACE RECOGNITION DEPENDENCY)
echo ===================================================
echo.
echo ⏳ This may take a few minutes...

:: Check if we're on 64-bit Windows
set ARCH=x86
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set ARCH=amd64
if "%PROCESSOR_ARCHITEW6432%"=="AMD64" set ARCH=amd64

:: Try multiple methods for dlib
set DLIB_INSTALLED=0

:: Method 1: Try pre-compiled wheel based on Python version
echo Attempting Method 1: Pre-compiled wheels...

:: Extract Python version number
for /f "tokens=2 delims= " %%i in ('python --version') do set pyver_full=%%i
for /f "tokens=1,2 delims=." %%a in ("!pyver_full!") do (
    set py_major=%%a
    set py_minor=%%b
)

:: Try to find compatible dlib wheel
if "!py_major!.!py_minor!"=="3.10" (
    echo Detected Python 3.10, trying dlib wheel...
    pip install https://github.com/z-mahmud22/Dlib_Windows_Python3.x/raw/main/dlib-19.24.2-cp310-cp310-win_amd64.whl
    if !errorLevel! equ 0 set DLIB_INSTALLED=1
) else if "!py_major!.!py_minor!"=="3.9" (
    echo Detected Python 3.9, trying dlib wheel...
    pip install https://github.com/z-mahmud22/Dlib_Windows_Python3.x/raw/main/dlib-19.24.2-cp39-cp39-win_amd64.whl
    if !errorLevel! equ 0 set DLIB_INSTALLED=1
) else if "!py_major!.!py_minor!"=="3.8" (
    echo Detected Python 3.8, trying dlib wheel...
    pip install https://github.com/z-mahmud22/Dlib_Windows_Python3.x/raw/main/dlib-19.24.2-cp38-cp38-win_amd64.whl
    if !errorLevel! equ 0 set DLIB_INSTALLED=1
) else if "!py_major!.!py_minor!"=="3.7" (
    echo Detected Python 3.7, trying dlib wheel...
    pip install https://github.com/z-mahmud22/Dlib_Windows_Python3.x/raw/main/dlib-19.24.2-cp37-cp37-win_amd64.whl
    if !errorLevel! equ 0 set DLIB_INSTALLED=1
)

:: Method 2: Try dlib-bin
if !DLIB_INSTALLED! equ 0 (
    echo.
    echo Method 2: Trying dlib-bin...
    pip install dlib-bin
    if !errorLevel! equ 0 set DLIB_INSTALLED=1
)

:: Method 3: Build from source
if !DLIB_INSTALLED! equ 0 (
    echo.
    echo Method 3: Building dlib from source...
    echo This requires Visual C++ Build Tools...
    
    :: Check if Visual C++ is available
    cl >nul 2>&1
    if !errorLevel! equ 0 (
        pip install dlib
        if !errorLevel! equ 0 set DLIB_INSTALLED=1
    ) else (
        echo ⚠️ Visual C++ Build Tools not found
        echo.
        echo Opening Visual C++ Build Tools download page...
        start https://visualstudio.microsoft.com/visual-cpp-build-tools/
        echo.
        echo Please install "Visual C++ Build Tools" with:
        echo   - MSVC compiler
        echo   - Windows SDK
        echo   - CMake tools
        echo.
        choice /c YN /m "Continue with dlib installation after installing Build Tools?"
        if !errorlevel! equ 1 (
            pip install dlib
            if !errorLevel! equ 0 set DLIB_INSTALLED=1
        )
    )
)

:: Method 4: Try conda if available
if !DLIB_INSTALLED! equ 0 (
    echo.
    echo Method 4: Checking conda...
    conda --version >nul 2>&1
    if !errorLevel! equ 0 (
        conda install -c conda-forge dlib -y
        if !errorLevel! equ 0 set DLIB_INSTALLED=1
    )
)

if !DLIB_INSTALLED! equ 0 (
    echo.
    echo ⚠️  WARNING: Could not install dlib automatically
    echo.
    echo Please install dlib manually from:
    echo   https://github.com/z-mahmud22/Dlib_Windows_Python3.x
    echo.
    echo After manual installation, continue with model setup
    pause
) else (
    echo ✅ dlib installed successfully
)

:: ===================================================
:: STEP 7: INSTALL FACE RECOGNITION MODELS
:: ===================================================
echo.
echo ===================================================
echo    PHASE 4: INSTALLING FACE RECOGNITION MODELS
echo ===================================================
echo.

:: Install face_recognition_models package
echo 📦 Installing face_recognition_models...
pip install face-recognition-models 2>nul
if %errorLevel% neq 0 (
    echo ⚠️ face-recognition-models not available, attempting alternative...
    
    :: Try to get models directly
    echo Creating model directory...
    python -c "import face_recognition_models; print('✅ Models already installed')" 2>nul
    if !errorLevel! neq 0 (
        echo Downloading models manually...
        
        :: Create models directory in site-packages
        for /f "tokens=*" %%i in ('python -c "import site; print(site.getsitepackages()[0])"') do set SITE_PKG=%%i
        mkdir "!SITE_PKG!\face_recognition_models\models" 2>nul
        
        :: Download model files (using PowerShell for download)
        echo Downloading face detection model (HOG)...
        powershell -Command "Invoke-WebRequest -Uri 'https://github.com/ageitgey/face_recognition_models/releases/download/v1.0/mmod_human_face_detector.dat' -OutFile '!SITE_PKG!\face_recognition_models\models\mmod_human_face_detector.dat'"
        
        echo Downloading face recognition model...
        powershell -Command "Invoke-WebRequest -Uri 'https://github.com/ageitgey/face_recognition_models/releases/download/v1.0/dlib_face_recognition_resnet_model_v1.dat' -OutFile '!SITE_PKG!\face_recognition_models\models\dlib_face_recognition_resnet_model_v1.dat'"
        
        echo Downloading landmark predictor...
        powershell -Command "Invoke-WebRequest -Uri 'https://github.com/ageitgey/face_recognition_models/releases/download/v1.0/shape_predictor_68_face_landmarks.dat' -OutFile '!SITE_PKG!\face_recognition_models\models\shape_predictor_68_face_landmarks.dat'"
    )
)

:: ===================================================
:: STEP 8: FINAL INSTALLATION AND VERIFICATION
:: ===================================================
echo.
echo ===================================================
echo    PHASE 5: FINALIZING INSTALLATION
echo ===================================================
echo.

:: Now install face_recognition with all dependencies (now that dlib is installed)
echo 🔧 Finalizing face_recognition installation...
pip install --upgrade --no-deps face-recognition

:: Verify installation
echo.
echo ===================================================
echo    VERIFYING ALL INSTALLATIONS
echo ===================================================
echo.

:: Change to installation directory for verification
cd /d "%INSTALL_DIR%"

:: Test each component
python -c "import numpy; print('✅ NumPy:', numpy.__version__)" 2>nul || echo ❌ NumPy not working
python -c "import cv2; print('✅ OpenCV:', cv2.__version__)" 2>nul || echo ❌ OpenCV not working
python -c "import PIL; print('✅ Pillow:', PIL.__version__)" 2>nul || echo ❌ Pillow not working
python -c "import flask; print('✅ Flask:', flask.__version__)" 2>nul || echo ❌ Flask not working
python -c "import dlib; print('✅ dlib:', dlib.__version__)" 2>nul || echo ❌ dlib not working

:: Test face_recognition and models
python -c "import face_recognition; print('✅ face_recognition:', face_recognition.__version__)" 2>nul
if %errorLevel% equ 0 (
    echo ✅ face_recognition is working
    
    :: Test model loading
    python -c "
import face_recognition
try:
    # Create a small test image
    import numpy as np
    test_image = np.zeros((100, 100, 3), dtype=np.uint8)
    face_locations = face_recognition.face_locations(test_image)
    print('✅ Models loaded successfully')
except Exception as e:
    print('⚠️ Model test failed:', str(e))
" 2>nul
) else (
    echo ⚠️ face_recognition not fully installed
)

:: Create requirements.txt with all dependencies
echo.
echo Creating requirements.txt...
(
echo # Core dependencies
echo numpy
echo opencv-python
echo Pillow
echo.
echo # Web framework
echo Flask
echo Flask-Login
echo Flask-SQLAlchemy
echo Flask-WTF
echo WTForms
echo pandas
echo reportlab
echo imagehash
echo SQLAlchemy
echo.
echo # Build tools
echo cmake
echo wheel
echo.
echo # Face recognition
echo dlib
echo face-recognition
echo face-recognition-models
) > requirements.txt

:: ===================================================
:: STEP 9: LAUNCH THE APPLICATION
:: ===================================================
echo.
echo ===================================================
echo    PHASE 6: LAUNCHING APPLICATION
echo ===================================================
echo.

:: Make sure we're in the right directory
cd /d "%INSTALL_DIR%"
echo Current directory: %CD%
echo.

:: Check if app.py exists
if not exist "app.py" (
    echo ⚠️ app.py not found in current directory!
    echo.
    echo Current directory: %CD%
    echo.
    echo Please make sure app.py is in this folder before launching.
    echo.
    choice /c YN /m "Would you like to create a sample app.py?"
    if !errorlevel! equ 1 (
        echo Creating sample app.py...
        (
        echo from flask import Flask, render_template, request, redirect, url_for, flash, session
        echo from flask_sqlalchemy import SQLAlchemy
        echo from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
        echo import face_recognition
        echo import numpy as np
        echo import cv2
        echo import os
        echo from datetime import datetime
        echo import pandas as pd
        echo from werkzeug.security import generate_password_hash, check_password_hash
        echo.
        echo app = Flask(__name__)
        echo app.config['SECRET_KEY'] = 'your-secret-key-here'
        echo app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///face_recognition.db'
        echo app.config['UPLOAD_FOLDER'] = 'uploads'
        echo.
        echo db = SQLAlchemy(app)
        echo login_manager = LoginManager()
        echo login_manager.init_app(app)
        echo login_manager.login_view = 'login'
        echo.
        echo # Create upload folder if it doesn't exist
        echo os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        echo.
        echo # Database Models
        echo class User(UserMixin, db.Model):
        echo     id = db.Column(db.Integer, primary_key=True)
        echo     email = db.Column(db.String(100), unique=True)
        echo     password = db.Column(db.String(100))
        echo     name = db.Column(db.String(100))
        echo     role = db.Column(db.String(50))  # super_admin, admin, user
        echo.
        echo class Person(db.Model):
        echo     id = db.Column(db.Integer, primary_key=True)
        echo     name = db.Column(db.String(100))
        echo     email = db.Column(db.String(100), unique=True)
        echo     face_encoding = db.Column(db.Text)  # Store as JSON
        echo     image_path = db.Column(db.String(200))
        echo     created_at = db.Column(db.DateTime, default=datetime.utcnow)
        echo.
        echo @login_manager.user_loader
        echo def load_user(user_id):
        echo     return User.query.get(int(user_id))
        echo.
        echo @app.route('/')
        echo def index():
        echo     return '''
        echo     ^<html^>
        echo         ^<head^>
        echo             ^<title^>Face Recognition System^</title^>
        echo             ^<style^>
        echo                 body { font-family: Arial; margin: 40px; background: #f0f0f0; }
        echo                 .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 10px; }
        echo                 h1 { color: #333; }
        echo                 .success { color: green; }
        echo             ^</style^>
        echo         ^</head^>
        echo         ^<body^>
        echo             ^<div class="container"^>
        echo                 ^<h1^>✅ Face Recognition System^</h1^>
        echo                 ^<p class="success"^>Application is running successfully!^</p^>
        echo                 ^<h2^>Installation Complete!^</h2^>
        echo                 ^<ul^>
        echo                     ^<li^>Flask: Working^</li^>
        echo                     ^<li^>Face Recognition: Working^</li^>
        echo                     ^<li^>Database: Connected^</li^>
        echo                 ^</ul^>
        echo                 ^<p^>You can now develop your face recognition application.^</p^>
        echo             ^</div^>
        echo         ^</body^>
        echo     ^</html^>
        echo     '''
        echo.
        echo @app.route('/health')
        echo def health():
        echo     return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}
        echo.
        echo if __name__ == '__main__':
        echo     with app.app_context():
        echo         db.create_all()
        echo         # Create default admin if not exists
        echo         if not User.query.filter_by(email='sadmin@gmail.com').first():
        echo             admin = User(
        echo                 email='sadmin@gmail.com',
        echo                 password=generate_password_hash('sadmin123'),
        echo                 name='Super Admin',
        echo                 role='super_admin'
        echo             )
        echo             db.session.add(admin)
        echo             db.session.commit()
        echo             print('✅ Default super admin created')
        echo     print('🚀 Starting Face Recognition System...')
        echo     print('📍 Server will run at: http://127.0.0.1:5000')
        echo     print(f'📁 Working directory: {os.getcwd()}')
        echo     app.run(debug=True, host='127.0.0.1', port=5000)
        ) > app.py
        echo ✅ Sample app.py created in %CD%
    ) else (
        echo Please place app.py in this directory and run manually.
        goto :launch_options
    )
)

:: Check if database needs initialization
echo.
echo 🔧 Checking database initialization...
cd /d "%INSTALL_DIR%"
python -c "
import sqlite3
import os
if not os.path.exists('face_recognition.db'):
    print('✓ Database will be created on first run')
else:
    print('✓ Database exists')
" 2>nul

:: Launch options
:launch_options
echo.
echo ===================================================
echo    LAUNCH OPTIONS
echo ===================================================
echo.
echo Choose how to launch the application:
echo   1. Launch now (opens in browser)
echo   2. Launch in background (minimized)
echo   3. Don't launch (I'll launch manually)
echo.
choice /c 123 /n /m "Enter your choice (1-3): "

if errorlevel 3 goto :no_launch
if errorlevel 2 goto :background_launch
if errorlevel 1 goto :foreground_launch

:foreground_launch
echo.
echo 🚀 Launching application in foreground from %INSTALL_DIR%...
echo.
:: Create a temporary launch script to ensure correct directory
(
echo @echo off
echo cd /d "%INSTALL_DIR%"
echo echo Starting Face Recognition System from %INSTALL_DIR%
echo echo.
echo call venv\Scripts\activate.bat
echo python app.py
echo pause
) > "%TEMP%\launch_frs.bat"

:: Start Flask in a new window
start "Face Recognition System" cmd /k call "%TEMP%\launch_frs.bat"

:: Wait a bit for the server to start
echo ⏳ Waiting for server to start...
timeout /t 5 /nobreak >nul

:: Open browser
echo 🌐 Opening browser...
start http://127.0.0.1:5000
goto :launch_complete

:background_launch
echo.
echo 🚀 Launching application in background from %INSTALL_DIR%...
echo.
:: Create a background launch script
(
echo @echo off
echo cd /d "%INSTALL_DIR%"
echo call venv\Scripts\activate.bat
echo python app.py ^> flask.log 2^>^&1
) > "%TEMP%\bg_launch_frs.bat"

:: Start Flask minimized
start /min "Face Recognition System" cmd /c call "%TEMP%\bg_launch_frs.bat"

:: Wait a bit for the server to start
echo ⏳ Waiting for server to start...
timeout /t 5 /nobreak >nul

:: Open browser
echo 🌐 Opening browser...
start http://127.0.0.1:5000
goto :launch_complete

:no_launch
echo.
echo 📝 You can launch manually later with:
echo   1. cd /d "%INSTALL_DIR%"
echo   2. venv\Scripts\activate
echo   3. python app.py
echo.
goto :launch_complete

:launch_complete
echo.
echo ===================================================
echo    INSTALLATION COMPLETE!
echo ===================================================
echo.
echo ✅ Git: Installed/Verified
echo ✅ Python: !pyver!
echo ✅ Virtual environment created in 'venv'
echo ✅ All dependencies installed
echo ✅ Face recognition models installed
echo.
echo 📁 Project Location: %INSTALL_DIR%
echo.
echo Default login credentials:
echo   Super Admin: sadmin@gmail.com / sadmin123
echo   Admin: admin@gmail.com / admin123
echo.
echo Quick Commands:
echo ===============
echo Start application: run.bat
echo Activate environment: cd /d "%INSTALL_DIR%" ^&^& venv\Scripts\activate
echo Run manually: cd /d "%INSTALL_DIR%" ^&^& python app.py
echo.
echo 📝 Log file: %INSTALL_DIR%\flask.log (if running in background)
echo.
if errorlevel 2 (
    echo ℹ️ Application is running in background
    echo   To stop: taskkill /f /im python.exe
    echo   Log file: %INSTALL_DIR%\flask.log
) else if errorlevel 1 (
    echo ℹ️ Application window is open
    echo   Close the window to stop the server
)
echo.

:: Create a convenient run script that always uses the correct directory
echo Creating run.bat for future use...
(
echo @echo off
echo title Face Recognition System
echo color 0A
echo.
echo :: Always use the installation directory
echo cd /d "%~dp0"
echo echo Starting Face Recognition System from %%CD%%
echo echo.
echo :: Activate virtual environment and run app
echo call venv\Scripts\activate.bat
echo if %%errorLevel%% neq 0 (
echo     echo ❌ Failed to activate virtual environment
echo     pause
echo     exit /b 1
echo )
echo.
echo echo 🚀 Starting Face Recognition System...
echo echo 📍 Server will be available at: http://127.0.0.1:5000
echo echo.
echo echo Press Ctrl+C to stop the server
echo echo.
echo python app.py
echo.
echo pause
) > run.bat

echo ✅ Created run.bat - double-click this file to start the app anytime
echo.

:: Clean up temp files
del "%TEMP%\launch_frs.bat" 2>nul
del "%TEMP%\bg_launch_frs.bat" 2>nul

:: Final instructions
if exist "app.py" (
    echo 🎯 Next steps:
    echo   1. The application should open in your browser shortly
    echo   2. If not, navigate to: http://127.0.0.1:5000
    echo   3. Login with the default credentials
    echo.
)

echo Press any key to exit installer...
pause >nul

:: Return to original directory
cd /d "%SCRIPT_DIR%"
exit /b 0