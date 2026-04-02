@echo off
echo ========================================
echo Downloading Offline Assets
echo ========================================
echo.

REM Create directories
mkdir static\css 2>nul
mkdir static\js 2>nul
mkdir static\webfonts 2>nul

REM Download Bootstrap CSS
echo Downloading Bootstrap CSS...
curl -o static\css\bootstrap.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css

REM Download Bootstrap JS
echo Downloading Bootstrap JS...
curl -o static\js\bootstrap.bundle.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js

REM Download Font Awesome CSS
echo Downloading Font Awesome CSS...
curl -o static\css\all.min.css https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css

REM Download Font Awesome Web Fonts
echo Downloading Font Awesome Web Fonts...
curl -o static\webfonts\fa-solid-900.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-solid-900.woff2
curl -o static\webfonts\fa-regular-400.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-regular-400.woff2
curl -o static\webfonts\fa-brands-400.woff2 https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-brands-400.woff2

echo.
echo ========================================
echo All assets downloaded successfully!
echo ========================================
echo.
echo You can now run the application offline.
pause