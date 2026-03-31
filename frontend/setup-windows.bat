@echo off
REM Frontend Setup Script for Windows

echo.
echo ====================================================
echo  Honeypot Dashboard - Frontend Setup
echo ====================================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo Node.js version:
node --version
echo.

echo npm version:
npm --version
echo.

echo Installing dependencies...
call npm install

if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo ====================================================
echo  Setup Complete!
echo ====================================================
echo.
echo To start the development server, run:
echo   npm start
echo.
echo The dashboard will open at http://localhost:3000
echo.
echo Make sure the Flask backend is running at http://localhost:5000
echo.
pause
