@echo off
echo ===========================
echo   SECURESHIELD INSTALLER
echo ===========================

REM Step 1: Create virtual environments
echo 🔧 Creating virtual environment...
python -m venv venv

REM Step 2: Activate virtual environment
echo 🔧 Activating virtual environment...
call venv\Scripts\activate.bat

REM Step 3: Upgrade pip and install dependencies
echo 🔧 Installing required packages...
pip install --upgrade pip
pip install -r requirements.txt

REM Step 4: Launch the app
echo ✅ Launching SECURESHIELD GUI App...
python main.py

pause
