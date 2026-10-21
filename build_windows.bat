@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Python 3.12 or newer is required on PATH.
  exit /b 1
)

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install "pyinstaller>=6.3"

python -m PyInstaller --noconfirm --clean --windowed --name StalkerPortalInspector --paths . --add-data "config;config" --hidden-import keyring.backends.Windows --collect-submodules keyring.backends main.py

if errorlevel 1 (
  echo The Windows build failed.
  exit /b 1
)

echo.
echo Built dist\StalkerPortalInspector\StalkerPortalInspector.exe
echo Settings and logs are stored under %%APPDATA%%\StalkerPortalInspector
echo Passwords and tokens are stored in Windows Credential Manager, not next to the executable.
endlocal
