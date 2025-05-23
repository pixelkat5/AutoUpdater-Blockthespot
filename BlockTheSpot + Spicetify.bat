@echo off

powershell -Command "& {iwr -useb https://raw.githubusercontent.com/pixelkat5/auto-spicetify/refs/heads/main/install.ps1 | iex}"
powershell -Command "& {iwr -useb https://raw.githubusercontent.com/pixelkat5/auto-marketplace/refs/heads/main/resources/install.ps1 | iex}"
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/pixelkat5/AutoUpdater-Blockthespot/refs/heads/master/install.ps1' | Invoke-Expression}"
pause
exit /b
