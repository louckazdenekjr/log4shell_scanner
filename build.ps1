./venv/Scripts/activate
pyinstaller --add-data 'icon.ico;.' --icon=icon.ico --onefile log4shell_scanner.pyw
sleep 5