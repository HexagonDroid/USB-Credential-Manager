@echo off
rem Set the working directory to the folder where the .bat file is located
set "CURRENT_DIR=%~dp0"

rem Define the paths for pythonw.exe and the Python file
set "PYTHONW_EXE=%CURRENT_DIR%python\python\pythonw.exe"
set "PYTHON_FILE=%CURRENT_DIR%python\outpost.py"

rem Check if pythonw.exe exists in the specified folder
if exist "%PYTHONW_EXE%" (
    rem Run outpost.py using pythonw.exe without a terminal window
    start "" "%PYTHONW_EXE%" "%PYTHON_FILE%"
) else (
    echo pythonw.exe not found in the python\python folder.
)

rem Optionally, check if outpost.py exists
if exist "%PYTHON_FILE%" (
    echo Found outpost.py in the python folder.
) else (
    echo outpost.py not found in the python folder.
)
se (
    echo outpost.py not found in the python folder.
)
