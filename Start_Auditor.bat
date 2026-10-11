@echo off
echo Starting AI Compliance Auditor...

:: Navigate to the script's directory
cd /d "%~dp0"

:: Start the FastAPI Backend in a new minimized window
start "FastAPI Backend" cmd /k "C:\Users\Austi\.venv\Scripts\activate && uvicorn main:app --reload --port 8000"

:: Start the Streamlit Frontend in a new window
start "Streamlit Frontend" cmd /k "C:\Users\Austi\.venv\Scripts\activate && streamlit run frontend.py"

exit