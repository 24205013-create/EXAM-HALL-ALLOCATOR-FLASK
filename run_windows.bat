@echo off
REM Starts the Exam Hall Seat Allocator (needs Python and MongoDB running on localhost:27017)
if not exist venv (
  python -m venv venv
)
call venv\Scripts\activate
pip install -r requirements.txt
python app.py
pause
