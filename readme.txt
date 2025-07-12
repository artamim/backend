python -m venv venv (if venv doesnt exist(it does now))
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload