import sys
sys.path.append('.')

from app import create_app
from db import get_session
from models import ValidationProcedure

try:
    app = create_app()
    with app.app_context():
        session = get_session()
        count = session.query(ValidationProcedure).count()
        print(f"Validation procedures count: {count}")

        if count > 0:
            validations = session.query(ValidationProcedure).all()
            for v in validations:
                print(f"ID: {v.id}, Name: {v.procedure_name}")
        else:
            print("No validation procedures found.")

        session.close()
except Exception as e:
    print(f"Error: {e}")