# db.py
from flask import current_app, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def get_engine():
    # SQLite database in ./instance/app.db (Flask pattern)
    db_url = "sqlite:///instance/app.db"
    engine = create_engine(db_url, echo=False, future=True)
    return engine

def get_session():
    if "db_session" not in g:
        engine = get_engine()
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
        g.db_session = SessionLocal()
    return g.db_session

def close_session(session=None):
    if session:
        session.close()
    else:
        db_session = g.pop("db_session", None)
        if db_session is not None:
            db_session.close()
