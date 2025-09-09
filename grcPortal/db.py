"""
Database Configuration and Session Management

This module provides database connectivity and session management for the GRC Portal
using SQLAlchemy ORM with Flask application context integration.

Functions:
    get_engine(): Creates and returns SQLAlchemy engine instance
    get_session(): Provides thread-safe database session with Flask g object
    close_session(): Properly closes database sessions to prevent connection leaks
"""

from flask import current_app, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def get_engine():
    """
    Create and configure SQLAlchemy database engine.

    Creates a SQLite engine instance configured for the Flask application pattern.
    The database file is located at ./instance/app.db relative to the application root.

    Returns:
        Engine: SQLAlchemy engine instance configured for SQLite database

    Note:
        Uses future=True for SQLAlchemy 2.0 compatibility
        Echo is disabled to prevent SQL query logging in production
    """
    # SQLite database in ./instance/app.db (Flask pattern)
    db_url = "sqlite:///instance/app.db"
    engine = create_engine(db_url, echo=False, future=True)
    return engine

def get_session():
    """
    Get or create a thread-safe database session using Flask application context.

    Uses Flask's g object to store the session, ensuring each request gets its own
    database session. This prevents session conflicts in multi-threaded environments.

    Returns:
        Session: SQLAlchemy session instance bound to the database engine

    Note:
        Sessions are automatically closed by Flask's teardown handlers
        Autoflush and autocommit are disabled for explicit transaction control
    """
    if "db_session" not in g:
        engine = get_engine()
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
        g.db_session = SessionLocal()
    return g.db_session

def close_session(session=None):
    """
    Properly close database session(s) to prevent connection leaks.

    Can close a specific session or the default session stored in Flask's g object.
    Ensures database connections are returned to the connection pool.

    Args:
        session (Session, optional): Specific session to close. If None, closes
                                   the session stored in Flask g object.

    Note:
        Always call this function or use Flask's teardown handlers to prevent
        database connection exhaustion in production environments.
    """
    if session:
        session.close()
    else:
        db_session = g.pop("db_session", None)
        if db_session is not None:
            db_session.close()
