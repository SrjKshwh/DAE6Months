#!/usr/bin/env python3
"""
Script to recreate the database with current models
"""

from sqlalchemy import create_engine
from models import Base
import os

# Database setup
DATABASE_URL = 'sqlite:///grc_portal.db'
engine = create_engine(DATABASE_URL, echo=True)

def recreate_database():
    """Drop all tables and recreate them"""
    print("Dropping all tables...")
    Base.metadata.drop_all(bind=engine)

    print("Creating all tables...")
    Base.metadata.create_all(bind=engine)

    print("Database recreated successfully!")

if __name__ == "__main__":
    recreate_database()