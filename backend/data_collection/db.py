"""
SQLite database setup via SQLAlchemy.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from data_collection.models import Base

_engine = None
_SessionFactory = None


def init_db(db_path: str):
    """Initialise the database engine and create all tables."""
    global _engine, _SessionFactory

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    _engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(_engine)
    _SessionFactory = scoped_session(sessionmaker(bind=_engine))


def get_session():
    """Return a thread-local database session."""
    if _SessionFactory is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _SessionFactory()
