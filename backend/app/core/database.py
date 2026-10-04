"""
Database engine, session management, and Base declarative model.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

# SQLite requires check_same_thread=False for FastAPI multi-threaded request handling
connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False  # Set to True for debugging SQL queries
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency that provides a transactional database session per request,
    and guarantees closing the session when done.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
