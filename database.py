# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# URL encode the dot in the password
DATABASE_URL = "postgresql+psycopg2://postgres:bdupassword%2E@localhost:5432/postgres"

engine = create_engine(
    DATABASE_URL,
    echo=True,          # show SQL queries in terminal
    pool_pre_ping=True
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()