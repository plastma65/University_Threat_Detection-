from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from src.api.core.config import settings


engine = create_engine(settings.database_url, echo=False)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, class_=Session)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
