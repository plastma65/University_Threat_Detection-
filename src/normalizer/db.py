"""
Database Integration (Step 13)

SQLAlchemy 2.0+ model for NormalizedLog with PostgreSQL integration.
Implements batch upsert with ON CONFLICT for idempotency.
"""

import os
from typing import List, Optional

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.types import String, DateTime
from sqlalchemy.dialects.postgresql import JSONB, insert
import json

from .schemas import NormalizedLog, LogSource

# Load environment variables
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
# Allow DATABASE_URL to be None for testing purposes
# It will be validated when actually creating engine


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""
    pass


class NormalizedLogDB(Base):
    """
    SQLAlchemy model for NormalizedLog.
    
    Matches ULM 100% with log_id as Primary Key for idempotency.
    """
    
    __tablename__ = "normalized_logs"
    
    # log_id is Primary Key (SHA256 hash, 64 hex chars)
    log_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    
    # ISO8601 formatted timestamp
    timestamp: Mapped[str] = mapped_column(String(50), index=True)
    
    # Log source type (enum value stored as string)
    source: Mapped[str] = mapped_column(String(20), index=True)
    
    # IP address (nullable)
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    
    # Username (nullable, may be masked/hashed)
    user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Event category
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    
    # Original log line with PII masked
    raw: Mapped[str] = mapped_column(String(5000))
    
    # Source-specific additional fields (JSONB for PostgreSQL)
    log_metadata: Mapped[dict] = mapped_column(JSONB, default={})
    
    def to_pydantic(self) -> NormalizedLog:
        """Convert SQLAlchemy model to Pydantic NormalizedLog."""
        source_enum = LogSource(self.source)
        return NormalizedLog(
            log_id=self.log_id,
            timestamp=self.timestamp,
            source=source_enum,
            ip=self.ip,
            user=self.user,
            event_type=self.event_type,
            raw=self.raw,
            metadata=self.log_metadata
        )
    
    @classmethod
    def from_pydantic(cls, log: NormalizedLog) -> "NormalizedLogDB":
        """Convert Pydantic NormalizedLog to SQLAlchemy model."""
        return cls(
            log_id=log.log_id,
            timestamp=log.timestamp,
            source=log.source.value if isinstance(log.source, LogSource) else log.source,
            ip=log.ip,
            user=log.user,
            event_type=log.event_type,
            raw=log.raw,
            log_metadata=log.metadata
        )


def get_engine():
    """Get SQLAlchemy engine from DATABASE_URL."""
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL not found in environment variables. Please set it in .env file.")
    return create_engine(DATABASE_URL, echo=False)


def create_tables():
    """Create all tables in the database."""
    engine = get_engine()
    Base.metadata.create_all(engine)


def batch_upsert(logs: List[NormalizedLog], batch_size: int = 1000) -> int:
    """
    Batch upsert logs to PostgreSQL using ON CONFLICT DO NOTHING.
    
    This ensures idempotency - duplicate log_id values are ignored.
    
    Args:
        logs: List of NormalizedLog objects
        batch_size: Number of records per batch (default 1000)
        
    Returns:
        Number of records successfully inserted
    """
    if not logs:
        return 0
    
    engine = get_engine()
    inserted_count = 0
    
    # Process in batches to avoid memory issues
    for i in range(0, len(logs), batch_size):
        batch = logs[i:i + batch_size]
        
        # Convert to SQLAlchemy models
        db_logs = [NormalizedLogDB.from_pydantic(log) for log in batch]
        
        with Session(engine) as session:
            try:
                # Build insert statement
                stmt = insert(NormalizedLogDB).values([
                    {
                        "log_id": log.log_id,
                        "timestamp": log.timestamp,
                        "source": log.source,
                        "ip": log.ip,
                        "user": log.user,
                        "event_type": log.event_type,
                        "raw": log.raw,
                        "log_metadata": log.log_metadata
                    }
                    for log in db_logs
                ])
                
                # Add ON CONFLICT DO NOTHING for idempotency
                stmt = stmt.on_conflict_do_nothing(index_elements=["log_id"])
                
                # Execute
                result = session.execute(stmt)
                session.commit()
                
                inserted_count += result.rowcount
                
            except Exception as e:
                session.rollback()
                raise e
    
    return inserted_count


def get_sample_logs(limit: int = 3, source: Optional[str] = None) -> List[dict]:
    """
    Retrieve sample logs from database for verification.
    
    Args:
        limit: Maximum number of records to retrieve
        source: Optional filter by source
        
    Returns:
        List of dictionaries representing log records
    """
    engine = get_engine()
    
    with Session(engine) as session:
        query = session.query(NormalizedLogDB)
        
        if source:
            query = query.filter(NormalizedLogDB.source == source)
        
        logs = query.order_by(NormalizedLogDB.timestamp).limit(limit).all()
        
        return [
            {
                "log_id": log.log_id,
                "timestamp": log.timestamp,
                "source": log.source,
                "ip": log.ip,
                "user": log.user,
                "event_type": log.event_type,
                "raw": log.raw[:100] + "..." if len(log.raw) > 100 else log.raw,
                "metadata": log.log_metadata
            }
            for log in logs
        ]


def get_log_count(source: Optional[str] = None) -> int:
    """
    Get total count of logs in database.
    
    Args:
        source: Optional filter by source
        
    Returns:
        Total count of logs
    """
    engine = get_engine()
    
    with Session(engine) as session:
        query = session.query(NormalizedLogDB)
        
        if source:
            query = query.filter(NormalizedLogDB.source == source)
        
        return query.count()
