from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.normalizer.db import Base


JSON_DATA_TYPE = JSON().with_variant(JSONB, "postgresql")


class AlertDB(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    user_identifier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON_DATA_TYPE, nullable=False, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    triage_note: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
