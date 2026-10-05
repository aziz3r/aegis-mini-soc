"""Database schema and session management.

SQLite by default so the whole stack starts with one command and no daemon;
`AEGIS_DATABASE_URL=postgresql+psycopg://...` switches to Postgres without a
code change. Nothing in the schema is SQLite-specific.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, create_engine, event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from aegis.config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------- domain model

class Incident(Base):
    """A deduplicated group of alerts: the unit an analyst actually works on."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(160), index=True)
    family: Mapped[str] = mapped_column(String(32), index=True)
    src: Mapped[str] = mapped_column(String(45), index=True)
    dst: Mapped[str] = mapped_column(String(45), index=True)
    dport: Mapped[int] = mapped_column(Integer, default=0)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    score_max: Mapped[float] = mapped_column(Float, default=0.0)
    score_mean: Mapped[float] = mapped_column(Float, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    severity: Mapped[str] = mapped_column(String(12), index=True, default="MEDIUM")
    priority: Mapped[int] = mapped_column(Integer, default=0, index=True)
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    asset_name: Mapped[str] = mapped_column(String(64), default="")

    status: Mapped[str] = mapped_column(String(16), index=True, default="NEW")
    assignee: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)  # TP | FP | BENIGN
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    mitre_technique: Mapped[str] = mapped_column(String(16), default="-")
    mitre_tactic: Mapped[str] = mapped_column(String(32), default="-")
    contributions: Mapped[list] = mapped_column(JSON, default=list)

    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    total_packets: Mapped[int] = mapped_column(Integer, default=0)
    distinct_dports: Mapped[int] = mapped_column(Integer, default=0)
    distinct_peers: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="selectin",
    )

    __table_args__ = (
        Index("ix_incident_open", "status", "priority"),
        Index("ix_incident_dedup_live", "dedup_key", "last_seen"),
    )


class Alert(Base):
    """One scored flow that crossed its host's threshold."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    flow_start: Mapped[float] = mapped_column(Float, default=0.0)
    flow_end: Mapped[float] = mapped_column(Float, default=0.0)

    src: Mapped[str] = mapped_column(String(45))
    sport: Mapped[int] = mapped_column(Integer, default=0)
    dst: Mapped[str] = mapped_column(String(45))
    dport: Mapped[int] = mapped_column(Integer, default=0)
    proto: Mapped[str] = mapped_column(String(8), default="tcp")

    score: Mapped[float] = mapped_column(Float, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    family: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(12), default="MEDIUM")

    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    truth: Mapped[str | None] = mapped_column(String(24), nullable=True)  # ground truth, lab only
    contributions: Mapped[list] = mapped_column(JSON, default=list)

    incident: Mapped[Incident] = relationship(back_populates="alerts")


class Bucket(Base):
    """Per-second rollup powering the charts without scanning the alert table."""

    __tablename__ = "buckets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=utcnow)
    flows: Mapped[int] = mapped_column(Integer, default=0)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    alerts: Mapped[int] = mapped_column(Integer, default=0)
    score_mean: Mapped[float] = mapped_column(Float, default=0.0)
    score_max: Mapped[float] = mapped_column(Float, default=0.0)
    threshold_mean: Mapped[float] = mapped_column(Float, default=0.0)


class Host(Base):
    """Rolling per-host profile, so the Hosts view is one query."""

    __tablename__ = "hosts"

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    asset_name: Mapped[str] = mapped_column(String(64), default="")
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    flows_out: Mapped[int] = mapped_column(Integer, default=0)
    flows_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    alerts: Mapped[int] = mapped_column(Integer, default=0)
    score_mean: Mapped[float] = mapped_column(Float, default=0.0)
    threshold: Mapped[float] = mapped_column(Float, default=0.0)
    calibrated: Mapped[bool] = mapped_column(Boolean, default=False)


class User(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # viewer|analyst|admin
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEntry(Base):
    """Every state-changing action, attributable. Required to trust the triage."""

    __tablename__ = "audit"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(48))
    target: Mapped[str] = mapped_column(String(96), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ------------------------------------------------------------------- machinery

_engine = None
_SessionFactory: sessionmaker[Session] | None = None


def engine():
    global _engine, _SessionFactory
    if _engine is None:
        url = settings.database_url
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, future=True, connect_args=connect_args)
        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - driver hook
                cur = dbapi_conn.cursor()
                # WAL lets the API read while the ingest worker writes.
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()
        _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def init_db(drop: bool = False) -> None:
    eng = engine()
    if drop:
        Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)


@contextmanager
def session_scope() -> Iterator[Session]:
    if _SessionFactory is None:
        engine()
    assert _SessionFactory is not None
    sess = _SessionFactory()
    try:
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()


def get_session() -> Session:
    if _SessionFactory is None:
        engine()
    assert _SessionFactory is not None
    return _SessionFactory()
