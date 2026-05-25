import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./cybershield.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scan_records"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    domain = Column(String, index=True)
    is_safe = Column(Boolean, default=True)
    threat_type = Column(String, nullable=True)
    risk_level = Column(String, nullable=True)
    confidence = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    reasons = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    scan_duration_ms = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    page_content_analyzed = Column(Boolean, default=False)
    blocked = Column(Boolean, default=False)
    user_override = Column(Boolean, default=False)


class BlacklistEntry(Base):
    __tablename__ = "blacklist"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
    reason = Column(String, nullable=True)
    threat_type = Column(String, nullable=True)


class WhitelistEntry(Base):
    __tablename__ = "whitelist"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
    reason = Column(String, nullable=True)


class AppSettings(Base):
    __tablename__ = "app_settings"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        defaults = {
            "protection_enabled": "true",
            "auto_block": "false",
            "sensitivity": "medium",
            "notifications": "true",
            "realtime_scan": "true",
            "scan_mode": "full",
        }
        for key, value in defaults.items():
            if not db.query(AppSettings).filter(AppSettings.key == key).first():
                db.add(AppSettings(key=key, value=value))
        db.commit()
    finally:
        db.close()
