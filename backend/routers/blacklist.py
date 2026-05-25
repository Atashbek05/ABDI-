import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from database import get_db, BlacklistEntry
from schemas import BlacklistAdd
from services.cache_service import scan_cache

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/blacklist")
async def get_blacklist(db: Session = Depends(get_db)):
    entries = db.query(BlacklistEntry).all()
    return [
        {
            "id": e.id,
            "domain": e.domain,
            "reason": e.reason,
            "threat_type": e.threat_type,
            "added_at": e.added_at.isoformat() if e.added_at else "",
        }
        for e in entries
    ]


@router.post("/blacklist")
async def add_to_blacklist(entry: BlacklistAdd, db: Session = Depends(get_db)):
    domain = entry.domain.lower().strip().lstrip("www.")
    existing = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain).first()
    if existing:
        raise HTTPException(status_code=409, detail="Domain already in blacklist")
    record = BlacklistEntry(domain=domain, reason=entry.reason, threat_type=entry.threat_type)
    db.add(record)
    db.commit()
    scan_cache.invalidate(f"https://{domain}")
    scan_cache.invalidate(f"http://{domain}")
    return {"domain": domain, "added": True}


@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, db: Session = Depends(get_db)):
    entry = db.query(BlacklistEntry).filter(BlacklistEntry.domain == domain).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not in blacklist")
    db.delete(entry)
    db.commit()
    return {"domain": domain, "removed": True}
