import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db, WhitelistEntry
from schemas import WhitelistAdd
from services.cache_service import scan_cache

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/whitelist")
async def get_whitelist(db: Session = Depends(get_db)):
    entries = db.query(WhitelistEntry).all()
    return [
        {
            "id": e.id,
            "domain": e.domain,
            "reason": e.reason,
            "added_at": e.added_at.isoformat() if e.added_at else "",
        }
        for e in entries
    ]


@router.post("/whitelist")
async def add_to_whitelist(entry: WhitelistAdd, db: Session = Depends(get_db)):
    domain = entry.domain.lower().strip().lstrip("www.")
    existing = db.query(WhitelistEntry).filter(WhitelistEntry.domain == domain).first()
    if existing:
        raise HTTPException(status_code=409, detail="Domain already whitelisted")
    record = WhitelistEntry(domain=domain, reason=entry.reason)
    db.add(record)
    db.commit()
    scan_cache.invalidate(f"https://{domain}")
    return {"domain": domain, "added": True}


@router.delete("/whitelist/{domain}")
async def remove_from_whitelist(domain: str, db: Session = Depends(get_db)):
    entry = db.query(WhitelistEntry).filter(WhitelistEntry.domain == domain).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not whitelisted")
    db.delete(entry)
    db.commit()
    return {"domain": domain, "removed": True}
