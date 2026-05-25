import json
import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from database import get_db, ScanRecord
from schemas import ScanHistoryItem

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/history", response_model=List[ScanHistoryItem])
async def get_history(
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    threat_only: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    query = db.query(ScanRecord).order_by(desc(ScanRecord.timestamp))
    if threat_only:
        query = query.filter(ScanRecord.is_safe == False)
    records = query.offset(offset).limit(limit).all()

    return [
        ScanHistoryItem(
            id=r.id,
            url=r.url,
            domain=r.domain,
            is_safe=r.is_safe,
            threat_type=r.threat_type,
            risk_level=r.risk_level,
            confidence=r.confidence,
            risk_score=r.risk_score,
            scan_duration_ms=r.scan_duration_ms,
            timestamp=r.timestamp.isoformat() if r.timestamp else "",
            blocked=r.blocked or False,
        )
        for r in records
    ]


@router.delete("/history")
async def clear_history(db: Session = Depends(get_db)):
    deleted = db.query(ScanRecord).delete()
    db.commit()
    return {"deleted": deleted, "message": "History cleared"}


@router.get("/history/{record_id}")
async def get_history_item(record_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == record_id).first()
    if not record:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Record not found")
    return {
        "id": record.id,
        "url": record.url,
        "domain": record.domain,
        "is_safe": record.is_safe,
        "threat_type": record.threat_type,
        "risk_level": record.risk_level,
        "confidence": record.confidence,
        "risk_score": record.risk_score,
        "reasons": json.loads(record.reasons) if record.reasons else [],
        "explanation": record.explanation,
        "scan_duration_ms": record.scan_duration_ms,
        "timestamp": record.timestamp.isoformat() if record.timestamp else "",
        "blocked": record.blocked,
    }
