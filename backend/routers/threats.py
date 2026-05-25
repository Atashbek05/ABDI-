import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from database import get_db, ScanRecord

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/threats")
async def get_threats(
    limit: int = Query(default=50, le=500),
    threat_type: str = Query(default=None),
    risk_level: str = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(ScanRecord).filter(ScanRecord.is_safe == False)
    if threat_type:
        query = query.filter(ScanRecord.threat_type == threat_type)
    if risk_level:
        query = query.filter(ScanRecord.risk_level == risk_level)
    records = query.order_by(desc(ScanRecord.timestamp)).limit(limit).all()

    return [
        {
            "id": r.id,
            "url": r.url,
            "domain": r.domain,
            "threat_type": r.threat_type,
            "risk_level": r.risk_level,
            "confidence": r.confidence,
            "risk_score": r.risk_score,
            "timestamp": r.timestamp.isoformat() if r.timestamp else "",
            "blocked": r.blocked,
        }
        for r in records
    ]


@router.get("/threats/summary")
async def get_threats_summary(db: Session = Depends(get_db)):
    by_type = (
        db.query(ScanRecord.threat_type, func.count(ScanRecord.id))
        .filter(ScanRecord.is_safe == False)
        .group_by(ScanRecord.threat_type)
        .order_by(desc(func.count(ScanRecord.id)))
        .all()
    )
    by_level = (
        db.query(ScanRecord.risk_level, func.count(ScanRecord.id))
        .filter(ScanRecord.is_safe == False)
        .group_by(ScanRecord.risk_level)
        .all()
    )
    return {
        "by_type": [{"type": r[0], "count": r[1]} for r in by_type],
        "by_level": [{"level": r[0], "count": r[1]} for r in by_level],
    }
