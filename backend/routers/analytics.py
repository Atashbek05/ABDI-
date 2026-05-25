import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from database import get_db, ScanRecord
from services.cache_service import scan_cache
from ai_engine.model_manager import get_model_manager
from ai_engine.prediction_cache import prediction_cache

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/analytics")
async def get_analytics(db: Session = Depends(get_db)):
    total = db.query(func.count(ScanRecord.id)).scalar() or 0
    threats = db.query(func.count(ScanRecord.id)).filter(ScanRecord.is_safe == False).scalar() or 0
    safe = total - threats
    blocked = db.query(func.count(ScanRecord.id)).filter(ScanRecord.blocked == True).scalar() or 0

    avg_conf = db.query(func.avg(ScanRecord.confidence)).scalar() or 0.0
    avg_dur = db.query(func.avg(ScanRecord.scan_duration_ms)).scalar() or 0.0

    threat_dist_rows = (
        db.query(ScanRecord.threat_type, func.count(ScanRecord.id))
        .filter(ScanRecord.is_safe == False)
        .group_by(ScanRecord.threat_type)
        .all()
    )
    threat_dist = {row[0] or "unknown": row[1] for row in threat_dist_rows}

    risk_dist_rows = (
        db.query(ScanRecord.risk_level, func.count(ScanRecord.id))
        .group_by(ScanRecord.risk_level)
        .all()
    )
    risk_dist = {row[0] or "unknown": row[1] for row in risk_dist_rows}

    # Daily scans for last 14 days
    daily_scans = []
    for i in range(13, -1, -1):
        day = datetime.utcnow().date() - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end = datetime.combine(day, datetime.max.time())
        count = (
            db.query(func.count(ScanRecord.id))
            .filter(ScanRecord.timestamp >= day_start, ScanRecord.timestamp <= day_end)
            .scalar() or 0
        )
        threat_count = (
            db.query(func.count(ScanRecord.id))
            .filter(
                ScanRecord.timestamp >= day_start,
                ScanRecord.timestamp <= day_end,
                ScanRecord.is_safe == False,
            )
            .scalar() or 0
        )
        daily_scans.append({"date": day.isoformat(), "scans": count, "threats": threat_count})

    # Top threats
    top_domains = (
        db.query(ScanRecord.domain, func.count(ScanRecord.id).label("count"))
        .filter(ScanRecord.is_safe == False)
        .group_by(ScanRecord.domain)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )
    top_threats = [{"domain": r[0], "count": r[1]} for r in top_domains]

    # Recent threats
    recent = (
        db.query(ScanRecord)
        .filter(ScanRecord.is_safe == False)
        .order_by(desc(ScanRecord.timestamp))
        .limit(10)
        .all()
    )
    recent_threats = [
        {
            "domain": r.domain,
            "threat_type": r.threat_type,
            "risk_level": r.risk_level,
            "confidence": r.confidence,
            "timestamp": r.timestamp.isoformat() if r.timestamp else "",
        }
        for r in recent
    ]

    cache_stats = scan_cache.stats

    return {
        "total_scans": total,
        "threats_detected": threats,
        "safe_sites": safe,
        "blocked_count": blocked,
        "detection_rate": round(threats / max(1, total) * 100, 2),
        "avg_confidence": round(avg_conf, 2),
        "avg_scan_duration": round(avg_dur, 2),
        "threat_distribution": threat_dist,
        "risk_level_distribution": risk_dist,
        "daily_scans": daily_scans,
        "top_threats": top_threats,
        "recent_threats": recent_threats,
        "cache_stats": cache_stats,
    }


@router.get("/ai/models")
async def ai_model_comparison():
    """Return per-model performance + ensemble metadata for the dashboard."""
    mm = get_model_manager()
    report = mm.comparison_report()
    report["prediction_cache"] = prediction_cache.stats
    return report


@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(ScanRecord.id)).scalar() or 0
    threats = db.query(func.count(ScanRecord.id)).filter(ScanRecord.is_safe == False).scalar() or 0
    today = datetime.utcnow().date()
    today_scans = (
        db.query(func.count(ScanRecord.id))
        .filter(ScanRecord.timestamp >= datetime.combine(today, datetime.min.time()))
        .scalar() or 0
    )
    return {
        "total_scans": total,
        "threats_detected": threats,
        "today_scans": today_scans,
        "detection_rate": round(threats / max(1, total) * 100, 2),
        "engine_status": "active",
        "ml_model": "loaded",
        "cache_size": scan_cache.stats["size"],
    }
