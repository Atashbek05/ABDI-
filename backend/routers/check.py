import json
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db, ScanRecord
from schemas import ScanRequest, ScanResponse
from services.ai_engine import AIDetectionEngine
from services.cache_service import scan_cache

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/check", response_model=ScanResponse)
async def check_url(request: ScanRequest, db: Session = Depends(get_db)):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Cache check
    cache_key = url
    cached = scan_cache.get(cache_key)
    if cached:
        return cached

    engine = AIDetectionEngine(db_session=db)
    result = await engine.analyze(
        url=url,
        html_content=request.html_content,
        page_title=request.page_title,
        page_text=request.page_text,
        forms=request.forms,
        scripts=request.scripts,
        redirects=request.redirects,
        dom_data=request.dom_data,
    )

    # Persist to database
    try:
        record = ScanRecord(
            url=result["url"],
            domain=result["domain"],
            is_safe=result["is_safe"],
            threat_type=result["threat_type"],
            risk_level=result["risk_level"],
            confidence=result["confidence"],
            risk_score=result["risk_score"],
            reasons=json.dumps(result["reasons"]),
            explanation=result["explanation"],
            scan_duration_ms=result["scan_duration_ms"],
            page_content_analyzed=bool(request.html_content or request.forms),
        )
        db.add(record)
        db.commit()
    except Exception as e:
        logger.error(f"DB save error: {e}")
        db.rollback()

    # Cache safe results longer, threats shorter
    ttl_override = None
    if result["is_safe"]:
        scan_cache.set(cache_key, result)
    else:
        scan_cache._cache[cache_key] = result
        import time
        scan_cache._timestamps[cache_key] = time.time()
        if cache_key not in scan_cache._access_order:
            scan_cache._access_order.append(cache_key)

    return result
