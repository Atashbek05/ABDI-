import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from database import get_db, AppSettings
from schemas import SettingUpdate

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/settings")
async def get_settings(db: Session = Depends(get_db)):
    settings = db.query(AppSettings).all()
    return {s.key: s.value for s in settings}


@router.put("/settings/{key}")
async def update_setting(key: str, body: SettingUpdate, db: Session = Depends(get_db)):
    setting = db.query(AppSettings).filter(AppSettings.key == key).first()
    if setting:
        setting.value = body.value
        setting.updated_at = datetime.utcnow()
    else:
        setting = AppSettings(key=key, value=body.value)
        db.add(setting)
    db.commit()
    return {"key": key, "value": body.value, "updated": True}


@router.get("/settings/{key}")
async def get_setting(key: str, db: Session = Depends(get_db)):
    setting = db.query(AppSettings).filter(AppSettings.key == key).first()
    if not setting:
        raise HTTPException(status_code=404, detail="Setting not found")
    return {"key": key, "value": setting.value}
