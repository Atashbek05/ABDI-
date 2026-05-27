import time
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from database import init_db
from routers import check, history, analytics, settings_router, blacklist, whitelist, threats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("CyberShield AI v2.0 — engine initialized")
    yield
    logger.info("CyberShield AI shutting down")


app = FastAPI(
    title="CyberShield AI — Security API",
    description="Advanced AI-powered cybersecurity browser protection backend",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # credentials=True + origins="*" is invalid per CORS spec
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = round((time.time() - start) * 1000, 2)
    response.headers["X-Process-Time-Ms"] = str(elapsed)
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error", "detail": str(exc)})


app.include_router(check.router, prefix="/api/v1", tags=["Detection"])
app.include_router(history.router, prefix="/api/v1", tags=["History"])
app.include_router(analytics.router, prefix="/api/v1", tags=["Analytics"])
app.include_router(settings_router.router, prefix="/api/v1", tags=["Settings"])
app.include_router(blacklist.router, prefix="/api/v1", tags=["Blacklist"])
app.include_router(whitelist.router, prefix="/api/v1", tags=["Whitelist"])
app.include_router(threats.router, prefix="/api/v1", tags=["Threats"])


@app.get("/health", tags=["System"])
async def health_check():
    import os
    model_exists = os.path.exists(os.path.join("ml", "model.pkl"))
    return {
        "status": "operational",
        "version": "2.0.0",
        "service": "CyberShield AI",
        "ai_engine": "active",
        "ml_model": "loaded" if model_exists else "heuristics_only",
        "database": "connected",
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "service": "CyberShield AI Security API",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health",
    }
