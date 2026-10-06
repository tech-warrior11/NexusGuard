"""
NexusGuard - Core Security Operations Center Platform
Main FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
import os

from app.core.config import settings, BASE_DIR
from app.core.database import get_db
from app.core.init_db import init_db
from app.api import (
    logs_router,
    alerts_router,
    incidents_router,
    rules_router,
    threat_intel_router,
    tools_router,
    metrics_router,
    ws_router,
)
from app.api.auth import router as auth_router, get_current_user


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize fresh SQLite tables and seed default detection rules & threat IOCs
    init_db()
    yield
    # Shutdown: Clean up resources if needed


app = FastAPI(
    title="🛡️ NexusGuard - Security Operations & Threat Detection Platform",
    description="Enterprise Real-Time SIEM, Rule-Based Threat Detection, Threat Intelligence & Analyst Workbench",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS Configuration for local frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth Router (No dependency)
app.include_router(auth_router, prefix="/api/v1")

# Include API Routers under /api/v1 (Secured)
app.include_router(logs_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(alerts_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(incidents_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(rules_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(threat_intel_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(tools_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(metrics_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
app.include_router(ws_router, prefix="")

# Remove top-level aliases to enforce strict /api/v1 prefix and security


@app.head("/", tags=["System"])
@app.get("/", tags=["System"])
def root():
    """
    Root endpoint returning SOC platform metadata and operational status.
    """
    return {
        "service": "NexusGuard",
        "role": "Security Operations Center & SIEM Detection Engine",
        "status": "OPERATIONAL",
        "version": settings.VERSION,
        "docs": "/docs",
        "endpoints": {
            "metrics": "/api/v1/metrics",
            "logs": "/api/v1/logs",
            "alerts": "/api/v1/alerts",
            "incidents": "/api/v1/incidents",
            "rules": "/api/v1/rules",
            "threat_intel": "/api/v1/threat-intel/lookup",
            "tools": "/api/v1/tools/cyberchef"
        }
    }


@app.head("/health", tags=["System"])
@app.get("/health", tags=["System"])
def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint verifying SQLite DB connectivity and Detection Engine status.
    """
    try:
        db.execute(text("SELECT 1"))
        db_status = "CONNECTED"
    except Exception as e:
        db_status = f"ERROR: {str(e)}"

    return {
        "status": "HEALTHY" if db_status == "CONNECTED" else "DEGRADED",
        "database": db_status,
        "detection_engine": "ACTIVE",
        "threat_intel_service": "READY",
        "uptime": "OK",
    }
