"""
Security Log Ingestion, Raw Parsing, and Retrieval API Endpoints
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.log import SecurityLog
from app.schemas.log import LogCreate, LogResponse, LogListResponse, RawLogIngestRequest
from app.detection.engine import DetectionEngine
from app.services.log_parser import parse_linux_auth_log, parse_windows_event_log, parse_network_packet_log

router = APIRouter(
    prefix="/logs",
    tags=["Log Ingestion & SIEM Explorer"]
)


@router.post("", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
def ingest_log(
    log_in: LogCreate, 
    db: Session = Depends(get_db)
):
    """
    Ingest and normalize a single security event.
    Stores the log in the database and automatically triggers real-time detection engine evaluation.
    """
    db_log = SecurityLog(
        timestamp=log_in.timestamp,
        source=log_in.source,
        event_type=log_in.event_type,
        username=log_in.username,
        source_ip=log_in.source_ip,
        destination_ip=log_in.destination_ip,
        port=log_in.port,
        protocol=log_in.protocol,
        action=log_in.action,
        status=log_in.status,
        message=log_in.message,
        raw_payload=log_in.raw_payload
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    # Run detection engine
    engine = DetectionEngine(db)
    engine.evaluate_log(db_log)

    return db_log


@router.post("/bulk", response_model=List[LogResponse], status_code=status.HTTP_201_CREATED)
def ingest_bulk_logs(
    logs_in: List[LogCreate], 
    db: Session = Depends(get_db)
):
    """
    Ingest a batch of security event logs simultaneously and run detection engine correlation.
    """
    db_logs = [
        SecurityLog(
            timestamp=item.timestamp,
            source=item.source,
            event_type=item.event_type,
            username=item.username,
            source_ip=item.source_ip,
            destination_ip=item.destination_ip,
            port=item.port,
            protocol=item.protocol,
            action=item.action,
            status=item.status,
            message=item.message,
            raw_payload=item.raw_payload
        )
        for item in logs_in
    ]
    db.add_all(db_logs)
    db.commit()
    for log_item in db_logs:
        db.refresh(log_item)

    # Run detection engine on batch
    engine = DetectionEngine(db)
    engine.evaluate_batch(db_logs)

    return db_logs


@router.post("/raw", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
def ingest_raw_log(
    raw_req: RawLogIngestRequest,
    db: Session = Depends(get_db)
):
    """
    Parses and ingests unstructured raw logs (Linux auth.log, Windows Event XML/Text, Wireshark packets).
    """
    parsed_log: Optional[LogCreate] = None
    
    if raw_req.format == "linux_auth":
        parsed_log = parse_linux_auth_log(raw_req.content)
    elif raw_req.format == "windows_event":
        parsed_log = parse_windows_event_log(raw_req.content)
    elif raw_req.format == "pcap_stream":
        parsed_log = parse_network_packet_log(raw_req.content)
    else:
        # Fallback generic parsing
        parsed_log = LogCreate(
            source=raw_req.source or "custom",
            event_type="raw_event",
            username=None,
            source_ip=None,
            action="raw_ingest",
            status="success",
            message=raw_req.content,
            raw_payload=raw_req.content
        )

    if not parsed_log:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not parse raw log content into normalized format."
        )

    return ingest_log(parsed_log, db)


@router.get("", response_model=LogListResponse)
def get_logs(
    source_ip: Optional[str] = Query(None, description="Filter by Source IP"),
    username: Optional[str] = Query(None, description="Filter by Username"),
    event_type: Optional[str] = Query(None, description="Filter by Event Type"),
    source: Optional[str] = Query(None, description="Filter by Log Source"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by Status (failed, success, denied)"),
    search: Optional[str] = Query(None, description="Full-text search in message or raw payload"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db)
):
    """
    Query, filter, and paginate security logs with source, status, IP, and full-text keyword filters.
    """
    query = db.query(SecurityLog)

    if source_ip:
        query = query.filter(SecurityLog.source_ip == source_ip)
    if username:
        query = query.filter(SecurityLog.username == username)
    if event_type:
        query = query.filter(SecurityLog.event_type == event_type)
    if source:
        query = query.filter(SecurityLog.source == source)
    if status_filter:
        query = query.filter(SecurityLog.status == status_filter)
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (SecurityLog.message.ilike(search_pattern)) | 
            (SecurityLog.raw_payload.ilike(search_pattern)) |
            (SecurityLog.source_ip.ilike(search_pattern)) |
            (SecurityLog.username.ilike(search_pattern))
        )

    total = query.count()
    logs = query.order_by(desc(SecurityLog.timestamp)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "logs": logs
    }


@router.get("/{log_id}", response_model=LogResponse)
def get_log_by_id(
    log_id: int, 
    db: Session = Depends(get_db)
):
    """
    Retrieve details of a specific security log by its ID.
    """
    log = db.query(SecurityLog).filter(SecurityLog.id == log_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security log with ID {log_id} not found."
        )
    return log
