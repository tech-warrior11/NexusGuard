"""
Threat Intelligence API Router: Lookups for IPs, Hashes, Domains, and MITRE Mapping
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.ioc import ThreatIOC
from app.schemas.threat_intel import ThreatIntelResponse
from app.services.threat_intel import lookup_threat_intel, MITRE_KNOWLEDGE_BASE

router = APIRouter(
    prefix="/threat-intel",
    tags=["Threat Intelligence & IOC Enrichment"]
)


@router.get("/lookup", response_model=ThreatIntelResponse)
def query_threat_intel(
    indicator: str = Query(..., description="IP, Domain, MD5, or SHA256 Hash to query", examples=["185.220.101.5"]),
    db: Session = Depends(get_db)
):
    """
    Query AbuseIPDB and VirusTotal threat intelligence reputation for any IP, Domain, or Hash.
    Returns confidence score, detection ratio, ISP, and MITRE ATT&CK technique mapping.
    """
    if not indicator.strip():
        raise HTTPException(status_code=400, detail="Indicator parameter cannot be empty.")

    return lookup_threat_intel(indicator, db)


@router.get("/iocs")
def get_known_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by type: ip, domain, hash_sha256, hash_md5"),
    db: Session = Depends(get_db)
):
    """
    List all known threat intelligence IOCs stored in the NexusGuard active threat database.
    """
    query = db.query(ThreatIOC)
    if ioc_type:
        query = query.filter(ThreatIOC.ioc_type == ioc_type)
    
    iocs = query.all()
    return {
        "total": len(iocs),
        "iocs": iocs
    }


@router.get("/mitre-matrix")
def get_mitre_matrix_data():
    """
    Returns full MITRE ATT&CK Matrix mapping supported by NexusGuard with active detection techniques.
    """
    tactics_summary = {
        "Initial Access": [
            {"id": "T1078", "name": "Valid Accounts", "detected_by": "RULE-003", "severity": "CRITICAL"},
            {"id": "T1566", "name": "Phishing", "detected_by": "THREAT_INTEL", "severity": "HIGH"}
        ],
        "Execution": [
            {"id": "T1059.001", "name": "PowerShell: Encoded Commands", "detected_by": "RULE-007", "severity": "HIGH"},
            {"id": "T1204.002", "name": "User Execution: Malicious File", "detected_by": "RULE-008", "severity": "CRITICAL"}
        ],
        "Privilege Escalation": [
            {"id": "T1548.003", "name": "Sudo Abuse & Caching", "detected_by": "RULE-004", "severity": "CRITICAL"}
        ],
        "Credential Access": [
            {"id": "T1110.001", "name": "Brute Force: Password Guessing", "detected_by": "RULE-001, RULE-002", "severity": "HIGH"},
            {"id": "T1110.003", "name": "Password Spraying", "detected_by": "RULE-009", "severity": "HIGH"},
            {"id": "T1003.001", "name": "LSASS Memory Dump (Mimikatz)", "detected_by": "RULE-008", "severity": "CRITICAL"}
        ],
        "Discovery": [
            {"id": "T1046", "name": "Network Service Discovery (Nmap)", "detected_by": "RULE-005", "severity": "HIGH"}
        ],
        "Lateral Movement": [
            {"id": "T1021.001", "name": "Remote Desktop Protocol (RDP)", "detected_by": "RULE-010", "severity": "MEDIUM"}
        ],
        "Command and Control": [
            {"id": "T1071.001", "name": "Web Protocols C2 (Cobalt Strike)", "detected_by": "RULE-006", "severity": "CRITICAL"}
        ],
        "Impact": [
            {"id": "T1486", "name": "Data Encrypted for Impact (Ransomware)", "detected_by": "RULE-008", "severity": "CRITICAL"}
        ]
    }

    return {
        "framework": "MITRE ATT&CK Enterprise Matrix v14",
        "tactics": tactics_summary,
        "knowledge_base": MITRE_KNOWLEDGE_BASE
    }
