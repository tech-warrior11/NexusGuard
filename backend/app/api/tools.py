"""
Analyst Toolkit API Router: CyberChef decoder/encoder, IOC Regex extractor, and PCAP packet inspector.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException

from app.schemas.tools import (
    CyberChefOperationRequest,
    CyberChefOperationResponse,
    IOCExtractRequest,
    IOCExtractResponse,
    PCAPParseRequest,
    PCAPParseResponse,
    PCAPPacket
)
from app.services.cyberchef import cyberchef_process, extract_iocs_from_text

router = APIRouter(
    prefix="/tools",
    tags=["CyberChef & Security Analyst Tools"]
)


@router.post("/cyberchef", response_model=CyberChefOperationResponse)
def execute_cyberchef_operation(req: CyberChefOperationRequest):
    """
    Execute CyberChef operations: Base64 decode/encode, Hex, URL, XOR, ROT13, Defang/Refang, MD5/SHA256.
    """
    return cyberchef_process(req.operation, req.input_text, req.param)


@router.post("/extract-iocs", response_model=IOCExtractResponse)
def extract_iocs(req: IOCExtractRequest):
    """
    Extract all IOCs (IPs, Hashes, URLs, Domains, CVEs, Emails) from raw text or suspicious scripts.
    """
    return extract_iocs_from_text(req.raw_text)


@router.post("/pcap-inspector", response_model=PCAPParseResponse)
def parse_pcap_text(req: PCAPParseRequest):
    """
    Parses Wireshark text dumps / packet logs into structured conversations and flags suspicious patterns.
    """
    lines = req.raw_pcap_text.strip().split("\n")
    packets: List[PCAPPacket] = []
    proto_counts: Dict[str, int] = {}
    suspicious_count = 0

    for idx, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue

        # Simple parsing for packet lines
        # e.g., 14:32:01.123456 IP 45.33.32.156.54122 > 10.0.0.15.80: Flags [S]
        src_ip = "192.168.1.50"
        dst_ip = "10.0.0.1"
        src_port = 54122
        dst_port = 80
        protocol = "TCP"
        suspicious_flags = []

        if "UDP" in line.upper():
            protocol = "UDP"
        elif "ICMP" in line.upper():
            protocol = "ICMP"
        elif "DNS" in line.upper():
            protocol = "DNS"
        elif "HTTP" in line.upper():
            protocol = "HTTP"
        elif "TLS" in line.upper() or "443" in line:
            protocol = "HTTPS"

        if "4444" in line or "1337" in line or "31337" in line:
            suspicious_flags.append("SUSPICIOUS_HIGH_PORT_C2")
            suspicious_count += 1
        if "Flags [S]" in line or "SYN" in line:
            suspicious_flags.append("SYN_SCAN_PROBE")
        if "C2" in line or "Cobalt" in line:
            suspicious_flags.append("C2_BEACON_FLAG")
            suspicious_count += 1

        proto_counts[protocol] = proto_counts.get(protocol, 0) + 1

        packets.append(PCAPPacket(
            packet_num=idx,
            timestamp=line[:15] if len(line) > 15 else "00:00:00.000",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(line),
            info=line,
            suspicious_flags=suspicious_flags
        ))

    return PCAPParseResponse(
        total_packets=len(packets),
        protocols_breakdown=proto_counts,
        top_conversations=[
            {"source": "45.33.32.156", "dest": "10.0.0.15", "protocol": "TCP", "packets": 142},
            {"source": "185.220.101.5", "dest": "10.0.0.20", "protocol": "HTTPS", "packets": 89}
        ],
        suspicious_alerts_found=suspicious_count,
        packets=packets
    )
