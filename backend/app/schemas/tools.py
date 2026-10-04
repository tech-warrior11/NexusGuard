"""
Pydantic Schemas for CyberChef security analysis tools & PCAP inspector
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class CyberChefOperationRequest(BaseModel):
    operation: str = Field(..., description="Operation: base64_decode, base64_encode, hex_decode, hex_encode, url_decode, url_encode, rot13, defang, refang, xor, md5, sha1, sha256")
    input_text: str = Field(..., description="Text/Payload to process")
    param: Optional[str] = Field(None, description="Optional parameter (e.g., XOR key, ROT shift)")


class CyberChefOperationResponse(BaseModel):
    operation: str
    input_text: str
    output_text: str
    success: bool
    error: Optional[str] = None


class IOCExtractRequest(BaseModel):
    raw_text: str = Field(..., description="Unstructured log, threat report, or script content")


class IOCExtractResponse(BaseModel):
    ipv4_addresses: List[str] = []
    ipv6_addresses: List[str] = []
    domains: List[str] = []
    urls: List[str] = []
    md5_hashes: List[str] = []
    sha256_hashes: List[str] = []
    email_addresses: List[str] = []
    cve_ids: List[str] = []
    total_found: int = 0


class PCAPParseRequest(BaseModel):
    raw_pcap_text: str = Field(..., description="Wireshark packet log or text export format")


class PCAPPacket(BaseModel):
    packet_num: int
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    length: int
    info: str
    suspicious_flags: List[str] = []


class PCAPParseResponse(BaseModel):
    total_packets: int
    protocols_breakdown: Dict[str, int]
    top_conversations: List[Dict[str, Any]]
    suspicious_alerts_found: int
    packets: List[PCAPPacket]
