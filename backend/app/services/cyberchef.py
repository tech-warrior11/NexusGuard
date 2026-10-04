"""
CyberChef Service: Decoding, Encoding, Hashing, Defanging, and Automated IOC Extraction
"""
import base64
import binascii
import hashlib
import re
import urllib.parse
from typing import Optional, List, Dict, Any

from app.schemas.tools import CyberChefOperationResponse, IOCExtractResponse


def cyberchef_process(operation: str, input_text: str, param: Optional[str] = None) -> CyberChefOperationResponse:
    """
    Executes a security decoding/encoding/transformation operation on input text.
    """
    operation = operation.lower().strip()
    try:
        if operation == "base64_decode":
            # Attempt UTF-8 decode, then UTF-16LE decode (standard for Windows PowerShell -enc commands)
            cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", input_text)
            # Add padding if needed
            missing_padding = len(cleaned) % 4
            if missing_padding:
                cleaned += "=" * (4 - missing_padding)
            decoded_bytes = base64.b64decode(cleaned)
            
            # Check if it contains null bytes typical of UTF-16LE PowerShell scripts
            if b"\x00" in decoded_bytes:
                try:
                    output = decoded_bytes.decode("utf-16le")
                except UnicodeDecodeError:
                    output = decoded_bytes.decode("utf-8", errors="replace")
            else:
                output = decoded_bytes.decode("utf-8", errors="replace")
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "base64_encode":
            output = base64.b64encode(input_text.encode("utf-8")).decode("utf-8")
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "hex_decode":
            # Strip spaces, 0x, colons, \x
            cleaned = re.sub(r"[0x\\:\s]", "", input_text)
            output = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "hex_encode":
            output = input_text.encode("utf-8").hex()
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "url_decode":
            output = urllib.parse.unquote(input_text)
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "url_encode":
            output = urllib.parse.quote(input_text)
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "rot13":
            import codecs
            output = codecs.encode(input_text, "rot_13")
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "defang":
            # Replaces http with hxxp, . with [.] and :// with [://]
            output = input_text
            output = re.sub(r"https?://", lambda m: "hxxp" + ("s" if "https" in m.group(0) else "") + "[://]", output)
            output = re.sub(r"\.", "[.]", output)
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "refang":
            output = input_text
            output = output.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://")
            output = output.replace("[.]", ".").replace("[:]", ":").replace("[\\]", "/")
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "xor":
            key = param if param else "key"
            key_bytes = key.encode("utf-8")
            input_bytes = input_text.encode("utf-8")
            xored = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(input_bytes)])
            output = xored.hex()
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=f"Hex Output: {output}", success=True)

        elif operation == "md5":
            output = hashlib.md5(input_text.encode("utf-8")).hexdigest()
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "sha1":
            output = hashlib.sha1(input_text.encode("utf-8")).hexdigest()
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        elif operation == "sha256":
            output = hashlib.sha256(input_text.encode("utf-8")).hexdigest()
            return CyberChefOperationResponse(operation=operation, input_text=input_text, output_text=output, success=True)

        else:
            return CyberChefOperationResponse(
                operation=operation,
                input_text=input_text,
                output_text="",
                success=False,
                error=f"Unsupported operation: {operation}"
            )

    except Exception as e:
        return CyberChefOperationResponse(
            operation=operation,
            input_text=input_text,
            output_text="",
            success=False,
            error=f"Operation failed: {str(e)}"
        )


def extract_iocs_from_text(raw_text: str) -> IOCExtractResponse:
    """
    Scans unstructured security logs, alert dumps, or malware scripts and extracts all IOCs using Regex.
    """
    if not raw_text:
        return IOCExtractResponse()

    # IPv4 Regex (0.0.0.0 to 255.255.255.255)
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ipv4_matches = list(set(re.findall(ipv4_pattern, raw_text)))

    # IPv6 Regex
    ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ipv6_matches = list(set(re.findall(ipv6_pattern, raw_text)))

    # SHA256 (64 hex characters)
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
    sha256_matches = list(set(re.findall(sha256_pattern, raw_text)))

    # MD5 (32 hex characters) - exclude if already part of sha256
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    md5_raw = re.findall(md5_pattern, raw_text)
    md5_matches = list(set([m for m in md5_raw if not any(m in sha for sha in sha256_matches)]))

    # URLs
    url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"
    url_matches = list(set(re.findall(url_pattern, raw_text)))

    # Domains (exclude common file extensions or pure IPs)
    domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|ru|cn|de|uk|gov|edu|info|xyz|biz)\b"
    domain_matches = list(set(re.findall(domain_pattern, raw_text, re.IGNORECASE)))

    # Email Addresses
    email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    email_matches = list(set(re.findall(email_pattern, raw_text)))

    # CVE IDs (e.g. CVE-2021-44228)
    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"
    cve_matches = list(set(re.findall(cve_pattern, raw_text, re.IGNORECASE)))

    total = (
        len(ipv4_matches) + len(ipv6_matches) + len(sha256_matches) +
        len(md5_matches) + len(url_matches) + len(domain_matches) +
        len(email_matches) + len(cve_matches)
    )

    return IOCExtractResponse(
        ipv4_addresses=ipv4_matches,
        ipv6_addresses=ipv6_matches,
        domains=domain_matches,
        urls=url_matches,
        md5_hashes=md5_matches,
        sha256_hashes=sha256_matches,
        email_addresses=email_matches,
        cve_ids=cve_matches,
        total_found=total
    )
