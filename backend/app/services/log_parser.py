"""
Log Parser Service: Parsing and normalizing Linux auth.log, Windows Event Logs (4624, 4625, etc.), and Network logs.
"""
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.schemas.log import LogCreate


def parse_linux_auth_log(log_line: str) -> Optional[LogCreate]:
    """
    Parses a single line from Linux `/var/log/auth.log` or `secure`.
    Examples:
    - 'Sep 29 14:22:01 server sshd[1234]: Failed password for root from 194.26.29.112 port 49212 ssh2'
    - 'Sep 29 14:22:05 server sshd[1235]: Failed password for invalid user admin from 185.220.101.5 port 51222 ssh2'
    - 'Sep 29 14:22:15 server sshd[1236]: Accepted password for ubuntu from 10.0.0.5 port 55112 ssh2'
    - 'Sep 29 14:23:00 server sudo: pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu'
    """
    log_line = log_line.strip()
    if not log_line:
        return None

    now = datetime.now(timezone.utc)
    
    # 1. SSH Failed Password
    failed_match = re.search(r"sshd\[\d+\]:\s+Failed password for (?:invalid user\s+)?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)", log_line, re.IGNORECASE)
    if failed_match:
        username = failed_match.group(1)
        src_ip = failed_match.group(2)
        port = int(failed_match.group(3))
        return LogCreate(
            timestamp=now,
            source="linux",
            event_type="authentication",
            username=username,
            source_ip=src_ip,
            destination_ip="10.0.0.1",
            port=22,
            protocol="SSH",
            action="login",
            status="failed",
            message=f"Failed SSH authentication attempt for user '{username}' from {src_ip}:{port}",
            raw_payload=log_line
        )

    # 2. SSH Accepted Password
    accepted_match = re.search(r"sshd\[\d+\]:\s+Accepted password for (\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)", log_line, re.IGNORECASE)
    if accepted_match:
        username = accepted_match.group(1)
        src_ip = accepted_match.group(2)
        port = int(accepted_match.group(3))
        return LogCreate(
            timestamp=now,
            source="linux",
            event_type="authentication",
            username=username,
            source_ip=src_ip,
            destination_ip="10.0.0.1",
            port=22,
            protocol="SSH",
            action="login",
            status="success",
            message=f"Successful SSH authentication for user '{username}' from {src_ip}:{port}",
            raw_payload=log_line
        )

    # 3. Sudo command / privilege escalation
    sudo_match = re.search(r"sudo:\s+(?:pam_unix\(sudo:session\): session opened for user (\S+)|(\S+)\s+:\s+TTY=.*COMMAND=(.*))", log_line, re.IGNORECASE)
    if sudo_match:
        username = sudo_match.group(1) or sudo_match.group(2) or "root"
        cmd = sudo_match.group(3) if sudo_match.group(3) else "privileged_session"
        return LogCreate(
            timestamp=now,
            source="linux",
            event_type="privilege_escalation",
            username=username,
            source_ip="127.0.0.1",
            destination_ip="127.0.0.1",
            port=None,
            protocol="LOCAL",
            action="sudo",
            status="success" if "opened" in log_line or "COMMAND" in log_line else "denied",
            message=f"Sudo execution by user '{username}': {cmd}",
            raw_payload=log_line
        )

    # Fallback Linux log
    return LogCreate(
        timestamp=now,
        source="linux",
        event_type="system",
        username="system",
        source_ip=None,
        destination_ip=None,
        port=None,
        protocol="SYSLOG",
        action="syslog_event",
        status="success",
        message=log_line,
        raw_payload=log_line
    )


def parse_windows_event_log(log_text: str) -> Optional[LogCreate]:
    """
    Parses Windows Event Log (plain text export or XML snippet) for Event IDs 4624, 4625, 4688, 7045.
    Examples:
    - Event ID: 4625 (An account failed to log on), Account Name: Administrator, Workstation Name: WIN-PC, Source Network Address: 185.220.101.5, Logon Type: 3
    - Event ID: 4624 (An account was successfully logged on), Account Name: Administrator, Source Network Address: 10.0.0.5, Logon Type: 10
    """
    log_text = log_text.strip()
    if not log_text:
        return None

    now = datetime.now(timezone.utc)

    # Extract Event ID
    event_id_match = re.search(r"(?:Event ID:?|EventID>|ID:)\s*(\d{4})", log_text, re.IGNORECASE)
    event_id = event_id_match.group(1) if event_id_match else "4625"

    # Extract Username / Account Name
    user_match = re.search(r"(?:Account Name|TargetUserName|User):\s*([^\r\n,]+)", log_text, re.IGNORECASE)
    username = user_match.group(1).strip() if user_match else "Administrator"

    # Extract Source IP / Network Address
    ip_match = re.search(r"(?:Source Network Address|IpAddress|Source IP):\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", log_text, re.IGNORECASE)
    src_ip = ip_match.group(1).strip() if ip_match else "194.26.29.112"

    # Extract Logon Type (e.g. 2=Interactive, 3=Network, 10=RemoteInteractive/RDP)
    logon_type_match = re.search(r"(?:Logon Type|LogonType):\s*(\d+)", log_text, re.IGNORECASE)
    logon_type = logon_type_match.group(1) if logon_type_match else "3"

    if event_id == "4625":
        return LogCreate(
            timestamp=now,
            source="windows",
            event_type="logon_4625",
            username=username,
            source_ip=src_ip,
            destination_ip="10.0.0.20",
            port=3389 if logon_type == "10" else 445,
            protocol="RDP" if logon_type == "10" else "SMB",
            action="login",
            status="failed",
            message=f"Windows Security Event 4625: Failed logon for account '{username}' from {src_ip} (Logon Type: {logon_type})",
            raw_payload=log_text
        )
    elif event_id == "4624":
        return LogCreate(
            timestamp=now,
            source="windows",
            event_type="logon_4624",
            username=username,
            source_ip=src_ip,
            destination_ip="10.0.0.20",
            port=3389 if logon_type == "10" else 445,
            protocol="RDP" if logon_type == "10" else "SMB",
            action="login",
            status="success",
            message=f"Windows Security Event 4624: Successful logon for account '{username}' from {src_ip} (Logon Type: {logon_type})",
            raw_payload=log_text
        )
    elif event_id == "4688":
        # Process Creation
        cmd_match = re.search(r"(?:Process Command Line|CommandLine):\s*([^\r\n]+)", log_text, re.IGNORECASE)
        cmd = cmd_match.group(1) if cmd_match else "powershell.exe -enc SQBFAFg..."
        return LogCreate(
            timestamp=now,
            source="windows",
            event_type="powershell_exec" if "powershell" in cmd.lower() else "process_creation",
            username=username,
            source_ip=src_ip,
            destination_ip="10.0.0.20",
            port=None,
            protocol="LOCAL",
            action="execute",
            status="success",
            message=f"Windows Security Event 4688: Process creation by '{username}': {cmd}",
            raw_payload=log_text
        )
    else:
        return LogCreate(
            timestamp=now,
            source="windows",
            event_type=f"windows_event_{event_id}",
            username=username,
            source_ip=src_ip,
            destination_ip="10.0.0.20",
            port=None,
            protocol="WINDOWS",
            action="audit",
            status="success",
            message=f"Windows Security Event {event_id} for user '{username}'",
            raw_payload=log_text
        )


def parse_network_packet_log(log_line: str) -> Optional[LogCreate]:
    """
    Parses a Wireshark / Network text packet stream.
    Example:
    - '14:32:01.123456 IP 45.33.32.156.54122 > 10.0.0.15.80: Flags [S], seq 0, win 65535, length 0'
    - '14:32:05.987654 IP 185.220.101.5.443 > 10.0.0.15.51222: Flags [P.], length 256 (C2_BEACON)'
    """
    log_line = log_line.strip()
    if not log_line:
        return None

    now = datetime.now(timezone.utc)
    match = re.search(r"IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s*(.*)", log_line)
    if match:
        src_ip = match.group(1)
        src_port = int(match.group(2))
        dst_ip = match.group(3)
        dst_port = int(match.group(4))
        info = match.group(5)

        is_scan = "Flags [S]" in info or "Flags [R]" in info
        is_suspicious = dst_port in [4444, 1337, 8888, 31337] or "C2" in info

        return LogCreate(
            timestamp=now,
            source="network",
            event_type="network_scan" if is_scan else ("c2_traffic" if is_suspicious else "traffic"),
            username=None,
            source_ip=src_ip,
            destination_ip=dst_ip,
            port=dst_port,
            protocol="TCP",
            action="connect" if not is_scan else "scan",
            status="blocked" if "Flags [R]" in info else "detected",
            message=f"Network packet from {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({info})",
            raw_payload=log_line
        )

    return None
