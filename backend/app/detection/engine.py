"""
Real-time Threat Detection and Correlation Engine for NexusGuard
"""
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, distinct

from app.models.log import SecurityLog
from app.models.alert import Alert
from app.models.rule import DetectionRuleModel
from app.models.ioc import ThreatIOC


class DetectionEngine:
    """
    Evaluates ingested security logs against configured SOC detection rules,
    correlates events across time windows, and generates actionable security alerts.
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate_log(self, log: SecurityLog) -> List[Alert]:
        """
        Evaluates a single newly ingested log against active rules and returns created alerts.
        """
        active_rules = self.db.query(DetectionRuleModel).filter(DetectionRuleModel.enabled == True).all()
        generated_alerts: List[Alert] = []

        for rule in active_rules:
            alert = self._check_rule(rule, log)
            if alert:
                # Increment rule trigger count
                rule.trigger_count = (rule.trigger_count or 0) + 1
                self.db.add(alert)
                self.db.commit()
                self.db.refresh(alert)
                generated_alerts.append(alert)

        return generated_alerts

    def evaluate_batch(self, logs: List[SecurityLog]) -> List[Alert]:
        """
        Evaluates a batch of ingested logs and returns all newly generated alerts.
        """
        all_alerts = []
        for log in logs:
            alerts = self.evaluate_log(log)
            all_alerts.extend(alerts)
        return all_alerts

    def _check_rule(self, rule: DetectionRuleModel, log: SecurityLog) -> Optional[Alert]:
        """
        Dispatches log to specific rule evaluation logic based on rule_id.
        """
        window_start = datetime.now(timezone.utc) - timedelta(seconds=rule.time_window)

        # RULE-001: SSH / Linux Auth Brute Force
        if rule.rule_id == "RULE-001":
            if log.status == "failed" and log.source in ["linux", "auth", "ssh", "system"] and log.source_ip:
                # Count recent failed attempts from this IP
                count = self.db.query(SecurityLog).filter(
                    SecurityLog.source_ip == log.source_ip,
                    SecurityLog.status == "failed",
                    SecurityLog.timestamp >= window_start
                ).count()

                if count >= rule.threshold:
                    if not self._has_recent_open_alert(rule.rule_id, log.source_ip):
                        return Alert(
                            alert_type="BRUTE_FORCE",
                            severity=rule.severity,
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip or "10.0.0.1",
                            username=log.username,
                            description=f"SSH Brute Force Attack detected: {count} failed login attempts from IP {log.source_ip} within {rule.time_window // 60} minutes.",
                            rule_id=rule.rule_id,
                            status="OPEN",
                            mitre_technique_id=rule.mitre_technique_id,
                            mitre_technique_name=rule.mitre_technique_name,
                            mitre_tactic=rule.mitre_tactic,
                            ioc_value=log.source_ip,
                            ioc_type="ip",
                            threat_score=88.0,
                            raw_event_data=log.message or log.raw_payload
                        )

        # RULE-002: Windows Event 4625 Failed Logon Burst
        elif rule.rule_id == "RULE-002":
            if (log.event_type == "logon_4625" or "4625" in (log.message or "")) and log.status == "failed" and log.source_ip:
                count = self.db.query(SecurityLog).filter(
                    SecurityLog.source_ip == log.source_ip,
                    SecurityLog.source == "windows",
                    SecurityLog.status == "failed",
                    SecurityLog.timestamp >= window_start
                ).count()

                if count >= rule.threshold:
                    if not self._has_recent_open_alert(rule.rule_id, log.source_ip):
                        return Alert(
                            alert_type="WINDOWS_AUTH_ANOMALY",
                            severity=rule.severity,
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip or "10.0.0.20",
                            username=log.username,
                            description=f"Windows Event 4625 logon failure burst: {count} consecutive failed attempts from {log.source_ip} targeting account '{log.username}'.",
                            rule_id=rule.rule_id,
                            status="OPEN",
                            mitre_technique_id=rule.mitre_technique_id,
                            mitre_technique_name=rule.mitre_technique_name,
                            mitre_tactic=rule.mitre_tactic,
                            ioc_value=log.source_ip,
                            ioc_type="ip",
                            threat_score=85.0,
                            raw_event_data=log.message or log.raw_payload
                        )

        # RULE-003: Compromise - Login Success Following Multiple Failures
        elif rule.rule_id == "RULE-003":
            if log.status == "success" and log.source_ip:
                failed_count = self.db.query(SecurityLog).filter(
                    SecurityLog.source_ip == log.source_ip,
                    SecurityLog.status == "failed",
                    SecurityLog.timestamp >= window_start
                ).count()

                if failed_count >= rule.threshold:
                    if not self._has_recent_open_alert(rule.rule_id, log.source_ip):
                        return Alert(
                            alert_type="CREDENTIAL_COMPROMISE",
                            severity=rule.severity,
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip or "10.0.0.1",
                            username=log.username,
                            description=f"CRITICAL: Successful authentication for '{log.username}' from {log.source_ip} immediately following {failed_count} failed login attempts. Account potentially compromised.",
                            rule_id=rule.rule_id,
                            status="OPEN",
                            mitre_technique_id=rule.mitre_technique_id,
                            mitre_technique_name=rule.mitre_technique_name,
                            mitre_tactic=rule.mitre_tactic,
                            ioc_value=log.source_ip,
                            ioc_type="ip",
                            threat_score=95.0,
                            raw_event_data=log.message or log.raw_payload
                        )

        # RULE-004: Suspicious Privilege Escalation / Sudo Abuse
        elif rule.rule_id == "RULE-004":
            if log.event_type == "privilege_escalation" or log.action == "sudo" or "sudo" in (log.message or "").lower():
                suspicious_keywords = ["root", "nopasswd", "/bin/bash", "/bin/sh", "chmod 777", "shadow", "useradd", "privilege"]
                msg_lower = (log.message or "").lower()
                if any(k in msg_lower for k in suspicious_keywords):
                    return Alert(
                        alert_type="PRIVILEGE_ESCALATION",
                        severity=rule.severity,
                        source_ip=log.source_ip or "127.0.0.1",
                        destination_ip=log.destination_ip,
                        username=log.username or "unknown",
                        description=f"Unauthorized or suspicious privilege escalation event by user '{log.username}': {log.message}",
                        rule_id=rule.rule_id,
                        status="OPEN",
                        mitre_technique_id=rule.mitre_technique_id,
                        mitre_technique_name=rule.mitre_technique_name,
                        mitre_tactic=rule.mitre_tactic,
                        ioc_value=log.username,
                        ioc_type="account",
                        threat_score=90.0,
                        raw_event_data=log.message or log.raw_payload
                    )

        # RULE-005: Network Port Scan & Reconnaissance
        elif rule.rule_id == "RULE-005":
            if (log.event_type in ["network_scan", "traffic"] or log.action == "scan" or log.source == "network") and log.source_ip:
                distinct_ports = self.db.query(distinct(SecurityLog.port)).filter(
                    SecurityLog.source_ip == log.source_ip,
                    SecurityLog.port.isnot(None),
                    SecurityLog.timestamp >= window_start
                ).count()

                if distinct_ports >= rule.threshold:
                    if not self._has_recent_open_alert(rule.rule_id, log.source_ip):
                        return Alert(
                            alert_type="PORT_SCAN",
                            severity=rule.severity,
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip or "10.0.0.15",
                            username=None,
                            description=f"Port Scan Activity: Source IP {log.source_ip} probed {distinct_ports} distinct target ports within {rule.time_window} seconds (Nmap/Recon signature).",
                            rule_id=rule.rule_id,
                            status="OPEN",
                            mitre_technique_id=rule.mitre_technique_id,
                            mitre_technique_name=rule.mitre_technique_name,
                            mitre_tactic=rule.mitre_tactic,
                            ioc_value=log.source_ip,
                            ioc_type="ip",
                            threat_score=82.0,
                            raw_event_data=log.message or log.raw_payload
                        )

        # RULE-006: Malicious Threat Intel C2 IP Activity
        elif rule.rule_id == "RULE-006":
            check_ips = [ip for ip in [log.source_ip, log.destination_ip] if ip]
            for check_ip in check_ips:
                ioc_match = self.db.query(ThreatIOC).filter(
                    ThreatIOC.ioc_value == check_ip,
                    ThreatIOC.ioc_type == "ip"
                ).first()

                if ioc_match:
                    if not self._has_recent_open_alert(rule.rule_id, check_ip):
                        return Alert(
                            alert_type="THREAT_INTEL_IOC",
                            severity=rule.severity,
                            source_ip=check_ip,
                            destination_ip=log.destination_ip if check_ip == log.source_ip else log.source_ip,
                            username=log.username,
                            description=f"Threat Intel Hit: Active traffic involving known malicious host {check_ip} ({ioc_match.threat_type}). AbuseIPDB Confidence: {ioc_match.confidence_score}%, VirusTotal: {ioc_match.virustotal_positives}/{ioc_match.virustotal_total}.",
                            rule_id=rule.rule_id,
                            status="OPEN",
                            mitre_technique_id=ioc_match.mitre_technique or rule.mitre_technique_id,
                            mitre_technique_name=rule.mitre_technique_name,
                            mitre_tactic=rule.mitre_tactic,
                            ioc_value=check_ip,
                            ioc_type="ip",
                            threat_score=ioc_match.confidence_score,
                            raw_event_data=log.message or log.raw_payload
                        )

        # RULE-007: Obfuscated PowerShell / Base64 Command Execution
        elif rule.rule_id == "RULE-007":
            content_to_check = f"{log.message or ''} {log.raw_payload or ''}".lower()
            suspicious_patterns = ["-enc ", "-encodedcommand ", "frombase64string", "downloadstring", "iex(", "invoke-expression", "bypass -c"]
            if any(p in content_to_check for p in suspicious_patterns) or log.event_type == "powershell_exec":
                return Alert(
                    alert_type="POWERSHELL_OBFUSCATION",
                    severity=rule.severity,
                    source_ip=log.source_ip or "127.0.0.1",
                    destination_ip=log.destination_ip,
                    username=log.username or "SYSTEM",
                    description=f"Obfuscated PowerShell execution detected: Script invoked with Base64 encoding or execution policy bypass flag.",
                    rule_id=rule.rule_id,
                    status="OPEN",
                    mitre_technique_id=rule.mitre_technique_id,
                    mitre_technique_name=rule.mitre_technique_name,
                    mitre_tactic=rule.mitre_tactic,
                    ioc_value=log.raw_payload[:100] if log.raw_payload else "powershell.exe -enc ...",
                    ioc_type="command_payload",
                    threat_score=92.0,
                    raw_event_data=log.raw_payload or log.message
                )

        # RULE-008: Malware File Hash IOC Match
        elif rule.rule_id == "RULE-008":
            content_to_check = f"{log.message or ''} {log.raw_payload or ''}"
            # Check for known hashes
            hash_iocs = self.db.query(ThreatIOC).filter(ThreatIOC.ioc_type.in_(["hash_sha256", "hash_md5"])).all()
            for hash_ioc in hash_iocs:
                if hash_ioc.ioc_value.lower() in content_to_check.lower():
                    return Alert(
                        alert_type="MALWARE_HASH",
                        severity=rule.severity,
                        source_ip=log.source_ip,
                        destination_ip=log.destination_ip,
                        username=log.username,
                        description=f"CRITICAL: Malware Hash Match detected: '{hash_ioc.threat_type}' (Hash: {hash_ioc.ioc_value}). VirusTotal Detection: {hash_ioc.virustotal_positives}/{hash_ioc.virustotal_total}.",
                        rule_id=rule.rule_id,
                        status="OPEN",
                        mitre_technique_id=hash_ioc.mitre_technique or rule.mitre_technique_id,
                        mitre_technique_name=rule.mitre_technique_name,
                        mitre_tactic=rule.mitre_tactic,
                        ioc_value=hash_ioc.ioc_value,
                        ioc_type=hash_ioc.ioc_type,
                        threat_score=hash_ioc.confidence_score,
                        raw_event_data=log.raw_payload or log.message
                    )

        # RULE-009: Targeted Account Password Spraying
        elif rule.rule_id == "RULE-009":
            if log.status == "failed" and log.source_ip and log.username:
                distinct_users = self.db.query(distinct(SecurityLog.username)).filter(
                    SecurityLog.source_ip == log.source_ip,
                    SecurityLog.status == "failed",
                    SecurityLog.timestamp >= window_start
                ).count()

                if distinct_users >= rule.threshold:
                    if not self._has_recent_open_alert(rule.rule_id, log.source_ip):
                        return Alert(
                            alert_type="PASSWORD_SPRAY",
                            severity=rule.severity,
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip or "10.0.0.1",
                            username=f"Multiple ({distinct_users} targets)",
                            description=f"Password Spraying Campaign detected from IP {log.source_ip} attempting authentication against {distinct_users} distinct accounts.",
                            rule_id=rule.rule_id,
                            status="OPEN",
                            mitre_technique_id=rule.mitre_technique_id,
                            mitre_technique_name=rule.mitre_technique_name,
                            mitre_tactic=rule.mitre_tactic,
                            ioc_value=log.source_ip,
                            ioc_type="ip",
                            threat_score=86.0,
                            raw_event_data=log.message or log.raw_payload
                        )

        # RULE-010: Suspicious Windows Remote Logon (Type 10 / Type 3)
        elif rule.rule_id == "RULE-010":
            if log.source == "windows" and log.status == "success" and log.protocol in ["RDP", "SMB"] and log.source_ip:
                is_internal = log.source_ip.startswith("10.0.0.") or log.source_ip.startswith("192.168.1.") or log.source_ip == "127.0.0.1"
                if not is_internal:
                    if not self._has_recent_open_alert(rule.rule_id, log.source_ip):
                        return Alert(
                            alert_type="WINDOWS_REMOTE_LOGON",
                            severity=rule.severity,
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip or "10.0.0.20",
                            username=log.username,
                            description=f"Suspicious external Windows Remote Logon ({log.protocol}) for '{log.username}' originating from external address {log.source_ip}.",
                            rule_id=rule.rule_id,
                            status="OPEN",
                            mitre_technique_id=rule.mitre_technique_id,
                            mitre_technique_name=rule.mitre_technique_name,
                            mitre_tactic=rule.mitre_tactic,
                            ioc_value=log.source_ip,
                            ioc_type="ip",
                            threat_score=75.0,
                            raw_event_data=log.message or log.raw_payload
                        )

        return None

    def _has_recent_open_alert(self, rule_id: str, source_ip: str, seconds: int = 180) -> bool:
        """
        De-duplicates alerts to avoid creating spammy duplicate open alerts within a cooldown period.
        """
        recent = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        existing = self.db.query(Alert).filter(
            Alert.rule_id == rule_id,
            Alert.source_ip == source_ip,
            Alert.status == "OPEN",
            Alert.timestamp >= recent
        ).first()
        return existing is not None
