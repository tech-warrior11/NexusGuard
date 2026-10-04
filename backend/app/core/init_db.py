"""
Database initialization, table creation, and default SOC rule / threat intel seed data.
"""
from app.core.database import engine, Base, SessionLocal
from app.models import User, SecurityLog, Alert, Incident, DetectionRuleModel, ThreatIOC


def init_db():
    """
    Creates all database tables defined in models and seeds default SOC data.
    """
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # 1. Seed Detection Rules
        if db.query(DetectionRuleModel).count() == 0:
            initial_rules = [
                DetectionRuleModel(
                    rule_id="RULE-001",
                    name="SSH/Linux Auth Brute Force Detection",
                    description="5 or more failed authentication attempts from the same IP within a 5-minute window.",
                    severity="HIGH",
                    enabled=True,
                    rule_type="threshold",
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Brute Force: Password Guessing",
                    mitre_tactic="Credential Access",
                    threshold=5,
                    time_window=300
                ),
                DetectionRuleModel(
                    rule_id="RULE-002",
                    name="Windows Event 4625 Failed Logon Burst",
                    description="Multiple Event 4625 (Failed Logon) occurrences detected indicating password attack.",
                    severity="HIGH",
                    enabled=True,
                    rule_type="threshold",
                    mitre_technique_id="T1110.001",
                    mitre_technique_name="Brute Force: Password Guessing",
                    mitre_tactic="Credential Access",
                    threshold=4,
                    time_window=300
                ),
                DetectionRuleModel(
                    rule_id="RULE-003",
                    name="Compromise: Login Success Following Failures",
                    description="Successful authentication immediately following multiple failed login attempts from same entity.",
                    severity="CRITICAL",
                    enabled=True,
                    rule_type="sequence",
                    mitre_technique_id="T1078",
                    mitre_technique_name="Valid Accounts",
                    mitre_tactic="Initial Access",
                    threshold=3,
                    time_window=300
                ),
                DetectionRuleModel(
                    rule_id="RULE-004",
                    name="Suspicious Privilege Escalation / Sudo Abuse",
                    description="Unauthorized sudo command execution or attempted root access elevation.",
                    severity="CRITICAL",
                    enabled=True,
                    rule_type="signature",
                    mitre_technique_id="T1548.003",
                    mitre_technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                    mitre_tactic="Privilege Escalation",
                    threshold=1,
                    time_window=60
                ),
                DetectionRuleModel(
                    rule_id="RULE-005",
                    name="Network Port Scan & Reconnaissance",
                    description="Rapid connection attempts across 4 or more distinct target ports from a single IP.",
                    severity="HIGH",
                    enabled=True,
                    rule_type="anomaly",
                    mitre_technique_id="T1046",
                    mitre_technique_name="Network Service Discovery",
                    mitre_tactic="Discovery",
                    threshold=4,
                    time_window=180
                ),
                DetectionRuleModel(
                    rule_id="RULE-006",
                    name="Malicious Threat Intel C2 IP Activity",
                    description="Inbound/outbound communication with an IP flagged in AbuseIPDB / VirusTotal threat feeds.",
                    severity="CRITICAL",
                    enabled=True,
                    rule_type="threat_intel",
                    mitre_technique_id="T1071.001",
                    mitre_technique_name="Application Layer Protocol: Web Protocols",
                    mitre_tactic="Command and Control",
                    threshold=1,
                    time_window=60
                ),
                DetectionRuleModel(
                    rule_id="RULE-007",
                    name="Obfuscated PowerShell / Base64 Command Execution",
                    description="PowerShell process invoked with Base64 encoding (-enc, -encodedcommand, FromBase64String).",
                    severity="HIGH",
                    enabled=True,
                    rule_type="signature",
                    mitre_technique_id="T1059.001",
                    mitre_technique_name="Command and Scripting Interpreter: PowerShell",
                    mitre_tactic="Execution",
                    threshold=1,
                    time_window=60
                ),
                DetectionRuleModel(
                    rule_id="RULE-008",
                    name="Malware File Hash IOC Match",
                    description="File execution or network transfer matching known ransomware/trojan SHA256/MD5 hash in VirusTotal.",
                    severity="CRITICAL",
                    enabled=True,
                    rule_type="threat_intel",
                    mitre_technique_id="T1204.002",
                    mitre_technique_name="User Execution: Malicious File",
                    mitre_tactic="Execution",
                    threshold=1,
                    time_window=60
                ),
                DetectionRuleModel(
                    rule_id="RULE-009",
                    name="Targeted Account Password Spraying",
                    description="Multiple distinct user account authentication failures from a single origin IP address.",
                    severity="HIGH",
                    enabled=True,
                    rule_type="threshold",
                    mitre_technique_id="T1110.003",
                    mitre_technique_name="Brute Force: Password Spraying",
                    mitre_tactic="Credential Access",
                    threshold=3,
                    time_window=300
                ),
                DetectionRuleModel(
                    rule_id="RULE-010",
                    name="Suspicious Windows Remote Logon (Type 10 / Type 3)",
                    description="Unusual Remote Interactive (RDP Type 10) or Network Logon (Type 3) outside baseline hours.",
                    severity="MEDIUM",
                    enabled=True,
                    rule_type="anomaly",
                    mitre_technique_id="T1021.001",
                    mitre_technique_name="Remote Services: Remote Desktop Protocol",
                    mitre_tactic="Lateral Movement",
                    threshold=2,
                    time_window=300
                ),
            ]
            db.add_all(initial_rules)
            db.commit()
            print("[INFO] Seeded default NexusGuard detection rules.")

        # 2. Seed Threat Intelligence IOCs (AbuseIPDB & VirusTotal cache)
        if db.query(ThreatIOC).count() == 0:
            initial_iocs = [
                ThreatIOC(
                    ioc_value="185.220.101.5",
                    ioc_type="ip",
                    threat_type="TOR_EXIT_NODE_C2",
                    severity="CRITICAL",
                    confidence_score=100.0,
                    abuseipdb_reports=842,
                    virustotal_positives=62,
                    virustotal_total=70,
                    country="DE",
                    isp="Zwiebelfreunde e.V.",
                    mitre_technique="T1071.001",
                    description="High-frequency Tor exit relay actively used for Cobalt Strike C2 staging and brute-force scans."
                ),
                ThreatIOC(
                    ioc_value="45.33.32.156",
                    ioc_type="ip",
                    threat_type="RECON_PORT_SCANNER",
                    severity="HIGH",
                    confidence_score=95.0,
                    abuseipdb_reports=412,
                    virustotal_positives=35,
                    virustotal_total=70,
                    country="US",
                    isp="Linode LLC",
                    mitre_technique="T1046",
                    description="Known mass scanning node conducting continuous unauthorized port scans and service enumeration."
                ),
                ThreatIOC(
                    ioc_value="194.26.29.112",
                    ioc_type="ip",
                    threat_type="SSH_BRUTE_FORCER",
                    severity="CRITICAL",
                    confidence_score=100.0,
                    abuseipdb_reports=1280,
                    virustotal_positives=58,
                    virustotal_total=70,
                    country="RU",
                    isp="Chang Way Technologies Co.",
                    mitre_technique="T1110.001",
                    description="Automated Hydra botnet node targeting SSH port 22 and Windows RDP port 3389."
                ),
                ThreatIOC(
                    ioc_value="198.51.100.23",
                    ioc_type="ip",
                    threat_type="C2_BOTNET_SERVER",
                    severity="HIGH",
                    confidence_score=92.0,
                    abuseipdb_reports=198,
                    virustotal_positives=49,
                    virustotal_total=70,
                    country="NL",
                    isp="HostPalace Web Solutions",
                    mitre_technique="T1071",
                    description="Command and Control server associated with DarkComet RAT and Lumma Stealer activity."
                ),
                ThreatIOC(
                    ioc_value="103.251.167.20",
                    ioc_type="ip",
                    threat_type="PHISHING_INFRASTRUCTURE",
                    severity="HIGH",
                    confidence_score=88.0,
                    abuseipdb_reports=310,
                    virustotal_positives=44,
                    virustotal_total=70,
                    country="CN",
                    isp="China Mobile Communications",
                    mitre_technique="T1566.002",
                    description="Malicious host hosting fake Microsoft 365 credential harvesting pages."
                ),
                ThreatIOC(
                    ioc_value="24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
                    ioc_type="hash_sha256",
                    threat_type="RANSOMWARE_WANNACRY",
                    severity="CRITICAL",
                    confidence_score=100.0,
                    abuseipdb_reports=0,
                    virustotal_positives=68,
                    virustotal_total=70,
                    country=None,
                    isp=None,
                    mitre_technique="T1486",
                    description="WannaCry ransomware payload binary hash. Encrypts disk volumes and drops decryptor note."
                ),
                ThreatIOC(
                    ioc_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    ioc_type="hash_sha256",
                    threat_type="CREDENTIAL_DUMPER_MIMIKATZ",
                    severity="CRITICAL",
                    confidence_score=100.0,
                    abuseipdb_reports=0,
                    virustotal_positives=65,
                    virustotal_total=70,
                    country=None,
                    isp=None,
                    mitre_technique="T1003.001",
                    description="Mimikatz LSASS memory credential dumper executable binary."
                ),
                ThreatIOC(
                    ioc_value="c0202cf6aeab8437a638533d14563d35",
                    ioc_type="hash_md5",
                    threat_type="COBALT_STRIKE_BEACON",
                    severity="CRITICAL",
                    confidence_score=98.0,
                    abuseipdb_reports=0,
                    virustotal_positives=60,
                    virustotal_total=70,
                    country=None,
                    isp=None,
                    mitre_technique="T1071.001",
                    description="Cobalt Strike reflective DLL loader payload hash."
                ),
                ThreatIOC(
                    ioc_value="malicious-c2-update.org",
                    ioc_type="domain",
                    threat_type="C2_DOMAIN",
                    severity="HIGH",
                    confidence_score=94.0,
                    abuseipdb_reports=150,
                    virustotal_positives=48,
                    virustotal_total=70,
                    country="US",
                    isp="Cloudflare Inc.",
                    mitre_technique="T1071.001",
                    description="Fast-flux dynamic DNS domain used by threat actors for C2 callback communication."
                ),
            ]
            db.add_all(initial_iocs)
            db.commit()
            print("[INFO] Seeded default NexusGuard threat intelligence IOCs.")

        # 3. Seed or Update SOC Analyst User
        import os
        admin_user = os.environ.get("ADMIN_USERNAME", "admin")
        
        analyst = db.query(User).filter(User.username == admin_user).first()
        if not analyst:
            # Pre-hashed password for 'admin@1512' to avoid leaking plaintext credentials
            default_hash = "$2b$12$zfH2N4NqNp2MhHfObsELa.urLfXgqMTyEe0.CnQvsCnHQgtpbjIri"
            analyst = User(
                username=admin_user,
                email="admin@nexusguard.internal",
                password_hash=default_hash,
                role="ADMIN"
            )
            db.add(analyst)
            print(f"[INFO] Seeded default SOC user: '{admin_user}'. Please change the password in production.")
        
        db.commit()

    finally:
        db.close()
