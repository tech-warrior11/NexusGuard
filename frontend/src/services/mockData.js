/**
 * NexusGuard In-Memory High-Fidelity Mock Telemetry & SOC Engine
 * Ensures 100% full interactive functionality for live preview on static hosting (e.g. Vercel)
 */

export const INITIAL_METRICS = {
  total_logs_ingested: 18492,
  total_alerts: 24,
  active_open_alerts: 6,
  critical_alerts: 2,
  open_incidents: 3,
  threat_level: "DEFCON-1 (CRITICAL ATTACK DETECTED)",
  threat_index_score: 86.4,
  severity_breakdown: {
    critical: 2,
    high: 3,
    medium: 1,
    low: 0
  },
  top_attacking_ips: [
    {
      ip: "194.26.29.112",
      count: 52,
      threat_score: 100.0,
      country: "RU",
      isp: "Chang Way Technologies Co.",
      reputation: "MALICIOUS"
    },
    {
      ip: "185.220.101.5",
      count: 38,
      threat_score: 100.0,
      country: "DE",
      isp: "Zwiebelfreunde e.V. (Tor Exit)",
      reputation: "MALICIOUS"
    },
    {
      ip: "45.33.32.156",
      count: 29,
      threat_score: 95.0,
      country: "US",
      isp: "Linode LLC (Masscan/Nmap)",
      reputation: "MALICIOUS"
    },
    {
      ip: "198.51.100.23",
      count: 18,
      threat_score: 92.0,
      country: "NL",
      isp: "HostPalace Web Solutions",
      reputation: "HIGH"
    },
    {
      ip: "103.251.167.20",
      count: 12,
      threat_score: 88.0,
      country: "CN",
      isp: "China Mobile Communications",
      reputation: "HIGH"
    }
  ],
  mitre_tactics_breakdown: [
    {
      tactic: "Credential Access",
      count: 5,
      technique_ids: ["T1110.001", "T1110.003", "T1003.001"]
    },
    {
      tactic: "Initial Access",
      count: 4,
      technique_ids: ["T1078", "T1566.002"]
    },
    {
      tactic: "Command & Control",
      count: 3,
      technique_ids: ["T1071.001"]
    },
    {
      tactic: "Privilege Escalation",
      count: 2,
      technique_ids: ["T1548.003"]
    },
    {
      tactic: "Execution",
      count: 2,
      technique_ids: ["T1059.001", "T1204.002"]
    },
    {
      tactic: "Discovery",
      count: 2,
      technique_ids: ["T1046"]
    }
  ],
  event_type_distribution: {
    authentication: 9420,
    network_scan: 4210,
    powershell_exec: 1850,
    c2_beacon: 1612,
    privilege_escalation: 1400
  },
  log_sources_distribution: {
    linux: 7850,
    windows: 6420,
    network: 4222
  },
  activity_timeline: [
    { time_label: "00:00", logs_count: 540, alerts_count: 1 },
    { time_label: "03:00", logs_count: 420, alerts_count: 0 },
    { time_label: "06:00", logs_count: 610, alerts_count: 1 },
    { time_label: "09:00", logs_count: 1150, alerts_count: 3 },
    { time_label: "12:00", logs_count: 1420, alerts_count: 5 },
    { time_label: "15:00", logs_count: 1980, alerts_count: 7 },
    { time_label: "18:00", logs_count: 1640, alerts_count: 4 },
    { time_label: "21:00", logs_count: 1280, alerts_count: 3 }
  ]
};

export const INITIAL_RULES = [
  {
    id: 1,
    rule_id: "RULE-001",
    name: "SSH/Linux Auth Brute Force Detection",
    description: "5 or more failed authentication attempts from the same IP within a 5-minute window.",
    severity: "HIGH",
    enabled: true,
    rule_type: "threshold",
    mitre_technique_id: "T1110.001",
    mitre_technique_name: "Brute Force: Password Guessing",
    mitre_tactic: "Credential Access",
    threshold: 5,
    time_window: 300,
    trigger_count: 14
  },
  {
    id: 2,
    rule_id: "RULE-002",
    name: "Windows Event 4625 Failed Logon Burst",
    description: "Multiple Event 4625 (Failed Logon) occurrences detected indicating password attack.",
    severity: "HIGH",
    enabled: true,
    rule_type: "threshold",
    mitre_technique_id: "T1110.001",
    mitre_technique_name: "Brute Force: Password Guessing",
    mitre_tactic: "Credential Access",
    threshold: 4,
    time_window: 300,
    trigger_count: 9
  },
  {
    id: 3,
    rule_id: "RULE-003",
    name: "Compromise: Login Success Following Failures",
    description: "Successful authentication immediately following multiple failed login attempts from same entity.",
    severity: "CRITICAL",
    enabled: true,
    rule_type: "sequence",
    mitre_technique_id: "T1078",
    mitre_technique_name: "Valid Accounts",
    mitre_tactic: "Initial Access",
    threshold: 3,
    time_window: 300,
    trigger_count: 4
  },
  {
    id: 4,
    rule_id: "RULE-004",
    name: "Suspicious Privilege Escalation / Sudo Abuse",
    description: "Unauthorized sudo command execution or attempted root access elevation.",
    severity: "CRITICAL",
    enabled: true,
    rule_type: "signature",
    mitre_technique_id: "T1548.003",
    mitre_technique_name: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    mitre_tactic: "Privilege Escalation",
    threshold: 1,
    time_window: 60,
    trigger_count: 6
  },
  {
    id: 5,
    rule_id: "RULE-005",
    name: "Network Port Scan & Reconnaissance",
    description: "Rapid connection attempts across 4 or more distinct target ports from a single IP.",
    severity: "HIGH",
    enabled: true,
    rule_type: "anomaly",
    mitre_technique_id: "T1046",
    mitre_technique_name: "Network Service Discovery",
    mitre_tactic: "Discovery",
    threshold: 4,
    time_window: 180,
    trigger_count: 11
  },
  {
    id: 6,
    rule_id: "RULE-006",
    name: "Malicious Threat Intel C2 IP Activity",
    description: "Inbound/outbound communication with an IP flagged in AbuseIPDB / VirusTotal threat feeds.",
    severity: "CRITICAL",
    enabled: true,
    rule_type: "threat_intel",
    mitre_technique_id: "T1071.001",
    mitre_technique_name: "Application Layer Protocol: Web Protocols",
    mitre_tactic: "Command and Control",
    threshold: 1,
    time_window: 60,
    trigger_count: 8
  },
  {
    id: 7,
    rule_id: "RULE-007",
    name: "Obfuscated PowerShell / Base64 Command Execution",
    description: "PowerShell process invoked with Base64 encoding (-enc, -encodedcommand, FromBase64String).",
    severity: "HIGH",
    enabled: true,
    rule_type: "signature",
    mitre_technique_id: "T1059.001",
    mitre_technique_name: "Command and Scripting Interpreter: PowerShell",
    mitre_tactic: "Execution",
    threshold: 1,
    time_window: 60,
    trigger_count: 5
  },
  {
    id: 8,
    rule_id: "RULE-008",
    name: "Malware File Hash IOC Match",
    description: "File execution or network transfer matching known ransomware/trojan SHA256/MD5 hash in VirusTotal.",
    severity: "CRITICAL",
    enabled: true,
    rule_type: "threat_intel",
    mitre_technique_id: "T1204.002",
    mitre_technique_name: "User Execution: Malicious File",
    mitre_tactic: "Execution",
    threshold: 1,
    time_window: 60,
    trigger_count: 3
  },
  {
    id: 9,
    rule_id: "RULE-009",
    name: "Targeted Account Password Spraying",
    description: "Multiple distinct user account authentication failures from a single origin IP address.",
    severity: "HIGH",
    enabled: true,
    rule_type: "threshold",
    mitre_technique_id: "T1110.003",
    mitre_technique_name: "Brute Force: Password Spraying",
    mitre_tactic: "Credential Access",
    threshold: 3,
    time_window: 300,
    trigger_count: 7
  },
  {
    id: 10,
    rule_id: "RULE-010",
    name: "Suspicious Windows Remote Logon (Type 10 / Type 3)",
    description: "Unusual Remote Interactive (RDP Type 10) or Network Logon (Type 3) outside baseline hours.",
    severity: "MEDIUM",
    enabled: true,
    rule_type: "anomaly",
    mitre_technique_id: "T1021.001",
    mitre_technique_name: "Remote Services: Remote Desktop Protocol",
    mitre_tactic: "Lateral Movement",
    threshold: 2,
    time_window: 300,
    trigger_count: 4
  }
];

export const INITIAL_ALERTS = [
  {
    id: 1,
    alert_type: "THREAT_INTEL_C2_MATCH",
    severity: "CRITICAL",
    source_ip: "185.220.101.5",
    destination_ip: "10.0.0.20",
    username: "system_svc",
    description: "Inbound beaconing detected to known Tor exit node C2 relay (Confidence 100%, 842 abuse reports). Matches Cobalt Strike profile.",
    rule_id: "RULE-006",
    status: "OPEN",
    mitre_technique_id: "T1071.001",
    mitre_technique_name: "Application Layer Protocol: Web Protocols",
    mitre_tactic: "Command and Control",
    ioc_value: "185.220.101.5",
    ioc_type: "ip",
    threat_score: 100.0,
    timestamp: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 4 * 60 * 1000).toISOString()
  },
  {
    id: 2,
    alert_type: "PRIVILEGE_ESCALATION",
    severity: "CRITICAL",
    source_ip: "10.0.0.45",
    destination_ip: "10.0.0.1",
    username: "www-data",
    description: "Unauthorized sudo execution attempted by service user www-data: '/bin/su - root' without valid tty.",
    rule_id: "RULE-004",
    status: "OPEN",
    mitre_technique_id: "T1548.003",
    mitre_technique_name: "Sudo Abuse & Caching",
    mitre_tactic: "Privilege Escalation",
    ioc_value: "10.0.0.45",
    ioc_type: "ip",
    threat_score: 95.0,
    timestamp: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 11 * 60 * 1000).toISOString()
  },
  {
    id: 3,
    alert_type: "BRUTE_FORCE_BURST",
    severity: "HIGH",
    source_ip: "194.26.29.112",
    destination_ip: "10.0.0.15",
    username: "root",
    description: "Automated dictionary attack detected: 14 failed SSH authentication attempts within 90 seconds from known botnet node.",
    rule_id: "RULE-001",
    status: "OPEN",
    mitre_technique_id: "T1110.001",
    mitre_technique_name: "Brute Force: Password Guessing",
    mitre_tactic: "Credential Access",
    ioc_value: "194.26.29.112",
    ioc_type: "ip",
    threat_score: 100.0,
    timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 25 * 60 * 1000).toISOString()
  },
  {
    id: 4,
    alert_type: "OBFUSCATED_POWERSHELL",
    severity: "HIGH",
    source_ip: "10.0.0.88",
    destination_ip: "185.220.101.5",
    username: "finance_lead",
    description: "Suspicious execution of encoded PowerShell command: powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgA...",
    rule_id: "RULE-007",
    status: "OPEN",
    mitre_technique_id: "T1059.001",
    mitre_technique_name: "PowerShell: Encoded Commands",
    mitre_tactic: "Execution",
    ioc_value: "powershell_enc",
    ioc_type: "command",
    threat_score: 90.0,
    timestamp: new Date(Date.now() - 48 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 48 * 60 * 1000).toISOString()
  },
  {
    id: 5,
    alert_type: "PORT_SCAN_RECON",
    severity: "HIGH",
    source_ip: "45.33.32.156",
    destination_ip: "10.0.0.15",
    username: null,
    description: "Sequential TCP SYN probes across ports 21, 22, 80, 443, 3389, 8080 detected within 12 seconds.",
    rule_id: "RULE-005",
    status: "OPEN",
    mitre_technique_id: "T1046",
    mitre_technique_name: "Network Service Discovery",
    mitre_tactic: "Discovery",
    ioc_value: "45.33.32.156",
    ioc_type: "ip",
    threat_score: 95.0,
    timestamp: new Date(Date.now() - 72 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 72 * 60 * 1000).toISOString()
  },
  {
    id: 6,
    alert_type: "MALWARE_HASH_MATCH",
    severity: "CRITICAL",
    source_ip: "10.0.0.33",
    destination_ip: "10.0.0.1",
    username: "accounting_usr",
    description: "File write event matches known WannaCry ransomware binary SHA256 (68/70 VirusTotal detection ratio).",
    rule_id: "RULE-008",
    status: "OPEN",
    mitre_technique_id: "T1486",
    mitre_technique_name: "Data Encrypted for Impact",
    mitre_tactic: "Impact",
    ioc_value: "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
    ioc_type: "hash_sha256",
    threat_score: 100.0,
    timestamp: new Date(Date.now() - 95 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 95 * 60 * 1000).toISOString()
  }
];

export const INITIAL_INCIDENTS = [
  {
    id: 1,
    incident_number: "INC-2026-0041",
    alert_id: 1,
    title: "Cobalt Strike C2 Beaconing & Lateral Reconnaissance from DMZ Host",
    severity: "CRITICAL",
    status: "OPEN",
    assigned_to: "soc_analyst",
    summary: "High-priority C2 connection established between internal Linux application server (10.0.0.20) and verified Tor exit relay (185.220.101.5). Packet inspector shows periodic HTTPS beaconing intervals.",
    investigation_notes: "Host isolated from main VLAN. Process memory dump acquired. Threat intel indicates source IP associated with FIN7 / Cobalt Strike infrastructure.",
    mitre_tactics: "Command and Control, Initial Access",
    mitre_techniques: "T1071.001, T1078",
    iocs: "[\"185.220.101.5\", \"c0202cf6aeab8437a638533d14563d35\"]",
    containment_steps: "1. Applied ingress/egress border firewall block rule for 185.220.101.5.\n2. Revoked active Kerberos service tickets for system_svc.\n3. Quarantined VM snapshot for forensic triage.",
    remediation_notes: "Deploy updated EDR agents, enforce strict egress egress proxy filtering, and rotate all database service credentials.",
    created_at: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    alert: INITIAL_ALERTS[0]
  },
  {
    id: 2,
    incident_number: "INC-2026-0039",
    alert_id: 3,
    title: "Distributed SSH Credential Brute Force Targeting Perimeter Bastion",
    severity: "HIGH",
    status: "INVESTIGATING",
    assigned_to: "soc_analyst",
    summary: "Automated Hydra dictionary scan originating from 194.26.29.112 attempting default passwords against administrative root accounts.",
    investigation_notes: "Fail2Ban rate limiting triggered. Inbound port 22 access restricted to VPN gateway CIDR.",
    mitre_tactics: "Credential Access",
    mitre_techniques: "T1110.001",
    iocs: "[\"194.26.29.112\"]",
    containment_steps: "Null-routed IP on edge router. Enforced SSH key-only authentication.",
    remediation_notes: "Disable password authentication globally on all Linux perimeter hosts.",
    created_at: new Date(Date.now() - 120 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 40 * 60 * 1000).toISOString(),
    alert: INITIAL_ALERTS[2]
  },
  {
    id: 3,
    incident_number: "INC-2026-0035",
    alert_id: 6,
    title: "WannaCry Ransomware Execution Intercepted via EDR Signature",
    severity: "CRITICAL",
    status: "CONTAINED",
    assigned_to: "soc_lead",
    summary: "Malicious payload matching WannaCrypt SHA256 signature dropped into C:\\Windows\\Temp. Process execution halted before encryption routine initialized.",
    investigation_notes: "File quarantine verified. Host 10.0.0.33 network adapter disabled remotely. Verified MS17-010 SMB patch status.",
    mitre_tactics: "Impact, Execution",
    mitre_techniques: "T1486, T1204.002",
    iocs: "[\"24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c\"]",
    containment_steps: "EDR quarantined binary. Host isolated from local subnet. Domain controller inspected for suspicious replication calls.",
    remediation_notes: "Audit all domain endpoints for SMBv1 enablement and enforce patch KB4012212.",
    created_at: new Date(Date.now() - 360 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 180 * 60 * 1000).toISOString(),
    alert: INITIAL_ALERTS[5]
  }
];

export const INITIAL_LOGS = [
  {
    id: 101,
    timestamp: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    source: "network",
    event_type: "c2_beacon",
    username: "system_svc",
    source_ip: "185.220.101.5",
    destination_ip: "10.0.0.20",
    port: 443,
    protocol: "HTTPS",
    action: "connect",
    status: "detected",
    message: "Outbound TLS heartbeat packet stream to Tor Exit C2 Node 185.220.101.5",
    raw_payload: "14:32:05.987654 IP 185.220.101.5.443 > 10.0.0.20.51222: Flags [P.], length 256 (C2_BEACON_HEARTBEAT)"
  },
  {
    id: 102,
    timestamp: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
    source: "linux",
    event_type: "privilege_escalation",
    username: "www-data",
    source_ip: "10.0.0.45",
    destination_ip: "10.0.0.1",
    port: 22,
    protocol: "SSH",
    action: "sudo",
    status: "denied",
    message: "sudo: www-data : 3 incorrect password attempts ; TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash",
    raw_payload: "Sep 29 14:28:11 server sudo: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty= ruser=www-data rhost= user=www-data"
  },
  {
    id: 103,
    timestamp: new Date(Date.now() - 14 * 60 * 1000).toISOString(),
    source: "linux",
    event_type: "authentication",
    username: "root",
    source_ip: "194.26.29.112",
    destination_ip: "10.0.0.15",
    port: 22,
    protocol: "SSH",
    action: "login",
    status: "failed",
    message: "Failed password for invalid user root from 194.26.29.112 port 49212 ssh2",
    raw_payload: "Sep 29 14:22:01 server sshd[1234]: Failed password for root from 194.26.29.112 port 49212 ssh2"
  },
  {
    id: 104,
    timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    source: "linux",
    event_type: "authentication",
    username: "admin",
    source_ip: "194.26.29.112",
    destination_ip: "10.0.0.15",
    port: 22,
    protocol: "SSH",
    action: "login",
    status: "failed",
    message: "Failed password for admin from 194.26.29.112 port 49213 ssh2",
    raw_payload: "Sep 29 14:21:58 server sshd[1233]: Failed password for admin from 194.26.29.112 port 49213 ssh2"
  },
  {
    id: 105,
    timestamp: new Date(Date.now() - 16 * 60 * 1000).toISOString(),
    source: "linux",
    event_type: "authentication",
    username: "ubuntu",
    source_ip: "194.26.29.112",
    destination_ip: "10.0.0.15",
    port: 22,
    protocol: "SSH",
    action: "login",
    status: "failed",
    message: "Failed password for ubuntu from 194.26.29.112 port 49214 ssh2",
    raw_payload: "Sep 29 14:21:55 server sshd[1232]: Failed password for ubuntu from 194.26.29.112 port 49214 ssh2"
  },
  {
    id: 106,
    timestamp: new Date(Date.now() - 22 * 60 * 1000).toISOString(),
    source: "windows",
    event_type: "powershell_exec",
    username: "finance_lead",
    source_ip: "10.0.0.88",
    destination_ip: "185.220.101.5",
    port: 443,
    protocol: "HTTPS",
    action: "execute",
    status: "detected",
    message: "PowerShell.exe invoked with encoded payload: -enc SQBFAFgA...",
    raw_payload: "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4688</EventID></System><EventData><Data Name='NewProcessName'>powershell.exe</Data><Data Name='CommandLine'>powershell.exe -enc SQBFAFgA...</Data></EventData></Event>"
  },
  {
    id: 107,
    timestamp: new Date(Date.now() - 31 * 60 * 1000).toISOString(),
    source: "windows",
    event_type: "authentication",
    username: "Administrator",
    source_ip: "194.26.29.112",
    destination_ip: "10.0.0.10",
    port: 3389,
    protocol: "RDP",
    action: "login",
    status: "failed",
    message: "An account failed to log on. Event ID: 4625, Logon Type: 10 (RemoteInteractive)",
    raw_payload: "Event ID: 4625, Account Name: Administrator, Workstation Name: WIN-SRV01, Status: 0xC000006D"
  },
  {
    id: 108,
    timestamp: new Date(Date.now() - 44 * 60 * 1000).toISOString(),
    source: "network",
    event_type: "network_scan",
    username: null,
    source_ip: "45.33.32.156",
    destination_ip: "10.0.0.15",
    port: 80,
    protocol: "TCP",
    action: "scan",
    status: "blocked",
    message: "TCP SYN stealth scan packet received on port 80",
    raw_payload: "14:32:01.123456 IP 45.33.32.156.54122 > 10.0.0.15.80: Flags [S], seq 0, win 65535, length 0"
  },
  {
    id: 109,
    timestamp: new Date(Date.now() - 44 * 60 * 1000).toISOString(),
    source: "network",
    event_type: "network_scan",
    username: null,
    source_ip: "45.33.32.156",
    destination_ip: "10.0.0.15",
    port: 443,
    protocol: "TCP",
    action: "scan",
    status: "blocked",
    message: "TCP SYN stealth scan packet received on port 443",
    raw_payload: "14:32:01.124500 IP 45.33.32.156.54123 > 10.0.0.15.443: Flags [S], seq 0, win 65535, length 0"
  },
  {
    id: 110,
    timestamp: new Date(Date.now() - 55 * 60 * 1000).toISOString(),
    source: "windows",
    event_type: "authentication",
    username: "john.analyst",
    source_ip: "10.0.0.5",
    destination_ip: "10.0.0.10",
    port: 3389,
    protocol: "RDP",
    action: "login",
    status: "success",
    message: "An account was successfully logged on. Event ID: 4624, Logon Type: 2 (Interactive)",
    raw_payload: "Event ID: 4624, TargetUserName: john.analyst, LogonType: 2, Workstation: SOC-WORKSTATION-01"
  }
];

export const KNOWN_IOC_DATABASE = {
  "185.220.101.5": {
    indicator: "185.220.101.5",
    indicator_type: "ip",
    threat_level: "CRITICAL",
    overall_confidence: 100.0,
    description: "High-frequency Tor exit relay actively used for Cobalt Strike C2 staging and brute-force scans.",
    mitre_technique_id: "T1071.001",
    mitre_technique_name: "Application Layer Protocol: Web Protocols",
    abuseipdb: {
      ip_address: "185.220.101.5",
      is_public: true,
      ip_version: 4,
      is_whitelisted: false,
      abuse_confidence_score: 100,
      country_code: "DE",
      country_name: "Germany",
      usage_type: "Data Center / Tor Exit",
      isp: "Zwiebelfreunde e.V.",
      domain: "torservers.net",
      hostnames: ["tor-exit-node-05.torservers.net"],
      is_tor: true,
      total_reports: 842,
      num_distinct_users: 184,
      last_reported_at: new Date().toISOString()
    },
    virustotal: {
      indicator: "185.220.101.5",
      indicator_type: "ip",
      reputation: -88,
      malicious_votes: 62,
      suspicious_votes: 6,
      harmless_votes: 2,
      undetected_votes: 0,
      total_engines: 70,
      detection_ratio: "62/70",
      threat_classification: "Cobalt Strike C2 / Tor Exit Node",
      engine_verdicts: {
        Kaspersky: "Malicious (Tor Exit / C2)",
        CrowdStrike: "Threat Actor Relay",
        Sophos: "Cobalt Strike Beacon Target",
        Fortinet: "Botnet C2 Relay"
      },
      sandbox_tags: ["c2-beacon", "tor-relay", "cobalt-strike"]
    },
    cached: true,
    queried_at: new Date().toISOString()
  },
  "194.26.29.112": {
    indicator: "194.26.29.112",
    indicator_type: "ip",
    threat_level: "CRITICAL",
    overall_confidence: 100.0,
    description: "Automated Hydra botnet node targeting SSH port 22 and Windows RDP port 3389.",
    mitre_technique_id: "T1110.001",
    mitre_technique_name: "Brute Force: Password Guessing",
    abuseipdb: {
      ip_address: "194.26.29.112",
      is_public: true,
      ip_version: 4,
      is_whitelisted: false,
      abuse_confidence_score: 100,
      country_code: "RU",
      country_name: "Russian Federation",
      usage_type: "Hosting / Botnet Scanner",
      isp: "Chang Way Technologies Co.",
      domain: "changway.ru",
      hostnames: ["scanner-node-99.changway.ru"],
      is_tor: false,
      total_reports: 1280,
      num_distinct_users: 312,
      last_reported_at: new Date().toISOString()
    },
    virustotal: {
      indicator: "194.26.29.112",
      indicator_type: "ip",
      reputation: -94,
      malicious_votes: 58,
      suspicious_votes: 8,
      harmless_votes: 4,
      undetected_votes: 0,
      total_engines: 70,
      detection_ratio: "58/70",
      threat_classification: "SSH Dictionary Brute Force Bot",
      engine_verdicts: {
        Microsoft: "Credential Access Brute Force",
        PaloAlto: "Known Malicious Scanner",
        Symantec: "Hydra Attack Origin"
      },
      sandbox_tags: ["ssh-brute-force", "botnet-scanner"]
    },
    cached: true,
    queried_at: new Date().toISOString()
  },
  "45.33.32.156": {
    indicator: "45.33.32.156",
    indicator_type: "ip",
    threat_level: "HIGH",
    overall_confidence: 95.0,
    description: "Known mass scanning node conducting continuous unauthorized port scans and service enumeration.",
    mitre_technique_id: "T1046",
    mitre_technique_name: "Network Service Discovery",
    abuseipdb: {
      ip_address: "45.33.32.156",
      is_public: true,
      ip_version: 4,
      is_whitelisted: false,
      abuse_confidence_score: 95,
      country_code: "US",
      country_name: "United States",
      usage_type: "Data Center",
      isp: "Linode LLC",
      domain: "scan-me.org",
      hostnames: ["recon-cluster-01.scan-me.org"],
      is_tor: false,
      total_reports: 412,
      num_distinct_users: 98,
      last_reported_at: new Date().toISOString()
    },
    virustotal: {
      indicator: "45.33.32.156",
      indicator_type: "ip",
      reputation: -65,
      malicious_votes: 35,
      suspicious_votes: 12,
      harmless_votes: 23,
      undetected_votes: 0,
      total_engines: 70,
      detection_ratio: "35/70",
      threat_classification: "Port Scanner / Reconnaissance",
      engine_verdicts: {
        AlienVault: "Malicious Reconnaissance Probe",
        TrendMicro: "Suspicious Port Scanner"
      },
      sandbox_tags: ["port-scan", "nmap", "recon"]
    },
    cached: true,
    queried_at: new Date().toISOString()
  },
  "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": {
    indicator: "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
    indicator_type: "hash_sha256",
    threat_level: "CRITICAL",
    overall_confidence: 100.0,
    description: "WannaCry ransomware payload binary hash. Encrypts disk volumes and drops decryptor note.",
    mitre_technique_id: "T1486",
    mitre_technique_name: "Data Encrypted for Impact",
    abuseipdb: null,
    virustotal: {
      indicator: "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
      indicator_type: "hash_sha256",
      reputation: -100,
      malicious_votes: 68,
      suspicious_votes: 2,
      harmless_votes: 0,
      undetected_votes: 0,
      total_engines: 70,
      detection_ratio: "68/70",
      threat_classification: "Ransomware.WannaCrypt.Win32",
      engine_verdicts: {
        Kaspersky: "Trojan-Ransom.Win32.Wanna.m",
        Microsoft: "Ransom:Win32/WannaCrypt",
        CrowdStrike: "win/malicious_confidence_100%",
        Sophos: "Troj/Wanna-G",
        Symantec: "Ransom.Wannacry"
      },
      sandbox_tags: ["ransomware", "wannacry", "killswitch-domain", "smb-exploit"]
    },
    cached: true,
    queried_at: new Date().toISOString()
  },
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
    indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    indicator_type: "hash_sha256",
    threat_level: "CRITICAL",
    overall_confidence: 100.0,
    description: "Mimikatz LSASS memory credential dumper executable binary.",
    mitre_technique_id: "T1003.001",
    mitre_technique_name: "OS Credential Dumping: LSASS Memory",
    abuseipdb: null,
    virustotal: {
      indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      indicator_type: "hash_sha256",
      reputation: -95,
      malicious_votes: 65,
      suspicious_votes: 3,
      harmless_votes: 2,
      undetected_votes: 0,
      total_engines: 70,
      detection_ratio: "65/70",
      threat_classification: "HackTool.Win64.Mimikatz",
      engine_verdicts: {
        Microsoft: "HackTool:Win64/Mikatz",
        Kaspersky: "not-a-virus:PSWTool.Win32.Mimikatz",
        PaloAlto: "generic.mimikatz"
      },
      sandbox_tags: ["lsass-dump", "mimikatz", "credential-theft"]
    },
    cached: true,
    queried_at: new Date().toISOString()
  },
  "10.0.0.15": {
    indicator: "10.0.0.15",
    indicator_type: "ip",
    threat_level: "CLEAN",
    overall_confidence: 0.0,
    description: "Clean internal RFC1918 enterprise asset (Linux Bastion Host). No public threat records found.",
    mitre_technique_id: null,
    mitre_technique_name: null,
    abuseipdb: {
      ip_address: "10.0.0.15",
      is_public: false,
      ip_version: 4,
      is_whitelisted: true,
      abuse_confidence_score: 0,
      country_code: "INTERNAL",
      country_name: "Private Intranet Subnet",
      usage_type: "Private Network (RFC 1918)",
      isp: "Enterprise Internal LAN",
      domain: "nexusguard.internal",
      hostnames: ["bastion-linux-01.internal"],
      is_tor: false,
      total_reports: 0,
      num_distinct_users: 0,
      last_reported_at: null
    },
    virustotal: {
      indicator: "10.0.0.15",
      indicator_type: "ip",
      reputation: 0,
      malicious_votes: 0,
      suspicious_votes: 0,
      harmless_votes: 70,
      undetected_votes: 0,
      total_engines: 70,
      detection_ratio: "0/70",
      threat_classification: "Clean Private IP",
      engine_verdicts: {},
      sandbox_tags: ["internal", "clean"]
    },
    cached: true,
    queried_at: new Date().toISOString()
  }
};

export const MITRE_MATRIX_DATA = {
  framework: "MITRE ATT&CK Enterprise Matrix v14",
  tactics: {
    "Initial Access": [
      { id: "T1078", name: "Valid Accounts", detected_by: "RULE-003", severity: "CRITICAL" },
      { id: "T1566", name: "Phishing", detected_by: "THREAT_INTEL", severity: "HIGH" }
    ],
    "Execution": [
      { id: "T1059.001", name: "PowerShell: Encoded Commands", detected_by: "RULE-007", severity: "HIGH" },
      { id: "T1204.002", name: "User Execution: Malicious File", detected_by: "RULE-008", severity: "CRITICAL" }
    ],
    "Privilege Escalation": [
      { id: "T1548.003", name: "Sudo Abuse & Caching", detected_by: "RULE-004", severity: "CRITICAL" }
    ],
    "Credential Access": [
      { id: "T1110.001", name: "Brute Force: Password Guessing", detected_by: "RULE-001, RULE-002", severity: "HIGH" },
      { id: "T1110.003", name: "Password Spraying", detected_by: "RULE-009", severity: "HIGH" },
      { id: "T1003.001", name: "LSASS Memory Dump (Mimikatz)", detected_by: "RULE-008", severity: "CRITICAL" }
    ],
    "Discovery": [
      { id: "T1046", name: "Network Service Discovery (Nmap)", detected_by: "RULE-005", severity: "HIGH" }
    ],
    "Lateral Movement": [
      { id: "T1021.001", name: "Remote Desktop Protocol (RDP)", detected_by: "RULE-010", severity: "MEDIUM" }
    ],
    "Command and Control": [
      { id: "T1071.001", name: "Web Protocols C2 (Cobalt Strike)", detected_by: "RULE-006", severity: "CRITICAL" }
    ],
    "Impact": [
      { id: "T1486", name: "Data Encrypted for Impact (Ransomware)", detected_by: "RULE-008", severity: "CRITICAL" }
    ]
  }
};
