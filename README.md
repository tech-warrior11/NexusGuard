# 🛡️ NexusGuard — Security Operations & Threat Detection Platform

[![Live Preview](https://img.shields.io/badge/Live_Preview-View_App-00C7B7?style=for-the-badge&logo=vercel&logoColor=white)](https://nexus-guard-six.vercel.app)

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14-FF6600?style=for-the-badge)](https://attack.mitre.org)
[![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)

**NexusGuard** is an enterprise-grade Security Operations Center (SOC) monitoring and automated threat detection platform. It centralizes security log ingestion, normalizes events across Linux servers, Windows Event Logs, and Network packet captures, executes real-time correlation detection rules, automates IOC enrichment via AbuseIPDB and VirusTotal, aligns incidents with the MITRE ATT&CK® framework, and provides an interactive analyst workbench with CyberChef decoding tools and downloadable Incident Response Reports.

---

## 🧰 Tools & Technology Matrix

| Tool / Technology | Role in NexusGuard |
| :--- | :--- |
| ![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black) | Security server log ingestion (`/var/log/auth.log`, `sshd`, `sudo` privilege escalation) |
| ![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white) | Windows Security Event log parsing (`4625` Failed Logon, `4624` Success, `4688` Process Creation) |
| ![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white) | Network traffic packet stream investigation, TCP SYN stealth scans, C2 beacons, reverse shells |
| ![Nmap](https://img.shields.io/badge/Nmap-000000?style=for-the-badge&logo=nmap&logoColor=white) | Reconnaissance detection, multi-port scanning simulation, and perimeter service discovery |
| ![SIEM](https://img.shields.io/badge/SIEM-FF4500?style=for-the-badge&logo=splunk&logoColor=white) | Centralized event normalization, multi-field filtering, full-text search, and detection correlation |
| ![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white) | File Hash (MD5/SHA256) and domain reputation checks, multi-engine detection ratios (e.g., 68/70) |
| ![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-CC0000?style=for-the-badge&logo=security-scorecard&logoColor=white) | IP abuse confidence scoring (0-100%), ISP/Geo data, Tor exit node detection, abuse reports |
| ![CyberChef](https://img.shields.io/badge/CyberChef-0099FF?style=for-the-badge&logo=chef&logoColor=white) | Security analyst utility for Base64 (UTF-8 & UTF-16LE PowerShell), Hex, URL, XOR, ROT13, Defang/Refang, and Regex IOC extraction |
| ![MITRE](https://img.shields.io/badge/MITRE-FF6600?style=for-the-badge) | Adversary tactic & technique mapping (T1110, T1046, T1059.001, T1071, T1204, T1548, T1486) |
| ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) | Backend detection engine, rule evaluators, incident report generators, and SQLite data storage |
| ![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white) | High-performance asynchronous REST API and WebSockets for real-time live alert streaming |
| ![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB) | Cyberpunk dark glassmorphism SOC dashboard, visual SVG analytics, and interactive case workbench |
| ![Bcrypt](https://img.shields.io/badge/Bcrypt-000000?style=for-the-badge&logo=npm&logoColor=white) | Advanced cryptographic hashing to ensure that all user credentials are 100% securely managed without plain-text exposure |

---

## 🔥 Platform Workflow Architecture

```text
       ┌─────────────────────────┐       ┌─────────────────────────┐
       │   Linux Security Logs   │       │  Windows Security Events│
       │   (/var/log/auth.log)   │       │  (4625, 4624, 4688 XML) │
       └────────────┬────────────┘       └────────────┬────────────┘
                    │                                 │
                    ▼                                 ▼
       ┌───────────────────────────────────────────────────────────┐
       │            NexusGuard Log Normalizer & Parser            │
       └─────────────────────────────┬─────────────────────────────┘
                                     │
                                     ▼
       ┌───────────────────────────────────────────────────────────┐
       │              Real-Time Detection Engine (Rules)           │
       │   • Brute Force (T1110)          • Sudo Abuse (T1548)     │
       │   • Port Scan (T1046)            • PowerShell -enc (T1059)│
       │   • Password Spray (T1110.003)   • WannaCry Hash (T1486)  │
       └──────────────┬───────────────────────────────┬────────────┘
                      │                               │
                      ▼                               ▼
       ┌─────────────────────────────┐ ┌───────────────────────────┐
       │     Threat Intel Hub        │ │  Real-Time Alert Feed     │
       │   • AbuseIPDB (Score 0-100) │ │  • DEFCON Gauge           │
       │   • VirusTotal (68/70 Ratio)│ │  • MITRE Technique Tags   │
       └──────────────┬──────────────┘ └──────────────┬────────────┘
                      │                               │
                      └───────────────┬───────────────┘
                                      │
                                      ▼
       ┌───────────────────────────────────────────────────────────┐
       │           SOC Analyst Investigation Workbench             │
       │   • 1-Click Alert-to-Incident Case Escalation             │
       │   • Integrated CyberChef Payload De-obfuscation           │
       │   • Wireshark / PCAP Stream Packet Inspector              │
       │   • Evidence Notes & Containment Checklist Tracker        │
       └──────────────────────────────┬────────────────────────────┘
                                      │
                                      ▼
       ┌───────────────────────────────────────────────────────────┐
       │       Automated Incident Response Documentation           │
       │   • Export Formal Markdown & HTML SOC Incident Reports    │
       └───────────────────────────────────────────────────────────┘
```

---

## 🧪 Hands-On Investigation Scenarios (Built-In Labs)

NexusGuard includes several interactive attack scenarios that trigger real-time detection:

### 1. SSH Brute Force Detection (Hydra)
- **Attack:** Automated dictionary password guessing on SSH port 22 from origin `194.26.29.112`.
- **Detection Rule:** `RULE-001` (Threshold: $\ge 5$ failures in 5 minutes).
- **MITRE ATT&CK:** `T1110.001 - Brute Force: Password Guessing` (*Credential Access*).
- **Workflow:** Ingest Linux auth failures $\to$ Alert generated $\to$ Query AbuseIPDB $\to$ Escalate to Incident $\to$ Apply firewall drop rule.

### 2. Network Reconnaissance & Port Scan (Nmap)
- **Attack:** TCP SYN stealth scan probing multiple ports from a single origin.
- **Detection Rule:** `RULE-005` (Threshold: $\ge 4$ distinct target ports).
- **MITRE ATT&CK:** `T1046 - Network Service Discovery` (*Discovery*).
- **Workflow:** Ingest network stream $\to$ Wireshark PCAP analysis $\to$ Alert generated $\to$ Restrict open edge ports.

### 3. Malicious C2 Beacon Communication
- **Attack:** Compromised internal host communicating with Cobalt Strike / Tor Exit C2 node.
- **Detection Rule:** `RULE-006` (Threat Intelligence IOC Match).
- **MITRE ATT&CK:** `T1071.001 - Application Layer Protocol: Web Protocols` (*Command & Control*).
- **Workflow:** Threat Intel hit $\to$ AbuseIPDB confirms 100% confidence $\to$ Isolate internal host.

### 4. Obfuscated PowerShell Payload (CyberChef Lab)
- **Attack:** Execution of Base64 encoded PowerShell string: `powershell.exe -enc SQBFAFgAKABOAGUAdw...`.
- **Detection Rule:** `RULE-007` (Signature match on `-enc`, `FromBase64String`, `DownloadString`).
- **MITRE ATT&CK:** `T1059.001 - Command and Scripting Interpreter: PowerShell` (*Execution*).
- **Workflow:** Copy encoded payload $\to$ CyberChef Base64 Decode (UTF-16LE) $\to$ Extract stage-2 C2 download URL $\to$ Update EDR rules.

### 5. Windows Security Event 4625/4624 Attack Chain
- **Attack:** Multiple Windows Event `4625` logon failures followed immediately by a successful `4624` logon.
- **Detection Rule:** `RULE-003` & `RULE-002`.
- **MITRE ATT&CK:** `T1078 - Valid Accounts` (*Initial Access / Lateral Movement*).
- **Workflow:** Correlate event IDs $\to$ CRITICAL alert $\to$ Invalidate Kerberos/NTLM tokens.

### 6. WannaCry Ransomware Hash IOC Detection
- **Attack:** Execution of malicious binary matching known WannaCry SHA256 signatures.
- **Detection Rule:** `RULE-008` (Malware Hash IOC).
- **MITRE ATT&CK:** `T1486 - Data Encrypted for Impact` (*Impact*).
- **Workflow:** VirusTotal lookup confirms WannaCrypt $\to$ Host isolation $\to$ MS17-010 vulnerability remediation.

---

## 📊 Executive SOC Dashboard Features

- **DEFCON Threat Level Gauge:** Dynamic threat index based on active uncontained critical alerts.
- **Real-Time Alert Feed:** Pulsating critical beacons, color-coded priority badges, and instant investigation jump.
- **Interactive Visual Analytics:**
  - Ingestion and alert timeline chart.
  - MITRE ATT&CK tactics distribution bars.
  - Top malicious source IPs with AbuseIPDB confidence flags.
- **Live SIEM Log Explorer:** Multi-column filtering by Source, Status, Event Type, and keyword search.
- **Detection Rules Tuner:** 1-Click enable/disable toggles and threshold adjustments for active correlation rules.
- **CyberChef Toolkit:** Base64 (UTF-8 & UTF-16LE), Hex, URL, ROT13, Defang/Refang, XOR, MD5/SHA256, and automated Regex IOC extractor natively integrated.
- **Incident Response Workbench:** SOC case tracking, analyst notes editor, containment checklist, and downloadable Markdown/HTML incident reports.
- **Wireshark / PCAP Inspector:** Network conversation breakdown, reverse shell flags, and SYN scan probes.

---

## 🔒 Security Best Practices Implemented

To ensure a safe environment free of exposed vulnerabilities, NexusGuard natively embraces zero-trust configurations:
- **No Plaintext Passwords:** All administrator endpoints and users utilize securely salted `Bcrypt` cryptographic hashes. 
- **Dynamic JWT Tokens:** Secure authentication keys dynamically re-generate on stateful backend server rotations.
- **Environment Driven Identity:** Eliminates potential leaks or hard-coded credentials stored in `.py`, `.js`, or Markdown files.

---

## 💼 Resume & Portfolio Description

> **NexusGuard — Security Operations & Threat Detection Platform**  
> *Technologies: Python, FastAPI, React, Linux Auth Logs, Windows Event Logs (4624/4625), Wireshark PCAP, Nmap, SIEM, MITRE ATT&CK, VirusTotal, AbuseIPDB, CyberChef, SQLite*  
> - Engineered an enterprise SOC monitoring and real-time SIEM detection platform capable of ingesting and normalizing heterogeneous logs across Linux (`auth.log`), Windows Security (`Security.evtx`), and Network packet streams.  
> - Designed rule-based detection correlation algorithms mapped to MITRE ATT&CK techniques (T1110, T1046, T1059, T1071, T1486) for detecting brute-force, port scanning, C2 beaconing, and obfuscated PowerShell exploits.  
> - Integrated multi-source Threat Intelligence workflows with AbuseIPDB confidence scoring and VirusTotal multi-engine reputation checks for automated IOC triage.  
> - Built an interactive analyst workbench featuring CyberChef de-obfuscation tools, PCAP inspection, incident case management, and automated export of formal Incident Response reports.

---

## 📄 License
This project is licensed under the MIT License — built purposely for SOC learning, university capstones, and robust cybersecurity analysis portfolios.

---

<p align="center">
  &copy; 2026 Developed with ❤️ by <a href="https://github.com/tech-warrior11"><b>tech-warrior11</b></a>
</p>
