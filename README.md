# <a href="https://www.linkedin.com/in/maury-nickelson/">Maury Nickelson</a>'s IT & Cybersecurity Project Portfolio 🔐

Maury Nickelson
Cybersecurity Operations & Threat Detection Portfolio

Welcome to my cybersecurity project portfolio. This repository showcases hands-on threat hunting investigations, vulnerability management workflows, detection engineering, and endpoint hardening projects built in lab environments that simulate real-world SOC operations.

My focus is on structured investigation methodology, clear documentation, and defensible remediation strategies aligned to industry frameworks.

Core Focus Areas

Threat Hunting & Detection Engineering

Incident Response & Timeline Reconstruction

Endpoint Telemetry Analysis (Microsoft Defender for Endpoint)

KQL Query Development

Vulnerability Management & STIG Remediation

Azure Lab Environments & Security Hardening

MITRE ATT&CK Mapping

NIST 800-61 Incident Response Alignment

---

## ⚠️ Vulnerability Management Projects

- **[Vulnerability Management Program Implementation](https://github.com/maurynickelson/Vulnerability-management-program)**  
  End-to-end documentation of a fully built vulnerability management program, including processes, KPIs, tools, and reporting.

- **Programmatic Vulnerability Remediations (PowerShell and Bash) IN PROGRESS**  
  Automating the remediation of common findings using scripts and configuration hardening.

---

## 🚨 Threat Hunting & Security Operations

- **[Threat Hunting Scenario: Exposed VM Accidentally Made Public](https://github.com/maurynickelson/threat-hunting-exposed-vm)**  
  Full threat-hunting investigation using Defender XDR, Azure, and KQL. Includes PREP → COLLECTION → ANALYSIS → INVESTIGATION → RESPONSE → LESSONS LEARNED, with visuals, queries, and documentation.

 - **[Threat Hunting Scenario:Internal Network Port Scanning Detection]( https://github.com/maurynickelson/internal-port-scanning-mde-threat-hunt)**  
  Full threat-hunting investigation using Defender XDR, Azure, and KQL. Investigated internal network performance degradation, detected unathorized internal port scanning via PowerShell, correlated network and process activity using MDE and KQL. Includes PREP → COLLECTION → ANALYSIS → INVESTIGATION → RESPONSE → LESSONS LEARNED, with visuals, queries, and documentation.

- [Insider Threat Investigation – Data Staging & Suspected Exfiltration]( https://github.com/maurynickelson/insider-threat-data-exfiltration-hunt)**
Tools: Microsoft Defender for Endpoint, KQL  
Conducted proactive threat hunt to investigate suspected insider data exfiltration following employee behavorial risk indicators. Correlated process, file, and network telemetry using timestamp-based analysis.Identified unauthorized PowerShell scripting that silently installed archive utilities and staged sensitive data locally. Assessed outbound network traffic and confirmed no successful data exfiltration. Documented findings using NIST-aligned incident response methodology and MITRE ATT&CK mapping.

- **[Threat Hunting Scenario: RDP Intrusion – Credential Dumping & Data Exfiltration](https://github.com/maurynickelson/maurynickelson/tree/main/threat-hunting/azuki-rdp-intrusion)**  
  Conducted structured threat hunt using Microsoft Defender for Endpoint (Advanced Hunting / KQL) to reconstruct a hands-on-keyboard intrusion involving external RDP abuse, LSASS credential dumping, persistence creation, encrypted C2 communications, and cloud-based data exfiltration. Performed cross-table telemetry correlation (Logon, Process, Registry, Network, File) to produce a complete attack timeline with MITRE ATT&CK alignment and actionable detection recommendations.

- **[Threat Hunting Scenario: Unauthorized TOR Browser Usage Detection](https://github.com/maurynickelson/unauthorized-tor-usage-threat-hunt)**  
  Behavioral detection of unauthorized TOR browser installation and anonymized network usage using Microsoft Defender for Endpoint. Correlated file, process, and network telemetry to confirm silent installation, browser execution, and TOR connectivity. Includes full timeline reconstruction, risk assessment, and containment actions.

  
---

## 🤳 Connect With Me

[<img align="left" alt="LinkedIn" width="22px" src="https://cdn.jsdelivr.net/npm/simple-icons@v3/icons/linkedin.svg" />][linkedin]

[linkedin]: https://linkedin.com/in/maury-nickelson

<br><br>

