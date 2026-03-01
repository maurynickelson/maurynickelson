<a href="https://www.linkedin.com/in/maury-nickelson/"> Maury Nickelson — Cybersecurity Operations & Detection Engineering Portfolio 🔐


Welcome to my cybersecurity project portfolio. This repository showcases hands-on threat hunting investigations, structured vulnerability remediation projects, and endpoint hardening workflows designed to replicate enterprise SOC operations.

Projects demonstrate cross-table telemetry correlation using Microsoft Defender for Endpoint, KQL-driven detection engineering, DISA STIG-based configuration enforcement, and defensible remediation strategies validated through re-scan workflows.

Emphasis is placed on structured investigation methodology, true-positive validation, risk-based decision making, and alignment with industry security frameworks.

---

## Core Focus Areas

- Threat Hunting & Detection Engineering  
- Incident Response & Timeline Reconstruction  
- Endpoint Telemetry Analysis (Microsoft Defender for Endpoint)  
- KQL Query Development  
- Vulnerability Management & STIG-Based Hardening  
- Azure Lab Environments & Cloud Security Boundary Analysis  
- MITRE ATT&CK Mapping  
- NIST 800-61 Incident Response Lifecycle  
- NIST 800-53 Control Alignment  

---

## Methodological Approach

Each project follows a structured security lifecycle:

**PREP → COLLECTION → ANALYSIS → INVESTIGATION → RESPONSE → VERIFICATION → LESSONS LEARNED**

For vulnerability management initiatives:

**DETECTION → VALIDATION → REMEDIATION → RE-SCAN → DOCUMENTATION → NIST ALIGNMENT**

This approach ensures findings are technically validated, remediation actions are defensible, and documentation aligns with enterprise security operations standards.

---

## ⚠️ Vulnerability Management Projects

- **[Vulnerability Management Program Implementation](https://github.com/maurynickelson/Vulnerability-management-program)**  
  End-to-end documentation of a fully built vulnerability management program, including processes, KPIs, tools, and reporting.

- **[Windows 11 Security Hardening & Vulnerability Remediation](https://github.com/maurynickelson/windows-11-stig-remediation-labs)**  
 Full structured remediation of DISA Windows 11 STIG controls using Tenable Vulnerability Management and PowerShell. Conducted endpoint hardening across identity, network, boot integrity, and legacy component exposure. Validated findings through manual registry, Group Policy, and PowerShell analysis to confirm true positives before remediation. Executed configuration enforcement, account lifecycle management, firewall hardening, protocol security controls, and Secure Boot validation (including Azure VM infrastructure boundary analysis). Includes DETECTION → VALIDATION → REMEDIATION → VERIFICATION → NIST 800-53 ALIGNMENT, with supporting evidence, scan reports, and technical documentation.

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

