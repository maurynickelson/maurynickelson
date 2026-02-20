# Incident Report  
## RDP Intrusion, Credential Dumping & Data Exfiltration  
**Environment:** Microsoft Defender for Endpoint (Advanced Hunting)  
**Impacted Host:** AZUKI-SL  
**Date of Activity:** November 19, 2025  
**Report Author:** Maury Nickelson  

---

# 1. Executive Summary

On November 19, 2025, suspicious activity was identified on the administrative workstation `AZUKI-SL` following reports of supplier pricing data appearing on underground forums.

A structured threat hunt using Microsoft Defender for Endpoint telemetry confirmed a full multi-stage intrusion involving:

- Unauthorized RDP access from external IP **88.97.178.12**
- Compromise of privileged account **kenji.sato**
- Defense evasion via Windows Defender exclusions
- Tool download using `certutil.exe`
- Credential dumping via `mm.exe` with `sekurlsa::logonpasswords`
- Command-and-control communication to **78.141.196.6** over port **443**
- Data staging into `export-data.zip`
- Exfiltration via Discord
- Event log tampering using `wevtutil`
- Creation of persistence mechanisms including scheduled task and backdoor admin account
- Attempted lateral movement to internal host **10.1.0.188**

The attack demonstrates structured hands-on-keyboard tradecraft aligned with MITRE ATT&CK techniques across Initial Access, Defense Evasion, Credential Access, Persistence, Command & Control, Exfiltration, and Impact.

---

# 2. Scope of Investigation

**Host Investigated:** AZUKI-SL  
**Time Window:** November 19, 2025 (24-hour review window)  

**Data Sources Used:**

- DeviceLogonEvents
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceRegistryEvents
- DeviceFileEvents

The objective was to reconstruct the full attack lifecycle and assess potential organizational impact.

---

# 3. Methodology

The threat hunt followed a lifecycle-based investigative approach:

1. Validate initial access vector  
2. Identify compromised identity  
3. Analyze post-authentication activity  
4. Detect defense evasion techniques  
5. Identify persistence mechanisms  
6. Confirm credential access activity  
7. Correlate command-and-control behavior  
8. Trace collection and exfiltration activity  
9. Detect anti-forensic behavior  
10. Assess lateral movement attempts  

Telemetry was correlated across identity, process, file, registry, and network data to build a complete timeline.

---

# 4. Detailed Findings

## 4.1 Initial Access – RDP Authentication

Analysis of `DeviceLogonEvents` revealed successful remote interactive logon from:

**88.97.178.12**

Authenticated account:

**kenji.sato**

A failed attempt immediately preceded successful authentication, suggesting credential validation prior to access.

**MITRE:** T1021.001 – Remote Services (RDP)

---

## 4.2 Discovery Activity

Shortly after authentication, the attacker executed:

```
arp -a
```

This command enumerates network neighbors and indicates interactive reconnaissance.

**MITRE:** T1016 – System Network Configuration Discovery

---

## 4.3 Defense Evasion & Staging

A hidden directory was created:

```
C:\ProgramData\WindowsCache
```

Subsequent registry modifications revealed:

- File extension exclusions added to Windows Defender
- Folder path exclusions added
- Directory attributes modified to hide contents

These actions impaired endpoint detection prior to tool execution.

**MITRE:**
- T1562.001 – Impair Defenses  
- T1074.001 – Local Data Staging  

---

## 4.4 Tool Ingress

The attacker used:

```
certutil.exe -urlcache
```

to download tooling into the staging directory.

Use of a native Windows binary demonstrates living-off-the-land tradecraft.

**MITRE:** T1105 – Ingress Tool Transfer

---

## 4.5 Persistence Mechanisms

### Scheduled Task

Task Name:
```
Windows Update Check
```

Execution Target:
```
C:\ProgramData\WindowsCache\svchost.exe
```

### Backdoor Administrator Account

New local admin account created:
```
support
```

Redundant persistence indicates intent for long-term access.

**MITRE:**
- T1053.005 – Scheduled Task  
- T1136.001 – Create Local Account  

---

## 4.6 Credential Access

Executable staged:

```
mm.exe
```

Executed with:

```
sekurlsa::logonpasswords
```

This module targets LSASS memory to extract authentication material.

Potential exposure includes NTLM hashes, Kerberos tickets, and cached credentials.

**MITRE:** T1003.001 – OS Credential Dumping: LSASS Memory

---

## 4.7 Command & Control

Repeated outbound HTTPS connections were observed to:

```
78.141.196.6
```

Destination Port:
```
443
```

Connections were initiated by `powershell.exe`, indicating encrypted C2 communications over standard web traffic.

**MITRE:** T1071.001 – Web Protocols

---

## 4.8 Collection & Exfiltration

Archive created:

```
export-data.zip
```

Outbound connections to Discord infrastructure occurred shortly after archive creation, confirming data exfiltration over HTTPS.

**MITRE:**
- T1560 – Archive Collected Data  
- T1567.002 – Exfiltration Over Web Service  

---

## 4.9 Anti-Forensics

Execution of:

```
wevtutil
```

First log cleared:

```
Security
```

Clearing Security logs first demonstrates awareness of forensic logging importance.

**MITRE:** T1070.001 – Indicator Removal on Host

---

## 4.10 Lateral Movement

Execution of:

```
mstsc.exe /v:10.1.0.188
```

Indicates attempted RDP pivot to internal host **10.1.0.188** following credential dumping.

**MITRE:** T1021.001 – Remote Services

---

# 5. Indicators of Compromise (IOCs)

| Type | Indicator |
|------|----------|
| External RDP IP | 88.97.178.12 |
| C2 IP | 78.141.196.6 |
| Internal Pivot Target | 10.1.0.188 |
| Malicious Directory | C:\ProgramData\WindowsCache |
| Archive File | export-data.zip |
| Credential Dump Tool | mm.exe |
| Scheduled Task | Windows Update Check |
| Backdoor Account | support |

---

# 6. Attack Timeline (Condensed)

| Stage | Artifact |
|--------|----------|
| Initial Access | RDP from 88.97.178.12 |
| Recon | arp -a |
| Defense Evasion | Defender exclusions + hidden directory |
| Tool Download | certutil.exe |
| Persistence | Scheduled task + support account |
| Credential Dumping | mm.exe (sekurlsa::logonpasswords) |
| C2 | 78.141.196.6:443 |
| Collection | export-data.zip |
| Exfiltration | Discord |
| Log Clearing | wevtutil (Security log) |
| Lateral Movement | mstsc.exe to 10.1.0.188 |

---

# 7. Impact Assessment

The intrusion resulted in:

- Compromised administrative credentials
- Extraction of authentication material
- Theft of sensitive supplier pricing data
- Persistent backdoor access
- Attempted internal lateral movement

Credential dumping significantly increases potential blast radius beyond a single endpoint.

---

# 8. Recommendations

- Restrict RDP access to VPN or allowlisted IP ranges
- Alert on public RDP authentication events
- Monitor Windows Defender exclusion registry modifications
- Detect certutil execution with URL parameters
- Alert on LSASS memory access
- Monitor scheduled task creation outside maintenance windows
- Detect outbound Discord traffic from sensitive endpoints
- Alert on event log clearing activity

---

# 9. Skills Demonstrated

- Advanced KQL threat hunting in Microsoft Defender
- Cross-table telemetry correlation (Logon, Process, Network, Registry, File)
- MITRE ATT&CK mapping
- Timeline reconstruction
- Credential abuse analysis
- C2 detection via behavioral correlation
- Data exfiltration detection
- Persistence mechanism discovery
- Business impact assessment

---

# Appendix A – Sample KQL Queries

### RDP Logon Analysis

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where LogonType contains "Remote"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, AccountName, RemoteIP, ActionType
| sort by Timestamp asc
```

### C2 Traffic Identification

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where RemoteIP == "78.141.196.6"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp asc
```

### Scheduled Task Creation

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "schtasks"
| project Timestamp, ProcessCommandLine
```

---

# Appendix B – Screenshots

*(Place screenshots in a folder named `screenshots/` and reference them below.)*

Example:

```
![RDP Logon Evidence](./screenshots/rdp-logon.png)
![C2 Traffic Evidence](./screenshots/c2-traffic.png)
![Scheduled Task Creation](./screenshots/schtasks.png)
```

---
