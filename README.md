<div align="center">

<img src="assets/topology.png" alt="Network Topology" width="100%"/>

# 🛡️ Microsoft Sentinel Threat Hunting Lab

**End-to-end cloud SIEM lab — attack simulation, KQL detection engineering & SOC documentation**

[![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4?style=flat-square&logo=microsoftazure)](https://azure.microsoft.com)
[![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-SIEM-0078D4?style=flat-square&logo=microsoft)](https://azure.microsoft.com/en-us/products/microsoft-sentinel)
[![KQL](https://img.shields.io/badge/KQL-Detection_Engineering-F5A623?style=flat-square)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-FF6B6B?style=flat-square)](https://attack.mitre.org)
[![Platform](https://img.shields.io/badge/Platform-Windows_10-00C9A7?style=flat-square&logo=windows)](https://www.microsoft.com/en-us/windows)

</div>

---

## 📌 Overview

This project demonstrates a full **blue team kill chain** — from cloud infrastructure deployment through live attack simulation to KQL-based detection and SOC documentation. A deliberately vulnerable Windows 10 VM was deployed in Azure, attacked from a Kali Linux node, and every stage of the intrusion was detected using Microsoft Sentinel.

> **Key insight:** An attacker clearing local Windows event logs cannot erase evidence already streamed to Sentinel via AMA — cloud-forwarded SIEM telemetry is forensically durable by design.

---

## 🏗️ Lab Architecture

| Component          | Detail                                                     |
| ------------------ | ---------------------------------------------------------- |
| **Attacker**       | Kali Linux — Nmap, Metasploit, Evil-WinRM v3.9             |
| **Victim VM**      | Windows 10 Azure VM — `victim-win10` (`172.210.65.72`)     |
| **SIEM**           | Microsoft Sentinel — `law-soc-sentinel` (East US)          |
| **Log Pipeline**   | Azure Monitor Agent → Data Collection Rule → Log Analytics |
| **Resource Group** | `rg-soc-sentinel-lab`                                      |

---

## ⚔️ Attack Kill Chain

### Phase 1 — Reconnaissance `T1046` `T1595`

- Nmap host discovery and full port scan against the victim VM
- WinRM port `5985` confirmed open → selected as primary exploitation vector

### Phase 2 — Initial Access `T1110.001` `T1078`

- Metasploit `winrm_login` module used for credential brute force
- 50+ failed logon attempts (EID `4625`) before `Admin:Admin123` discovered
- Evil-WinRM v3.9 used to establish a full PowerShell shell

### Phase 3 — Persistence `T1547.001` `T1053.005` `T1136.001` `T1098`

```powershell
# Registry Run Key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "cmd.exe" /f

# Scheduled Task (runs as SYSTEM on logon)
schtasks /create /tn "SystemCheck" /tr "powershell.exe -WindowStyle Hidden" /sc onlogon /ru system /f

# Backdoor local account
net user backdoor B@ckd00r123!! /add
net localgroup administrators backdoor /add
```

### Phase 4 — Defense Evasion `T1070.001`

```powershell
# Clear Windows Security log — generates EID 1102 (already in Sentinel)
wevtutil cl Security
wevtutil cl System
```

---

## 🔍 KQL Hunting Campaigns

### Campaign 1 — Brute Force & Credential Access

```kql
// Kill Shot: Brute Force → Successful Logon Chain
let BruteForce =
    SecurityEvent
    | where TimeGenerated > ago(2h)
    | where Computer == "victim-win10"
    | where EventID == 4625
    | summarize FailCount = count() by IpAddress, TargetUserName
    | where FailCount > 3;
SecurityEvent
| where TimeGenerated > ago(2h)
| where Computer == "victim-win10"
| where EventID == 4624
| where LogonType in (3, 10)
| where IpAddress != "-"
| join kind=inner BruteForce
    on $left.IpAddress == $right.IpAddress,
       $left.TargetUserName == $right.TargetUserName
| project TimeGenerated, Account = TargetUserName,
    SourceIP = IpAddress, FailCountBeforeSuccess = FailCount
```

### Campaign 2 — Remote Session Activity

- EID `4624` (LogonType 3, NTLM) + EID `4672` (SeDebugPrivilege / SeImpersonatePrivilege)
- Confirms Evil-WinRM attacker-level session

### Campaign 3 — Persistence Detection

```kql
// Backdoor Chain: New Account → Added to Administrators (SID-joined)
let NewAccounts =
    SecurityEvent
    | where EventID == 4720
    | project AccountCreatedTime = TimeGenerated,
        NewAccount = TargetUserName, NewAccountSid = TargetSid,
        CreatedBy = SubjectUserName, Computer;
SecurityEvent
| where EventID == 4732
| where TargetUserName == "Administrators"
| join kind=inner NewAccounts
    on $left.MemberSid == $right.NewAccountSid
| extend MinutesBetween = datetime_diff('minute', AddedToAdminTime, AccountCreatedTime)
```

> SID-based join survives username obfuscation — a common gap in signature-based detection.

### Campaign 4 — Log Clearing (Defense Evasion)

- EID `1102` detected in Sentinel **after** local log was wiped
- Proves cloud SIEM telemetry survives attacker log clearing

### Campaign 5 — Lateral Movement Indicators

- EID `4648` explicit credential logon events
- Correlated with brute force source IP for full session timeline

---

## 🛠️ Remediation Matrix

| Technique                  | Remediation                                             | Priority     |
| -------------------------- | ------------------------------------------------------- | ------------ |
| T1110 Brute Force          | Account lockout (5 attempts / 15 min), MFA              | **CRITICAL** |
| T1021.006 WinRM            | Restrict via NSG to mgmt IPs only                       | **CRITICAL** |
| T1078 Weak Credentials     | 16-char minimum, LAPS for local admin                   | **CRITICAL** |
| T1547.001 Registry Run     | Sysmon EID 13 alerts, AppLocker                         | HIGH         |
| T1053.005 Scheduled Tasks  | Alert on EID 4698, restrict to admins                   | HIGH         |
| T1136.001 Account Creation | Alert on EID 4720, monthly audit                        | HIGH         |
| T1070.001 Log Clearing     | Real-time AMA forwarding (already done), EID 1102 alert | HIGH         |

---

---

## 🧠 Skills Demonstrated

| Area                     | Detail                                                          |
| ------------------------ | --------------------------------------------------------------- |
| **Cloud Infrastructure** | Azure VM, NSG, Log Analytics Workspace, AMA via CLI             |
| **SIEM Engineering**     | Sentinel deployment, DCR configuration, analytics rules         |
| **KQL**                  | Joins, aggregations, time intelligence, multi-stage correlation |
| **Threat Detection**     | Hypothesis-driven hunting, MITRE ATT&CK mapping                 |
| **Offensive Security**   | Nmap, Metasploit, Evil-WinRM, persistence simulation            |
| **Documentation**        | Professional SOC report, detection methodology writeup          |

---

## 👤 Author

**Mamoon Ahmad**
[GitHub](https://github.com/maamooon) · [LinkedIn](https://linkedin.com/in/maamooon) · mamoonahmad.dev@gmail.com
