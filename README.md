# 🛡️ Incident Timeline & Threat Analysis Report

## 📅 Date of Observation
**2025-04-18**

## 🖥️ Host Under Review
**Hostname:** `windows-target-1`  
**Internet Facing:** Yes  
**Last Observed Internet-Facing Timestamp:** `2025-04-18T21:32:49.4861764Z`

---

## 📌 Summary of Findings

1. **Target system has been internet-facing for several days.**
2. **Multiple failed login attempts detected from external IPs.**
3. **No successful logins from unauthorized IPs were observed.**
4. **All successful logons in the last 30 days were from a single known user (`labuser`).**
5. **No evidence of brute-force or credential stuffing success.**

---

## 🔍 Key KQL Queries Used

### 1. Check for Internet-Facing System
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts

let RemoteIPsInQuestion = dynamic(["197.210.194.240","185.42.12.59", "103.20.195.132", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()

DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count() by DeviceName, ActionType, AccountName, RemoteIP
## 🧠 MITRE ATT&CK Mapping

| Tactic             | Technique                         | ID         | Description                                                                 |
|--------------------|-----------------------------------|------------|-----------------------------------------------------------------------------|
| Initial Access     | Valid Accounts: Default Accounts  | T1078.001  | Attempted access using default/known accounts (`labuser`).                 |
| Credential Access  | Brute Force                       | T1110      | High volume of failed login attempts from external IPs.                     |
|                    | Password Guessing                 | T1110.001  | Indicates attackers may be attempting simple password variations.          |
| Discovery          | System Network Configuration      | T1016      | Adversaries likely identified system as internet-facing prior to attempts. |
| Defense Evasion    | (Potential) Log Tampering         | T1070.004  | No successful unauthorized access, may imply log evasion (not confirmed).  |

