# -Devices-Exposed-to-the-Internet

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts

 Gather relevant data from logs, network traffic, and endpoints.
Consider inspecting the logs to see which devices have been exposed to the internet and have received excessive failed login attempts. Take note of the source IP addresses and number of failures, etc

Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.

Sample Queries (spoilers, highlight or copy/paste to reveal):


// Check most failed logons
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts


// Take the top 10 IPs with the most logon failures and see if any succeeded to logon
let RemoteIPsInQuestion = dynamic(["119.42.115.235","183.81.169.238", "74.39.190.50", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)


// Look for any remote IP addresses who have had both successful and failed logons
// Investigate for potential brute force successes
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by ActionType, RemoteIP, DeviceName
| order by FailedLogonAttempts;
let SuccessfulLogons =  DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by ActionType, RemoteIP, DeviceName, AccountName
| order by SuccessfulLogons;
FailedLogons
| join SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
Timeline Summary and Findings:
Windows-target-1 har been internetfacing for several days
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc




Last internet facing time:


2025-04-18T21:32:49.4861764Z


Several bad actors have been discovered attempting to log into the machine 
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts










The top 5 IP address have not been able to log into VM
/ Take the top 10 IPs with the most logon failures and see if any succeeded to logon
let RemoteIPsInQuestion = dynamic(["197.210.194.240","185.42.12.59", "103.20.195.132", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)














< Query no results >


Only successful logon for the last 30 day for from the labuser account (0) 


DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()


Logon failed also for this account  were (0) brute attempt is unlikely for this VM




Checked successful attempts e labuser’s IP address had normal activity 


DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSucess"
| where AccountName == "labuser"
| summarize count() by DeviceName, ActionType, AccountName, RemoteIP






MITRE ATT&CK Tactics and Techniques:


# MITRE ATT&CK Mapping - Timeline Summary


## Initial Access
- **T1078.001**: Valid Accounts: Default Accounts  
  - Relevance: Use of the "labuser" account for successful logon, suggesting possible monitoring for default or known credentials.


## Credential Access
- **T1110**: Brute Force  
  - Relevance: Numerous failed logon attempts from external IPs, suggesting brute-force attempts.
- **T1110.001**: Password Guessing  
  - Relevance: Pattern of failed logins from multiple remote IPs.


## Discovery
- **T1016**: System Network Configuration Discovery  
  - Relevance: Attacker may have scanned or inferred that `windows-target-1` was internet-facing.


## Defense Evasion
- **T1070.004**: File Deletion or Log Tampering (Hypothetical)  
  - Relevance: If no signs of compromise are found despite failed attempts, attackers may be using evasion techniques, though not directly evident from logs.


## Impact (Ruled Out)
- No signs of successful compromise or persistence; no direct mapping to Impact TTPs based on your notes.


—
NSG for windows-target-1 is harden 
