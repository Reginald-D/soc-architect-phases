<div align="center">

# ANALYST SHIFT OPERATIONS, INCIDENT RESPONSE & PURPLE TEAM
### Phase IV — Running the SOC as a Disciplined, 24/7 Operation

*Shift workflow and SLAs · Incident response playbooks · Purple team exercise framework*

![Discipline](https://img.shields.io/badge/Discipline-SOC%20Operations-0078D4?style=flat-square)
![IR](https://img.shields.io/badge/IR-Playbook%20Library-D7263D?style=flat-square)
![Validation](https://img.shields.io/badge/Validation-Purple%20Team-5C2D91?style=flat-square)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-2b2b2b?style=flat-square)
![Status](https://img.shields.io/badge/Status-Phase%204-2ea44f?style=flat-square)

</div>

<br/>

> *Detection engineering only matters if the humans behind it operate on a schedule they*
> *can trust, respond from a playbook instead of memory, and get tested often enough to*
> *know the difference. This is the operating system that turns detections into a*
> *functioning SOC.*

<br/>

---

## Contents

**Part I — Analyst Shift Operations**
[Shift Structure](#1-shift-structure-design) · [Shift Start Sequence](#2-shift-start-sequence--what-every-analyst-does-first) · [Alert Triage](#3-alert-triage-workflow--the-analyst-decision-tree) · [T1 KQL Toolkit](#4-t1-analyst--investigation-kql-toolkit) · [Severity SLAs](#5-incident-severity-slas--response-time-standards) · [Shift Handoff](#6-shift-handoff-template--required-every-shift-end) · [Role Progression](#7-analyst-role-progression--t1-vs-t2-vs-shift-lead) · [Analyst Dashboard](#8-sentinel-analyst-dashboard--build-this)

**Part II — Incident Response Playbook**
[Playbook Structure](#playbook-structure-standard) · [Ransomware](#playbook-1--ransomware) · [Credential Compromise](#playbook-2--credential-compromise--account-takeover) · [Lateral Movement](#playbook-3--lateral-movement-detected) · [C2 Beacon](#playbook-4--active-command-and-control-beacon)

**Part III — Purple Team Exercise Framework**
[What Purple Team Means](#1-what-purple-team-means-in-the-soc) · [Exercise Architecture](#2-purple-team-exercise-architecture) · [Planning Template](#3-exercise-planning-template) · [Atomic Test Execution](#4-exercise-execution--the-atomic-test-approach) · [Atomic Tests Reference](#5-atomic-tests-reference--what-red-runs) · [Scoring Matrix](#6-scoring-matrix--measure-every-exercise) · [Post-Exercise Workflow](#7-post-exercise-workflow--where-the-real-value-is) · [Tabletop Format](#8-tabletop-exercise-format--phase-1-2-before-live) · [Maturity Levels](#9-purple-team-program-maturity-levels)

---
<br/>

# Part I — Analyst Shift Operations

## 1. Shift Structure Design

Before anything else, the shift architecture is defined — every other workflow depends
on it.

<div align="center">
<img width="1536" height="1024" alt="shift-structure-model" src="https://github.com/user-attachments/assets/a72a61c9-e2af-49f5-96dd-c49264580181" />
</div>

---

## 2. Shift Start Sequence — What Every Analyst Does First

This is **non-negotiable**. Every shift starts the same way, every time — consistency is
what makes a SOC reliable.

<div align="center">
<img width="1536" height="1024" alt="shift-start-checklist" src="https://github.com/user-attachments/assets/60b36319-eac8-4df8-bbbd-ab1a6de98f24" />
</div>

---

## 3. Alert Triage Workflow — The Analyst Decision Tree

<div align="center">
<img width="1024" height="1536" alt="alert-triage-tree" src="https://github.com/user-attachments/assets/85c82227-00a4-4008-b93c-9f0015a2712b" />
</div>

---

## 4. T1 Analyst — Investigation KQL Toolkit

The queries T1 runs during every investigation — bookmarked in Sentinel.

```kql
// QUERY 1: Entity Timeline -- everything an IP did in the last 24h
// Run this first on any suspicious source IP
let SuspiciousIP = "185.220.101.45"; // Replace with alert IP
union
    SecurityEvent,
    AADSignInLogs,
    AzureActivity,
    DeviceNetworkEvents,
    HoneypotEvents_CL
| where TimeGenerated > ago(24h)
| where * has SuspiciousIP
| project TimeGenerated, Type, tostring(pack_all())
| order by TimeGenerated asc
```

```kql
// QUERY 2: User Account Full Activity -- last 7 days
// Run on any user account involved in an alert
let SuspiciousUser = "jsmith@corp.local";
union
    AADSignInLogs,
    SecurityEvent,
    DeviceEvents,
    AuditLogs
| where TimeGenerated > ago(7d)
| where * has SuspiciousUser
| project TimeGenerated, Type, tostring(pack_all())
| order by TimeGenerated asc
```

```kql
// QUERY 3: Host Investigation -- what happened on a machine
let SuspiciousHost = "CORP-WS-042";
union
    SecurityEvent,
    DeviceProcessEvents,
    DeviceNetworkEvents,
    DeviceFileEvents,
    DeviceRegistryEvents
| where TimeGenerated > ago(48h)
| where Computer == SuspiciousHost or DeviceName == SuspiciousHost
| project TimeGenerated, Type, ActionType, tostring(pack_all())
| order by TimeGenerated asc
```

```kql
// QUERY 4: Lateral Movement Check -- has this account touched other machines?
let AccountName = "jsmith";
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where TargetUserName contains AccountName
| summarize
    MachinesAccessed = make_set(Computer),
    LogonCount = count(),
    LogonTypes = make_set(LogonType)
    by TargetUserName
| extend MachineCount = array_length(MachinesAccessed)
| where MachineCount > 2
```

```kql
// QUERY 5: Related Incidents -- same entities in other incidents
// Paste the IPs and user from the current alert
let RelatedEntities = dynamic(["185.220.101.45", "jsmith@corp.local"]);
SecurityAlert
| where TimeGenerated > ago(30d)
| where Entities has_any (RelatedEntities)
| project TimeGenerated, AlertName, Severity, Entities, SystemAlertId
| order by TimeGenerated desc
```

---

## 5. Incident Severity SLAs — Response Time Standards

<div align="center">
<img src="images/severity-sla-matrix.png" alt="Incident severity SLA matrix — Critical alerts acknowledged in 5 minutes with 15-minute assessment and immediate T2/IR paging, High in 15 minutes with 45-minute assessment and 1-hour escalation, Medium in 30 minutes with 2-hour assessment and 4-hour escalation, and Low in 2 hours with assessment by shift end and escalation next shift" width="640"/>
</div>

---

## 6. Shift Handoff Template — Required Every Shift End

<div align="center">
<img width="1402" height="1122" alt="severity-sla-matrix" src="https://github.com/user-attachments/assets/37d83a06-9860-4fa8-8fc6-811b3d60c70b" />
</div>

---

## 7. Analyst Role Progression — T1 vs T2 vs Shift Lead

<div align="center">
<img width="1024" height="1536" alt="analyst-role-progression" src="https://github.com/user-attachments/assets/cd0a9403-fafa-4220-87e9-a5b3123e91be" />
</div>

---

## 8. Sentinel Analyst Dashboard — Build This

Pinned to the analyst Sentinel workbook.

```kql
// Widget 1: My Open Incidents
SecurityIncident
| where Status != "Closed"
| where Owner.assignedTo == current_user()
| project IncidentNumber, Title, Severity, CreatedTime, Status
| order by Severity asc
```

```kql
// Widget 2: SLA Breach Watch -- incidents approaching SLA limit
SecurityIncident
| where Status != "Closed"
| extend AgeMinutes = datetime_diff('minute', now(), CreatedTime)
| extend SLALimit = case(
    Severity == "Critical", 15,
    Severity == "High", 60,
    Severity == "Medium", 240,
    480)
| extend SLAPercentUsed = (AgeMinutes * 100) / SLALimit
| where SLAPercentUsed > 75
| project IncidentNumber, Title, Severity, AgeMinutes, SLALimit, SLAPercentUsed
| order by SLAPercentUsed desc
```

```kql
// Widget 3: Alert Volume Heatmap -- when do alerts spike?
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize Count = count() by Hour = datetime_part("hour", TimeGenerated), DayOfWeek = dayofweek(TimeGenerated)
| render heatmap
```

<br/>

---
<br/>

# Part II — Incident Response Playbook

## Playbook Structure Standard

Every playbook follows the same format — consistency means an analyst who has never seen
a playbook can still execute it under pressure.

**Mandatory sections:** Trigger — exactly when to run it · Severity — what to assign ·
Immediate Actions — first 5 minutes, stop the bleeding · Investigation Steps — numbered,
specific, with KQL included · Containment — what to isolate, block, or revoke and how ·
Eradication — how to remove the threat · Recovery — how to restore to known-good state ·
Post-Incident — what to document and who to notify · MITRE Techniques — what this covers.

---

## Playbook 1 — Ransomware

**IR PLAYBOOK: Ransomware Detection and Response**
`ID: PB-IR-001 | Severity: CRITICAL | MITRE: T1486, T1490`

### Trigger
- MDE alert: ransomware behavior detected
- Unusual mass file encryption events on any host
- Honeypot file server shows bulk file modification
- User reports files renamed with an unknown extension

### Immediate Actions — First 5 Minutes
1. Page T2 and Shift Lead immediately — do not investigate alone
2. Identify the affected host(s) from the alert
3. Do **not** reboot the affected machine — this destroys forensic evidence
4. Initiate MDE host isolation — cuts network access but preserves state (`MDE Portal → Device → Actions → Isolate Device`)
5. Identify the user logged into the affected host
6. Immediately disable that user account in Azure AD (`Azure AD → Users → [username] → Block sign-in: Yes`)
7. Notify the Shift Lead — activate the Major Incident Communication Plan

### Investigation — Determine Scope

```kql
// QUERY 1: Find all hosts with mass file modification (ransomware pattern)
DeviceFileEvents
| where TimeGenerated > ago(2h)
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| summarize
    FileCount = count(),
    Extensions = make_set(tostring(split(FileName, ".")[-1])),
    FirstEvent = min(TimeGenerated)
    by DeviceName, bin(TimeGenerated, 5m)
| where FileCount > 100
| order by FileCount desc
```

Run the patient-zero query — sort the above output by `FirstEvent` ascending to find which
host encrypted first.

```kql
// QUERY 2: What happened on patient zero in the 24h BEFORE encryption?
let PatientZero = "CORP-WS-042"; // First infected host
let InfectionTime = datetime(2026-01-15 14:30);
union SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents
| where TimeGenerated between ((InfectionTime - 24h) .. InfectionTime)
| where Computer == PatientZero or DeviceName == PatientZero
| project TimeGenerated, Type, ActionType, tostring(pack_all())
| order by TimeGenerated asc
```

```kql
// QUERY 3: Ransomware-related network connections from affected hosts
DeviceNetworkEvents
| where TimeGenerated > ago(2h)
| where DeviceName in (AffectedHosts)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (445, 3389, 135) // SMB, RDP, WMI -- spread vectors
| summarize Connections = count() by DeviceName, RemoteIP, RemotePort
```

### Containment
- Isolate all confirmed affected hosts via MDE
- Block the source IP (if external) in Azure Firewall
- Disable all accounts that authenticated from affected hosts:

```kql
// QUERY 4: All accounts used on affected hosts in the last 48h
SecurityEvent
| where EventID == 4624
| where Computer in (AffectedHosts)
| where TimeGenerated > ago(48h)
| distinct TargetUserName
```

- Snapshot affected VMs in Azure **before** any remediation (`Azure Portal → VM → Operations → Disaster Recovery → Take snapshot`)
- Preserve the MDE investigation package (`MDE Portal → Device → Collect Investigation Package`)

### Eradication
- Identify the malware binary from the MDE investigation package
- Add the hash to MISP as a high-confidence IOC
- Search all other hosts for the same binary:

```kql
DeviceFileEvents
| where SHA256 == "MALWARE_HASH_HERE"
| distinct DeviceName
```

- Run a full AV scan on all hosts via MDE (`MDE Portal → Device → Actions → Run Antivirus Scan`)
- Remove persistence mechanisms found during investigation
- Verify no scheduled tasks, registry run keys, or services remain

### Recovery
- Restore affected systems from the last known-good snapshot
- Verify backup integrity **before** reconnecting to the network
- Reset **all** credentials used on affected systems, not just the disabled accounts
- Re-enable user accounts only after password reset plus MFA re-enrollment
- Remove isolation from hosts only after a clean AV scan is confirmed, no persistence is found, credentials are reset, and the Shift Lead approves

### Post-Incident
- Complete the incident report within 24 hours
- Reconstruct the timeline from initial access to containment
- Document how it got in, what it did, and how it was caught
- Add new IOCs to MISP
- Submit the detection gap to the Detection Engineering backlog
- Schedule a post-incident review within 72 hours
- Update this playbook if any steps were wrong or missing

---

## Playbook 2 — Credential Compromise / Account Takeover

**IR PLAYBOOK: Compromised User Account**
`ID: PB-IR-002 | Severity: HIGH-CRITICAL | MITRE: T1078, T1110`

### Trigger
- Successful login from a blacklisted IP
- Impossible travel alert from Azure AD
- Honeypot credentials used on real systems
- User reports unknown account activity
- MFA bypass detected

### Immediate Actions — First 5 Minutes
1. Revoke all active sessions for the account (`Azure AD → Users → [user] → Revoke Sessions`)
2. Reset the password — forces re-authentication everywhere
3. If it's an admin account, escalate to Critical immediately
4. Notify the user by phone, not email — the attacker may have inbox access
5. Enable 24-hour session token revocation in Conditional Access, if not already active

### Investigation

```kql
// QUERY 1: Everything this account did in the last 7 days
let CompromisedUser = "jsmith@corp.local";
union AADSignInLogs, AuditLogs, DeviceEvents, SecurityEvent
| where TimeGenerated > ago(7d)
| where * has CompromisedUser
| project TimeGenerated, Type, OperationName, IPAddress, Location, tostring(pack_all())
| order by TimeGenerated asc
```

```kql
// QUERY 2: Sign-in geography anomalies
AADSignInLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName == CompromisedUser
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Logins = count() by Country, IPAddress, bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

```kql
// QUERY 3: Email forwarding rules created
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("New-InboxRule", "Set-InboxRule")
| where * has CompromisedUser
```

```kql
// QUERY 4: Azure AD role assignments
AuditLogs
| where TimeGenerated > ago(7d)
| where Category == "RoleManagement"
| where * has CompromisedUser
```

```kql
// QUERY 5: Files accessed or downloaded
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId == CompromisedUser
| where Operation in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull")
| summarize FileCount = count(), Files = make_set(SourceFileName, 20) by bin(TimeGenerated, 1h)
```

### Containment
- Remove any inbox forwarding rules found
- Remove any suspicious Azure AD role assignments
- Review and revoke OAuth app permissions granted during the compromise window
- If lateral movement is confirmed, isolate affected hosts via MDE
- Block source IPs in Azure Firewall

### Eradication and Recovery
- Force MFA re-enrollment — revoke existing MFA methods
- Review the Conditional Access policy — was MFA actually enforced?
- Confirm no backdoor accounts were created (check new Azure AD users)
- Reset passwords for any shared credentials the account had access to

### Post-Incident
- Notify the user what was accessed during the compromise window
- If PII was accessed, escalate to legal/compliance under the data breach protocol
- Add attacker IPs and infrastructure to MISP
- File the incident report within 24 hours
- Review why MFA didn't prevent this, if applicable

---

## Playbook 3 — Lateral Movement Detected

**IR PLAYBOOK: Lateral Movement**
`ID: PB-IR-003 | Severity: HIGH | MITRE: T1021, T1550, T1047`

### Trigger
- Pass-the-Hash alert fires
- PsExec / PSEXESVC service detected
- WMI remote execution from an unexpected source
- Analyst observes an account accessing more than 3 hosts in a short window

### Immediate Actions — First 5 Minutes
1. Identify the source host — origin of the lateral movement
2. Identify all destination hosts touched
3. Isolate the source host via MDE immediately
4. Page T2 — lateral movement means an attacker is active right now
5. Do **not** alert the user or touch destination hosts yet — this preserves evidence and prevents the attacker from going deeper

### Investigation — Trace the Kill Chain

```kql
// QUERY 1: Build the lateral movement graph
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10) // Network + Remote Interactive
| where TimeGenerated > ago(4h)
| where TargetUserName !endswith "$"
| summarize
    Destinations = make_set(Computer),
    Methods = make_set(AuthenticationPackageName)
    by SubjectUserName, SubjectDomainName, bin(TimeGenerated, 10m)
| where array_length(Destinations) > 2
| extend HopCount = array_length(Destinations)
| order by HopCount desc
```

```kql
// QUERY 2: Suspicious process execution on all affected hosts
DeviceProcessEvents
| where TimeGenerated > ago(4h)
| where DeviceName in (AffectedHosts)
| where FileName in~ (
    "psexec.exe", "psexec64.exe", "paexec.exe",
    "wmic.exe", "powershell.exe", "cmd.exe"
)
| where InitiatingProcessFileName !in~ ("explorer.exe", "services.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

```kql
// QUERY 3: Any connections TO domain controllers
SecurityEvent
| where EventID == 4624
| where Computer contains "DC"
| where TimeGenerated > ago(4h)
| where SubjectUserName !endswith "$"
| where IpAddress !in (_GetWatchlist('Internal_IPs') | project SearchKey)
```

### Containment — Critical Priority Order
1. Is the DC compromised? If yes, escalate to Critical
2. Isolate the source host, if not already done
3. Block the credential being used — disable the account
4. Isolate destination hosts, in order of sensitivity
5. Block the attacker IP at the network edge

### Post-Incident
- Document the full kill chain from initial access to detection
- Audit credential hygiene — how was the credential obtained?
- Purple team follow-up — re-run the same technique to verify detection now works
- Document which hop caught it, and whether it can be caught earlier

---

## Playbook 4 — Active Command and Control Beacon

**IR PLAYBOOK: C2 Beacon Detected**
`ID: PB-IR-004 | Severity: HIGH | MITRE: T1071, T1095, T1048`

### Trigger
- DNS beaconing rule fires
- Regular outbound connection to an external IP detected
- Threat Intel IOC match on an outbound connection
- MDE suspicious network activity alert

### Immediate Actions — First 5 Minutes
1. Identify the beaconing host
2. Identify the C2 destination — IP or domain
3. Block the destination IP/domain in Azure Firewall immediately — this cuts the C2 channel before deeper investigation
4. Do **not** isolate the host yet — continue monitoring to see if the attacker shifts to a backup C2 channel

### Investigation

```kql
// QUERY 1: Connection regularity analysis
DeviceNetworkEvents
| where TimeGenerated > ago(6h)
| where DeviceName == BeaconingHost
| where RemoteIP == C2IP
| project TimeGenerated, SentBytes, ReceivedBytes, RemotePort
| order by TimeGenerated asc
// Look for: consistent interval, small packet sizes, regular heartbeat
```

```kql
// QUERY 2: Which process owns the C2 connection?
DeviceNetworkEvents
| where TimeGenerated > ago(6h)
| where RemoteIP == C2IP
| distinct InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessSHA256
```

```kql
// QUERY 3: Process and file creation before the beacon started
// Review SentBytes in QUERY 1 -- spikes indicate data being sent out
DeviceProcessEvents
| where TimeGenerated between ((BeaconStartTime - 2h) .. BeaconStartTime)
| where DeviceName == BeaconingHost
| where FileName !in~ (KnownGoodProcesses) // Reference the environment baseline
```

### Containment
- Block all C2 IPs/domains in Azure Firewall and the Sentinel watchlist
- If data exfiltration is confirmed, isolate the host via MDE immediately
- Kill the malicious process via MDE Live Response (`MDE → Device → Live Response → Kill process [PID]`)
- Add all C2 infrastructure to MISP

### Post-Incident
- Document dwell time — how long was C2 active before detection?
- Determine what data, if any, was exfiltrated
- Add the C2 infrastructure to MISP with a campaign tag
- Ask Detection Engineering whether this beacon pattern can be caught faster

<br/>

---
<br/>

# Part III — Purple Team Exercise Framework

## 1. What Purple Team Means in the SOC

<div align="center">
<img width="1536" height="1024" alt="red-blue-purple-team" src="https://github.com/user-attachments/assets/70c9a180-e783-4716-b435-150cdd1ddf60" />
</div>

This is the single fastest way to improve detection coverage. One purple team day
typically yields 10 or more newly validated detection rules.

---

## 2. Purple Team Exercise Architecture

<div align="center">
<img width="1536" height="1024" alt="purple-team-exercise-structure" src="https://github.com/user-attachments/assets/2dc64c41-bba9-4c42-b055-9ad24c800035" />
</div>

---

## 3. Exercise Planning Template

Run for every exercise.

<div align="center">
<img width="1024" height="1536" alt="purple-team-exercise-plan" src="https://github.com/user-attachments/assets/07b928cb-5f74-4f28-b039-d79ab9948064" />
</div>

**Success criteria:** detection rate target of 80% or more of techniques detected, mean
time to alert under 5 minutes per technique, and zero false negatives on Critical
techniques such as DCSync and LSASS.

**Rules of engagement:** target systems are the RANGE subnet only (10.0.2.0/24); no
lateral movement outside the range subnet; the Red operator notifies the Exercise Lead
before each technique; the Blue team has no advance knowledge of technique order; the stop
signal "ENDEX" halts all activity immediately.

**Out of scope:** production systems, the SOC Ops subnet, the Honeypot DMZ, destructive
actions (no file encryption, no service deletion), and exfiltration of real data.

---

## 4. Exercise Execution — The Atomic Test Approach

Each technique runs as a discrete atomic test, one at a time, measured precisely — using
the open-source [Atomic Red Team](https://redcanary.com/atomic-red-team/) library.

<div align="center">
<img width="1536" height="1024" alt="atomic-test-approach" src="https://github.com/user-attachments/assets/83611110-89d0-4d21-b928-5286dbd02211" />
</div>

**Recorded for every test:** did the alert fire (yes, no, or partial); time to alert, in
seconds from execution to Sentinel incident; alert accuracy — did it correctly identify
the technique; false-positive risk — would this fire in a benign scenario; enrichment
quality — did SOAR attach useful context; and what a T1 analyst would do with the alert.

---

## 5. Atomic Tests Reference — What Red Runs

The specific commands Red executes on range machines, mapped directly to the KQL
detections.

**Technique 1: Kerberoasting (T1558.003)**

```powershell
# Tool: Rubeus -- runs on any domain-joined Windows machine in range
.\Rubeus.exe kerberoast /outfile:hashes.txt
# Expected: SOC-CRED-003 fires within 2 minutes (EventID 4769, RC4 encryption)
```

**Technique 2: Password Spray (T1110.003)**

```powershell
# Tool: Spray.ps1
Import-Module .\Spray.ps1
Invoke-Spray -UserList users.txt -Password "Welcome2026!" -Domain corp.local
# Expected: SOC-INIT-002 fires (>10 failed AAD logins, low attempts per account)
```

**Technique 3: DCSync (T1003.006)**

```text
# Tool: Mimikatz -- run from domain admin context on range machine
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
# Expected: SOC-CRED-004 fires (EventID 4662, replication GUIDs)
# CRITICAL: This MUST fire. If not, stop the exercise and fix immediately.
```

**Technique 4: LSASS Memory Dump (T1003.001)**

```text
# Tool: ProcDump (legitimate Sysinternals tool, commonly abused)
procdump.exe -ma lsass.exe lsass.dmp
# Expected: SOC-CRED-001 fires (MDE DeviceEvent: LSASS access)
```

**Technique 5: Pass-the-Hash (T1550.002)**

```text
# Tool: Mimikatz
mimikatz.exe "sekurlsa::pth /user:admin /domain:corp /ntlm:HASH /run:cmd.exe" exit
# Expected: SOC-LATMOV-001 fires (NTLM network logon, workstation-to-workstation)
```

**Technique 6: Scheduled Task Persistence (T1053.005)**

```powershell
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -enc BASE64" /sc onlogon
# Expected: SOC-PERS-001 fires (EventID 4698, encoded content in task)
```

**Technique 7: Log Clearing (T1070.001)**

```text
wevtutil cl Security
# Expected: SOC-DEFEVAS-001 fires immediately (EventID 1102)
# This is a canary -- if this doesn't fire, the logging pipeline is broken.
```

---

## 6. Scoring Matrix — Measure Every Exercise

<div align="center">
<img width="1536" height="1024" alt="exercise-scorecard" src="https://github.com/user-attachments/assets/e2f90ae8-1fe8-4ed1-97a8-c9b72b85e164" />
</div>

<div align="center">
<img width="1536" height="1024" alt="detection-failures-backlog" src="https://github.com/user-attachments/assets/5c5e4acf-79b8-4a93-ad0a-72746828e376" />
</div>

---

## 7. Post-Exercise Workflow — Where the Real Value Is

**Within 24 hours of the exercise**
- Exercise Lead publishes the scorecard to all teams
- Detection Engineer writes rules for every detection failure
- Each new rule goes through the Detection-as-Code pipeline — PR, review, deploy
- Tuning tasks are created for partial detections
- The ATT&CK Navigator layer is updated with new coverage

**Within 72 hours**
- New rules are deployed to Sentinel and validated
- Only the failed techniques are re-tested — a 1-hour mini-exercise
- New rules are confirmed to fire correctly
- The coverage map is updated with newly detected techniques
- Exercise findings and remediation are documented in the lessons-learned log

**Monthly**
- The next technique set is picked based on current blind spots in ATT&CK Navigator, techniques observed in honeypot logs that month, and CISA advisories or the current threat landscape
- The exercise calendar for the quarter is published

---

## 8. Tabletop Exercise Format — Phase 1-2 (Before Live)

When live attacks aren't yet possible, tabletops build the same muscle memory.

**Scenario: "The Overnight Breach"**

At 2:00 AM, an attacker who compromised a vendor's VPN credentials logged into the jump
server. They spent six hours enumerating the domain, Kerberoasting service accounts, and
establishing persistence via a scheduled task before being detected at 8:00 AM, when a
shift analyst noticed an unusual alert.

**Discussion questions, worked through as a team:**
1. Which alerts would have fired during the six-hour window?
2. At what point would a T1 analyst have escalated to T2?
3. Which playbook gets invoked?
4. What containment actions happen in the first 15 minutes?
5. Who gets notified, and in what order?
6. What evidence gets preserved?
7. How is the blast radius determined?
8. What would have been done differently if this was detected at 2:00 AM instead of 8:00 AM?

**Inject cards, introduced mid-exercise by the facilitator:**
- "The attacker just disabled Windows Defender on the jump server."
- "A second host is now showing the same scheduled task."
- "The user account used was a service account — no real user to call."

**Outcome:** any playbook steps that were unclear get rewritten, any steps with no
documented owner get one assigned, and any detection gaps the scenario exposed go into the
backlog.

---

## 9. Purple Team Program Maturity Levels

Used to track program evolution across the roadmap phases.

| Level | Phase | Characteristics |
|---|---|---|
| **1 — Tabletop** | Phase 1–2 | Scenario-based walkthroughs, playbooks tested verbally, no live attack execution, gap identification only |
| **2 — Atomic Tests** | Phase 3 | Single techniques executed one at a time, Blue team observing Sentinel live, detection gaps trigger immediate rule creation, a scorecard produced after each exercise |
| **3 — Chained Scenarios** | Phase 4 | Full kill chain — initial access through lateral movement — Blue team responds as if it's a real incident, SOAR playbooks tested under realistic conditions, analyst decision-making evaluated, not just detection |
| **4 — Continuous Purple** | Phase 5 | Red and Blue work together weekly, not monthly; automated testing via Atomic Red Team and BAS tools; every new detection rule validated by Red before production; detection coverage trending upward every month, measurably |

<br/>

---

## The Complete SOC Operating System

<div align="center">
<img width="1536" height="1024" alt="soc-operating-system" src="https://github.com/user-attachments/assets/bdece0dd-9eca-4f36-a935-7042768d3eef" />
</div>

<br/>

<div align="center">

*A playbook nobody has run is a hypothesis. A detection nobody has attacked is a guess.*
*Everything in this document exists to turn both into something proven.*

</div>
