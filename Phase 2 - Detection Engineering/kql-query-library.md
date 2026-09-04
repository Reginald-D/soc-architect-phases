<div align="center">

# KQL QUERY LIBRARY & DETECTION ENGINEERING
### Phase II — MITRE-Aligned Detections and Threat Intelligence

*Version-controlled detection logic · Honeypot instrumentation · MISP threat intel integration*

![Language](https://img.shields.io/badge/Language-KQL-0078D4?style=flat-square)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-D7263D?style=flat-square)
![Platform](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=flat-square)
![Intel](https://img.shields.io/badge/Threat%20Intel-MISP-5C2D91?style=flat-square)
![Status](https://img.shields.io/badge/Status-Phase%202-2ea44f?style=flat-square)

</div>

<br/>

> *A detection rule that isn't organized, versioned, and validated against real data isn't*
> *a detection — it's a guess with good intentions. Every query in this library exists in a*
> *known folder, maps to a known technique, and carries a documented false-positive rate*
> *before it ever reaches production.*

<br/>

---

## Contents

**Part I — KQL Query Library & Detection Engineering**
[Library Structure](#1-library-structure--organization) · [Detection Queries by Phase](#2-core-detection-queries--by-mitre-phase) · [Honeypot Queries](#3-honeypot-specific-queries) · [Threat Hunting](#4-threat-hunting-queries-not-deployed-as-rules) · [KQL Functions](#5-kql-functions--reusable-building-blocks) · [Severity Matrix](#6-alert-severity-matrix) · [Deployment Process](#7-detection-rule-deployment-process)

**Part II — MISP Threat Intel Platform**
[What MISP Does](#1-what-misp-does-in-the-soc) · [Azure Architecture](#2-misp-architecture-in-azure) · [Installation](#3-misp-installation) · [Data Model](#4-misp-data-model--how-intel-is-organized) · [Free Feeds](#5-free-threat-intel-feeds-to-connect) · [Sentinel Integration](#6-misp--sentinel-integration) · [API Queries](#7-misp-api--key-queries-for-playbooks) · [Team Workflow](#8-threat-intel-workflow--team-operating-procedure) · [Intel Loop](#9-misp--sentinel--the-intel-loop) · [Build Checklist](#10-build-checklist)

---
<br/>

# Part I — KQL Query Library & Detection Engineering

## 1. Library Structure & Organization

Before a single query is written, the library architecture is established first. Detection
Engineering needs a system, not a folder of loose `.kql` files.

```text
soc-detection-library/
├── 01_initial_access/
│   ├── brute_force_ssh.kql
│   ├── brute_force_rdp.kql
│   ├── password_spray_aad.kql
│   └── phishing_link_click.kql
├── 02_execution/
│   ├── powershell_encoded_commands.kql
│   ├── suspicious_wscript_cscript.kql
│   └── mshta_execution.kql
├── 03_persistence/
│   ├── scheduled_task_creation.kql
│   ├── registry_run_key_modification.kql
│   └── new_local_admin_account.kql
├── 04_privilege_escalation/
│   ├── token_impersonation.kql
│   └── uac_bypass_attempts.kql
├── 05_defense_evasion/
│   ├── log_clearing_events.kql
│   ├── av_tamper_detection.kql
│   └── timestomping.kql
├── 06_credential_access/
│   ├── lsass_memory_access.kql
│   ├── kerberoasting_detection.kql
│   ├── dcsync_attempt.kql
│   └── ntds_dit_access.kql
├── 07_discovery/
│   ├── network_port_scanning.kql
│   ├── ad_enumeration_bloodhound.kql
│   └── domain_trust_discovery.kql
├── 08_lateral_movement/
│   ├── pass_the_hash.kql
│   ├── psexec_lateral_movement.kql
│   └── wmi_remote_execution.kql
├── 09_collection/
│   ├── large_file_staging.kql
│   └── email_forwarding_rules.kql
├── 10_exfiltration/
│   ├── dns_tunneling.kql
│   ├── large_upload_azure_storage.kql
│   └── data_exfil_to_rare_domain.kql
├── 11_command_and_control/
│   ├── beacon_regularity_detection.kql
│   ├── c2_over_http_https.kql
│   └── dns_c2_detection.kql
├── 12_honeypot/
│   ├── any_honeypot_interaction.kql
│   ├── honeypot_credential_reuse.kql
│   └── honeypot_brute_force.kql
├── 99_hunting/            ← proactive, not deployed as rules
│   ├── long_tail_analysis.kql
│   ├── beaconing_hunt.kql
│   └── rare_parent_child_processes.kql
└── templates/
    ├── RULE_TEMPLATE.kql
    └── HUNTING_TEMPLATE.kql
```

Every `.kql` file carries a standard header:

```text
// ============================================================
// RULE NAME: Kerberoasting Detection
// MITRE TECHNIQUE: T1558.003 - Steal or Forge Kerberos Tickets
// ATTACK PHASE: Credential Access
// DATA SOURCE: SecurityEvent, MDE DeviceEvents
// SEVERITY: High
// FREQUENCY: Every 5 minutes
// LOOKBACK: 1 hour
// AUTHOR: [name]
// CREATED: 2026-01-15
// LAST MODIFIED: 2026-01-15
// VERSION: 1.0
// STATUS: Active | Tuning | Deprecated
// FALSE POS RATE: Low
// NOTES: Fires on Kerberos TGS requests for service
// accounts with SPNs. Confirm with auth logs.
// ============================================================
```

---

## 2. Core Detection Queries — By MITRE Phase

### Initial Access

**Brute Force — RDP**

```kql
// T1110.001 - Brute Force: Password Guessing (RDP)
SecurityEvent
| where EventID == 4625
| where LogonType == 10 // Remote Interactive (RDP)
| where TimeGenerated > ago(15m)
| summarize
    FailedAttempts = count(),
    Accounts = make_set(TargetUserName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IpAddress, Computer
| where FailedAttempts >= 10
| extend
    AccountCount = array_length(Accounts),
    Technique = "T1110.001",
    Severity = iff(FailedAttempts >= 50, "High", "Medium")
| project LastAttempt, Computer, IpAddress, FailedAttempts, AccountCount, Accounts, Severity, Technique
| order by FailedAttempts desc
```

**Password Spray — Azure AD**

```kql
// T1110.003 - Brute Force: Password Spraying (AAD)
// Key signature: many accounts, few attempts per account, same IP/time window
AADSignInLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0 // Failed sign-ins only
| summarize
    FailedAccounts = dcount(UserPrincipalName),
    TotalAttempts = count(),
    Accounts = make_set(UserPrincipalName),
    AppNames = make_set(AppDisplayName)
    by IPAddress, bin(TimeGenerated, 10m)
| where FailedAccounts >= 10
| extend AttemptsPerAccount = TotalAttempts / FailedAccounts
| where AttemptsPerAccount <= 3 // Low attempts per account = spray pattern
| extend Technique = "T1110.003", Severity = "High"
| project TimeGenerated, IPAddress, FailedAccounts, TotalAttempts, AttemptsPerAccount, Accounts
```

**Impossible Travel**

```kql
// T1078 - Valid Accounts: Impossible Travel
AADSignInLogs
| where TimeGenerated > ago(1d) and ResultType == 0 and isnotempty(LocationDetails)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize
    SignIns = make_list(pack("time", TimeGenerated, "country", Country, "ip", IPAddress)),
    Countries = make_set(Country)
    by UserPrincipalName
| where array_length(Countries) > 1
| mv-expand SignIns
| extend SignInTime = todatetime(SignIns.time), SignInCountry = tostring(SignIns.country)
| order by UserPrincipalName, SignInTime asc
| serialize
| extend PrevTime = prev(SignInTime), PrevCountry = prev(SignInCountry), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser and SignInCountry != PrevCountry
| extend TimeDiffMinutes = datetime_diff('minute', SignInTime, PrevTime)
| where TimeDiffMinutes < 120 // Less than 2 hours between countries
| project UserPrincipalName, PrevCountry, SignInCountry, TimeDiffMinutes, SignInTime
| extend Technique = "T1078", Severity = "High"
```

### Execution

**PowerShell Encoded Commands**

```kql
// T1059.001 - Command and Scripting: PowerShell
// Encoded commands are a major red flag -- almost never legitimate
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-ec ")
| extend
    DecodedHint = extract(@"-[Ee][Nn][Cc][Oo]?[Dd]?[Ee]?[Dd]?\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine),
    Technique = "T1059.001",
    Severity = "High"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, DecodedHint, InitiatingProcessFileName
| order by TimeGenerated desc
```

**LOLBins — Living Off the Land**

```kql
// T1218 - Signed Binary Proxy Execution (LOLBins)
// Legitimate binaries abused to execute malicious code
let LOLBins = dynamic([
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "odbcconf.exe",
    "ieexec.exe", "pcalua.exe", "forfiles.exe"
]);
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName in~ (LOLBins)
| where InitiatingProcessFileName !in~ (
    "explorer.exe", "msiexec.exe", "svchost.exe", "services.exe"
)
| extend Technique = "T1218", Severity = "Medium"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

**Malicious Macro Execution Pattern**

```kql
// T1566.001 - Phishing: Spearphishing Attachment (macro execution chain)
// Office app spawning script interpreters = macro execution
let OfficeApps = dynamic(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]);
let SuspiciousChildren = dynamic([
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe"
]);
DeviceProcessEvents
| where TimeGenerated > ago(2h)
| where InitiatingProcessFileName in~ (OfficeApps)
| where FileName in~ (SuspiciousChildren)
| extend Technique = "T1566.001", Severity = "High"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Persistence

**Scheduled Task Creation**

```kql
// T1053.005 - Scheduled Task/Job
SecurityEvent
| where EventID == 4698 // Scheduled task created
| where TimeGenerated > ago(1h)
| extend
    TaskName = tostring(EventData.TaskName),
    TaskContent = tostring(EventData.TaskContent),
    SubjectUserName = tostring(EventData.SubjectUserName)
| where TaskName !startswith @"\Microsoft\" // Filter built-in Windows tasks
| extend
    HasNetworkPath = TaskContent has "http",
    HasEncodedContent = TaskContent has "base64" or TaskContent has "-enc",
    HasSystemDir = TaskContent has_any (@"\temp\", @"\appdata\", @"\programdata\")
| where HasNetworkPath or HasEncodedContent or HasSystemDir
| extend Technique = "T1053.005", Severity = "High"
| project TimeGenerated, Computer, SubjectUserName, TaskName, HasNetworkPath, HasEncodedContent
```

**New Local Admin Account**

```kql
// T1136.001 - Create Account: Local Account
SecurityEvent
| where EventID in (4720, 4732) // Account created OR added to group
| where TimeGenerated > ago(2h)
| extend
    NewAccount = tostring(EventData.TargetUserName),
    CreatedBy = tostring(EventData.SubjectUserName),
    GroupName = tostring(EventData.TargetUserName)
| where EventID == 4732 and GroupName =~ "Administrators"
| union (
    SecurityEvent
    | where EventID == 4720
    | extend NewAccount = tostring(EventData.TargetUserName), CreatedBy = tostring(EventData.SubjectUserName)
    | extend GroupName = "N/A"
)
| extend Technique = "T1136.001", Severity = "High"
| project TimeGenerated, Computer, CreatedBy, NewAccount, GroupName, Technique
```

### Credential Access

**Kerberoasting Detection**

```kql
// T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
// Signature: TGS requests (EventID 4769) for RC4 encryption (0x17)
// RC4 is weak and specifically requested by Kerberoasting tools
SecurityEvent
| where EventID == 4769
| where TimeGenerated > ago(1h)
| extend
    ServiceName = tostring(EventData.ServiceName),
    TicketEncryptionType = tostring(EventData.TicketEncryptionType),
    TargetUserName = tostring(EventData.TargetUserName),
    IpAddress = tostring(EventData.IpAddress)
| where TicketEncryptionType == "0x17" // RC4 -- the Kerberoasting signature
| where ServiceName !endswith "$" // Exclude machine accounts
| where ServiceName !in ("krbtgt", "kadmin")
| summarize
    RequestCount = count(),
    Services = make_set(ServiceName)
    by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| extend Technique = "T1558.003", Severity = "High"
| project TimeGenerated, TargetUserName, IpAddress, RequestCount, Services
```

**DCSync Attack Detection**

```kql
// T1003.006 - OS Credential Dumping: DCSync
// DCSync uses replication rights to pull password hashes from a DC
// Signature: 4662 with replication GUIDs from a non-DC account
SecurityEvent
| where EventID == 4662
| where TimeGenerated > ago(1h)
| where ObjectType contains "domainDNS"
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c"  // DS-Replication-Get-Changes-In-Filtered-Set
)
| extend
    SubjectUserName = tostring(EventData.SubjectUserName),
    SubjectDomainName = tostring(EventData.SubjectDomainName)
| where SubjectUserName !endswith "$" // Filter out legitimate DC machine accounts
| extend Technique = "T1003.006", Severity = "Critical"
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName
```

**LSASS Memory Access**

```kql
// T1003.001 - OS Credential Dumping: LSASS Memory
// Tools like Mimikatz access lsass.exe memory to extract credentials
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType == "CreateRemoteThreadApiCall" or ActionType == "OpenProcessApiCall"
| extend TargetProcess = tostring(AdditionalFields.TargetProcessName)
| where TargetProcess =~ "lsass.exe"
| where InitiatingProcessFileName !in~ (
    // Known legitimate processes that access LSASS
    "MsMpEng.exe", "WerFault.exe", "taskmgr.exe",
    "csrss.exe", "wininit.exe", "services.exe"
)
| extend Technique = "T1003.001", Severity = "Critical"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, TargetProcess
```

### Lateral Movement

**Pass-the-Hash Detection**

```kql
// T1550.002 - Use Alternate Authentication Material: Pass the Hash
// Signature: NTLM logon (type 3) with no password entered (no prior 4648)
// Key: NtLmSsp logon from a workstation to another workstation
SecurityEvent
| where EventID == 4624
| where TimeGenerated > ago(1h)
| where LogonType == 3 // Network logon
| where AuthenticationPackageName == "NTLM"
| where WorkstationName != ""
| where TargetDomainName != "NT AUTHORITY"
// Filter: source and target are both workstations (not DC authentication)
| where Computer !contains "DC" and Computer !contains "SERV"
| extend Technique = "T1550.002", Severity = "High"
| project TimeGenerated, Computer, TargetUserName, IpAddress, WorkstationName, LogonType
```

**PsExec / Remote Service Execution**

```kql
// T1021.002 - Remote Services: SMB/Windows Admin Shares
// PsExec creates a service named "PSEXESVC" -- very specific signature
SecurityEvent
| where EventID in (4697, 7045) // Service installed
| where TimeGenerated > ago(1h)
| extend ServiceName = tostring(EventData.ServiceName)
| where ServiceName has_any ("PSEXESVC", "PSEXECSVC")
    or ServiceName matches regex @"^[A-Za-z]{6,8}$" // Random-name services
| extend Technique = "T1021.002", Severity = "High"
| project TimeGenerated, Computer, ServiceName, EventData
```

**Lateral Movement via WMI**

```kql
// T1047 - Windows Management Instrumentation (Remote)
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName !in~ (
    "WmiPrvSE.exe", "scrcons.exe", "unsecapp.exe",
    "mofcomp.exe", "wmiadap.exe"
)
| where FileName in~ (
    "cmd.exe", "powershell.exe", "cscript.exe",
    "wscript.exe", "mshta.exe", "rundll32.exe"
)
| extend Technique = "T1047", Severity = "High"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### Defense Evasion

**Security Log Cleared**

```kql
// T1070.001 - Indicator Removal: Clear Windows Event Logs
// Attackers clear logs to remove evidence -- this IS the evidence
SecurityEvent
| where EventID in (1102, 104)
// 1102 = Security log cleared (requires admin)
// 104 = System log cleared
| extend
    SubjectUserName = tostring(EventData.SubjectUserName),
    LogType = iff(EventID == 1102, "Security", "System")
| extend Technique = "T1070.001", Severity = "High"
| project TimeGenerated, Computer, SubjectUserName, LogType
```

**Antivirus / MDE Tampering**

```kql
// T1562.001 - Impair Defenses: Disable or Modify Tools
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType in (
    "AntivirusDetectionFailure", "AntivirusDisabled", "SecurityProductStateChange"
)
| union (
    DeviceRegistryEvents
    | where RegistryKey has_any (
        @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        @"HKLM\SOFTWARE\Microsoft\Windows Defender"
    )
    | where RegistryValueName in~ ("DisableAntiSpyware", "DisableAntiVirus", "DisableRealtimeMonitoring")
    | where RegistryValueData == "1"
)
| extend Technique = "T1562.001", Severity = "Critical"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessAccountName
```

### Command & Control

**DNS Beaconing Detection**

```kql
// T1071.004 - Application Layer Protocol: DNS
// Beacon signature: same domain queried at highly regular intervals
DnsEvents
| where TimeGenerated > ago(4h)
| where QueryType == "A" or QueryType == "AAAA"
| where Name !endswith ".microsoft.com"
    and Name !endswith ".windows.com"
    and Name !endswith ".azure.com"
| summarize
    QueryCount = count(),
    QueryTimes = make_list(TimeGenerated),
    Computers = make_set(Computer)
    by Name, bin(TimeGenerated, 1h)
| where QueryCount > 30 // High frequency to same domain
| extend Technique = "T1071.004", Severity = "Medium"
| project TimeGenerated, Name, QueryCount, Computers
```

**Long Connection Duration (C2 Keep-Alive)**

```kql
// T1095 - Non-Application Layer Protocol
// C2 channels maintain long connections -- unusual for legitimate traffic
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType == "NetworkConnectionEvents"
| where RemotePort !in (80, 443, 22, 25, 53, 8080, 8443)
| summarize
    ConnectionCount = count(),
    TotalBytes = sum(SentBytes + ReceivedBytes),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where DurationMinutes > 60 and ConnectionCount > 100
| extend Technique = "T1095", Severity = "Medium"
```

### Exfiltration

**DNS Tunneling**

```kql
// T1048.003 - Exfiltration Over Alternative Protocol: DNS
// Signature: abnormally long DNS queries or high data volume per query
DnsEvents
| where TimeGenerated > ago(2h)
| extend QueryLength = strlen(Name)
| where QueryLength > 50 // Unusually long DNS query = encoded data
| summarize
    LongQueryCount = count(),
    AvgQueryLength = avg(QueryLength),
    MaxQueryLength = max(QueryLength),
    SampleQueries = make_list(Name, 5)
    by Computer, bin(TimeGenerated, 10m)
| where LongQueryCount > 20
| extend Technique = "T1048.003", Severity = "High"
```

**Large Outbound Data Transfer**

```kql
// T1041 - Exfiltration Over C2 Channel
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public" // Only external destinations
| summarize
    TotalBytesSent = sum(SentBytes),
    UniqueDestinations = dcount(RemoteIP),
    TopDestination = arg_max(SentBytes, RemoteIP)
    by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 15m)
| where TotalBytesSent > 100000000 // >100MB in 15 minutes
| extend
    DataSentGB = round(TotalBytesSent / 1073741824.0, 2),
    Technique = "T1041",
    Severity = "High"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, DataSentGB, UniqueDestinations
```

---

## 3. Honeypot-Specific Queries

```kql
// ANY interaction with honeypot assets (NRT -- Near Real Time)
// Zero false positives -- no legitimate traffic should touch these
let HoneypotAssets = (_GetWatchlist('Honeypot_Assets') | project HoneypotIP = SearchKey);
HoneypotEvents_CL
| where TimeGenerated > ago(5m)
| lookup kind=inner HoneypotAssets on $left.DestIP_s == $right.HoneypotIP
| extend Technique = "T1078", Severity = "High"
| project TimeGenerated, HoneypotName_s, SourceIP_s, DestPort_d, ServiceType_s, CredentialUsed_s
```

```kql
// Honeypot credential reuse on legitimate systems
// Critical: attacker grabbed creds from lure and tried them on real assets
let HoneypotCreds = HoneypotEvents_CL
    | where isnotempty(CredentialUsed_s)
    | extend UserName = split(CredentialUsed_s, ":")[0]
    | distinct tostring(UserName);
SecurityEvent
| where EventID in (4624, 4625)
| where TargetUserName in (HoneypotCreds)
| extend IsSuccess = iff(EventID == 4624, "Yes", "No")
| extend Technique = "T1078", Severity = "Critical"
| project TimeGenerated, Computer, TargetUserName, IpAddress, IsSuccess
```

---

## 4. Threat Hunting Queries (Not Deployed as Rules)

These live in `/99_hunting/` — run proactively, not automatically.

**Long-Tail Process Analysis — Find Rare Executables**

```kql
// Find processes that run on very few machines -- rare = suspicious
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| summarize
    MachineCount = dcount(DeviceName),
    RunCount = count(),
    Machines = make_set(DeviceName, 5)
    by FileName, SHA256
| where MachineCount <= 2 and RunCount >= 5
| where FileName !endswith ".tmp"
| order by MachineCount asc, RunCount desc
```

**Beaconing Detection Hunt — Statistical Analysis**

```kql
// Find processes making highly regular network connections
// Regular interval = beacon. Irregular = human browsing.
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize ConnectionTimes = make_list(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where array_length(ConnectionTimes) > 20
| extend
    Sorted = array_sort_asc(ConnectionTimes),
    Count = array_length(ConnectionTimes)
// Calculate time deltas between connections
| mv-expand with_itemindex=i ConnectionTime = Sorted to typeof(datetime)
| order by DeviceName, InitiatingProcessFileName, RemoteIP, i
| serialize
| extend Delta = iff(
    prev(DeviceName) == DeviceName and prev(RemoteIP) == RemoteIP,
    datetime_diff('second', ConnectionTime, prev(ConnectionTime)),
    long(null)
)
| where isnotnull(Delta) and Delta > 0
| summarize
    AvgDelta = avg(Delta),
    StdDev = stdev(Delta),
    ConnectionCount = count()
    by DeviceName, InitiatingProcessFileName, RemoteIP
| extend ConsistencyScore = iff(StdDev < 30, "High", iff(StdDev < 120, "Medium", "Low"))
| where ConsistencyScore == "High" and ConnectionCount > 15
| order by ConsistencyScore asc, AvgDelta asc
```

**Rare Parent-Child Process Relationships**

```kql
// Find unusual process parent-child pairs -- great for finding novel malware
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| summarize
    PairCount = count(),
    MachineCount = dcount(DeviceName)
    by InitiatingProcessFileName, FileName
| where MachineCount <= 2
| where FileName !in~ ("conhost.exe", "WerFault.exe")
| order by MachineCount asc, PairCount asc
```

---

## 5. KQL Functions — Reusable Building Blocks

Saved as Sentinel Functions so every rule can call them.

```kql
// FUNCTION: IsKnownGoodIP
// Checks if an IP is in the whitelist watchlists
let IsKnownGoodIP = (ip: string) {
    let KnownGood = union
        (_GetWatchlist('Known_Scanners') | project SearchKey),
        (_GetWatchlist('Internal_IPs') | project SearchKey);
    KnownGood
    | where SearchKey == ip
    | count
    | project IsKnown = (Count > 0)
};

// FUNCTION: GetAssetCriticality
// Returns criticality tier for a given hostname
let GetAssetCriticality = (hostname: string) {
    _GetWatchlist('Range_Assets')
    | where SearchKey =~ hostname
    | project Criticality = iff(isnotempty(Criticality), Criticality, "Unknown")
};
```

---

## 6. Alert Severity Matrix

Wired directly into every KQL rule via `extend Severity`.

| Severity | Examples |
|---|---|
| **Critical** | DCSync, LSASS dump, honeypot credential reuse, AV disabled |
| **High** | Kerberoasting, log cleared, password spray success, new admin account, confirmed lateral movement |
| **Medium** | LOLBin execution, brute force with no success, suspected DNS beaconing, large outbound transfer |
| **Low** | Single failed login, scheduled task with no suspicious content, new service with a legitimate parent |
| **Info** | Honeypot hit — auto-enriched, sent to Threat Intel |

---

## 7. Detection Rule Deployment Process

1. Write the rule in `/99_hunting/` first — run as a hunt query manually
2. Validate against 7 days of historical data — check volume, confirm true positives versus noise, tune thresholds until the false-positive rate is acceptable
3. Move to the correct MITRE folder
4. Peer review — a second Detection Engineer reviews the KQL
5. Deploy to Sentinel Analytics Rules in a **disabled** state
6. Run in the test environment for 48 hours, monitoring results
7. Enable in production with severity set one level **lower** than intended
8. Monitor for 1 week, tuning as needed
9. Promote to final severity only after validation

<br/>

---
<br/>

# Part II — MISP Threat Intel Platform — Deep Dive

## 1. What MISP Does in the SOC

MISP serves four functions:

1. **IOC Storage** — central database of IPs, domains, hashes, and TTPs
2. **IOC Enrichment** — Sentinel queries MISP before alerting
3. **IOC Sharing** — export feeds to Sentinel watchlists and block lists
4. **Intel Analysis** — link indicators to campaigns, actors, and techniques

---

## 2. MISP Architecture in Azure

<div align="center">
<img src="images/misp-azure-deployment.png" alt="MISP deployed on an Ubuntu 22.04 VM in the SOC Ops subnet, running the MISP web application, MySQL, Redis, and Apache2, accessed internally via Azure Bastion and queried by Microsoft Sentinel over the MISP REST API" width="700"/>
</div>

---

## 3. MISP Installation

**Step 1 — download and run the official MISP install script**

```bash
# On Ubuntu 22.04 LTS in the SOC Ops subnet
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
chmod +x /tmp/INSTALL.sh
sudo /tmp/INSTALL.sh -A   # -A = automated install with all defaults

# This installs: MISP, MySQL, Redis, Apache2, PHP, PyMISP
# Takes approximately 15-20 minutes
```

**Step 2 — set the base URL**

```bash
sudo -u www-data /var/www/MISP/app/Console/cake \
    Admin setSetting "MISP.baseurl" "https://10.0.1.50"
```

**Step 3 — create the first API key**

```text
Login to MISP web UI → My Profile → Auth keys → Add new auth key
Save this key -- Sentinel Logic Apps will use it
```

**Step 4 — enable required modules**

```bash
sudo -u www-data /var/www/MISP/app/Console/cake \
    Admin setSetting "Plugin.Enrichment_enable" true
```

---

## 4. MISP Data Model — How Intel Is Organized

```text
MISP HIERARCHY:

Event (top level)
├── Info: "Honeypot activity - SSH brute force campaign"
├── Date: 2026-01-15
├── Threat Level: High
├── Distribution: This Community Only
├── Tags: tlp:amber, mitre:T1110.001, campaign:range-jan-2026
│
└── Attributes (the actual IOCs)
    ├── ip-src: 185.220.101.45 (source IP from honeypot)
    ├── ip-src: 194.165.16.71
    ├── domain: c2-bad-domain.xyz
    ├── md5: a1b2c3d4... (malware hash from range)
    ├── filename: svchost32.exe (fake svchost -- persistence)
    └── url: http://bad.xyz/payload.ps1
```

**Tag taxonomy — defined before anyone adds data:**

| Category | Tags |
|---|---|
| **Mandatory, every event** | `tlp:white` / `tlp:green` / `tlp:amber` / `tlp:red` (sharing level) · `source:honeypot` / `source:mde` / `source:external` / `source:osint` · `confidence:low` / `confidence:medium` / `confidence:high` · `status:active` / `status:historical` / `status:falsepositive` |
| **MITRE, added when known** | `mitre-attack:T1110` (technique) · `mitre-attack:TA0001` (tactic) |
| **Campaign** | `campaign:[name]-[year]` |

---

## 5. Free Threat Intel Feeds to Connect

Configured in MISP → Sync → Feeds. All free:

| Feed | Contents | Format | Update Frequency |
|---|---|---|---|
| **Abuse.ch URLhaus** | Malicious URLs | MISP | Every 1 hour |
| **Abuse.ch MalwareBazaar** | Malware hashes | MISP | Every 4 hours |
| **Abuse.ch ThreatFox** | IOCs — IPs, domains, URLs | MISP | Every 4 hours |
| **CIRCL OSINT Feed** | Community OSINT | MISP | Daily |
| **AlienVault OTX** | Community threat data (free account required) | TAXII 2.0 | Daily |
| **Feodo Tracker** | C2 infrastructure | MISP | Every 2 hours |

---

## 6. MISP → Sentinel Integration

The critical pipeline — intel collected in MISP flows automatically into Sentinel
detections.

### Method 1: Sentinel Threat Intelligence Connector (Recommended)

```python
# Python script -- runs on a scheduled Azure Function or cron job
# Pulls IOCs from MISP and pushes to the Sentinel ThreatIntelligenceIndicators table

from pymisp import PyMISP
import requests
from datetime import datetime, timedelta

MISP_URL = "https://10.0.1.50"
MISP_KEY = "your-api-key"
SENTINEL_WORKSPACE_ID = "your-workspace-id"
SENTINEL_KEY = "your-primary-key"

# Connect to MISP
misp = PyMISP(MISP_URL, MISP_KEY, ssl=False)

# Pull recent events (last 24 hours) with high/medium confidence
events = misp.search(
    controller='attributes',
    type_attribute=['ip-dst', 'ip-src', 'domain', 'md5', 'sha256', 'url'],
    tags=['confidence:high', 'confidence:medium'],
    timestamp=int((datetime.now() - timedelta(hours=24)).timestamp()),
    to_ids=True  # Only export attributes marked as indicators
)

# Push each IOC to Sentinel Log Analytics (Custom Logs API)
for attribute in events:
    indicator = {
        "indicatorType": map_misp_type(attribute['type']),
        "indicatorValue": attribute['value'],
        "confidence": get_confidence(attribute['tags']),
        "expirationDateTime": (datetime.now() + timedelta(days=30)).isoformat(),
        "source": "MISP-CyberRange",
        "threatType": "MaliciousUrl",  # adjust per type
        "tlpLevel": get_tlp(attribute['tags'])
    }
    push_to_sentinel(indicator, SENTINEL_WORKSPACE_ID, SENTINEL_KEY)
```

### Method 2: Sentinel Watchlist Auto-Update via Logic App

**Schedule:** every 4 hours

**Actions:**
1. HTTP GET → MISP API `/attributes/restSearch` (active IOCs only)
2. Parse the JSON response, extracting values by type
3. For each IOC type — IPs update `IOC_Blocklist`, domains update `Malicious_Domains`, hashes update `Malicious_Hashes`
4. Log the update summary to a Sentinel custom table

---

## 7. MISP API — Key Queries for Playbooks

```python
# Query 1: Check if an IP is in MISP (called by the Sentinel enrichment playbook)
def check_ip_in_misp(ip_address):
    result = misp.search(
        controller='attributes',
        value=ip_address,
        type_attribute='ip-src'
    )
    if result:
        return {
            "found": True,
            "event_count": len(result),
            "tags": [tag['name'] for attr in result for tag in attr.get('Tag', [])],
            "first_seen": min(attr['timestamp'] for attr in result)
        }
    return {"found": False}
```

```python
# Query 2: Add a new IOC from a honeypot hit
def add_honeypot_ioc(ip, service, timestamp):
    event = MISPEvent()
    event.info = f"Honeypot hit - {service} - {timestamp}"
    event.threat_level_id = 2  # High
    event.distribution = 0     # This community only
    event.add_tag("source:honeypot")
    event.add_tag("confidence:medium")
    event.add_tag("tlp:amber")

    attr = event.add_attribute('ip-src', ip)
    attr.to_ids = True  # Flag as actionable indicator
    attr.add_tag(f"service:{service}")

    misp.add_event(event)
    return event.uuid
```

---

## 8. Threat Intel Workflow — Team Operating Procedure

**Daily (Threat Intel Analyst)**
- Review the MISP dashboard for new IOCs from overnight feeds
- Check honeypot IOCs added by the SOAR playbook
- Validate any auto-added IOCs — real or false?
- Mark stale IOCs (over 30 days, no new hits) for expiry review

**Weekly**
- Review all events created that week — tagged correctly?
- Correlate — are the same IPs hitting honeypots *and* appearing in external feeds?
- Brief Detection Engineering on new IOCs that need detection rules
- Publish the Weekly Intel Brief to the SOC
- Export a fresh IOC list and update Sentinel watchlists

**Monthly**
- Publish a threat landscape report
- Review feed quality — which feeds generate true positives?
- Perform MISP data hygiene — expire outdated indicators
- Confidence review — promote medium to high based on additional sightings

---

## 9. MISP + Sentinel — The Intel Loop

<div align="center">
<img src="images/intel-feedback-loop.png" alt="Full intel feedback loop from an attacker hitting a honeypot, through automatic MISP IOC creation, a four-hour Sentinel watchlist sync, KQL detection rules querying the watchlist, alert firing with MISP context attached, analyst confirmation, and rising confidence scores for future alerts" width="560"/>
</div>

---

## 10. Build Checklist

**Week 1**
- [ ] Deploy the MISP VM in the SOC Ops subnet (Ubuntu 22.04)
- [ ] Run the automated install script
- [ ] Configure the base URL and admin account
- [ ] Generate the API key for Sentinel integration
- [ ] Add the tag taxonomy before any data goes in
- [ ] Enable the first 3 free feeds (Abuse.ch URLhaus, MalwareBazaar, ThreatFox)

**Week 2**
- [ ] Write the PyMISP sync script to push IOCs to the Sentinel TI table
- [ ] Schedule the sync as an Azure Function (every 4 hours)
- [ ] Build the Logic App: SOAR honeypot hit → auto-add IP to MISP
- [ ] Train the Threat Intel team on creating events and tagging
- [ ] Validate that IOCs from MISP appear in the Sentinel TI table

**Week 3**
- [ ] Connect the AlienVault OTX feed
- [ ] Connect the CIRCL OSINT feed
- [ ] Build the MISP enrichment call into the Tier 1 SOAR enrichment playbook
- [ ] Create a weekly IOC export to update all Sentinel watchlists
- [ ] Run the first manual IOC hunt — search MISP feed IOCs against 30 days of logs

**Ongoing**
- [ ] Monthly — expire IOCs with no new hits for over 60 days
- [ ] Monthly — review feed quality; are external feeds generating true hits?
- [ ] Quarterly — full intel library review with the Threat Intel team

<br/>

---

## The Complete Stack — Everything Connected

<div align="center">
<img src="images/complete-stack-loop.png" alt="Complete detection and intel stack loop — attacker activity captured by honeypots, centralized in MDE and Sentinel, automated and enriched by SOAR and Logic Apps, matched against MISP-synced watchlists by KQL detection rules, and routed through an AI-agentic brief to analyst decision, closing the loop back to MISP" width="600"/>
</div>

<br/>

<div align="center">

*Every query in this library was validated against real data before it was trusted —*
*and every indicator MISP holds got there because something in this range actually saw it.*

</div>
