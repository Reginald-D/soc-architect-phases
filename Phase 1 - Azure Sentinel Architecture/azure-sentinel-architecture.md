<div align="center">

# AZURE SENTINEL ARCHITECTURE
### Phase I — Foundation, Detection, and Automated Response

*Log Analytics design · Honeypot network engineering · AI-agentic SOAR*

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel-0078D4?style=flat-square)
![Layer](https://img.shields.io/badge/Layer-Detection%20Engineering-2b2b2b?style=flat-square)
![Layer](https://img.shields.io/badge/Layer-SOAR%20Automation-2b2b2b?style=flat-square)
![Status](https://img.shields.io/badge/Status-Phase%201-2ea44f?style=flat-square)

</div>

<br/>

> *A SIEM is only as good as what feeds it, and automation is only safe if it is sequenced*
> *deliberately. This document is the architecture behind both — how signal is generated,*
> *ingested, detected, and finally acted on, with a human in the loop until the system has*
> *earned the right to act alone.*

<br/>

---

## Contents

**Part I — Azure Sentinel Architecture**
[Foundation](#1-foundation--log-analytics-workspace-design) · [Data Connectors](#2-data-connector-priority-order) · [Data Ingestion](#3-data-ingestion-architecture) · [Analytics Rules](#4-analytics-rules--the-detection-layer) · [RBAC](#5-rbac--access-control-design) · [Watchlists](#6-watchlists--the-operational-intelligence-layer) · [Cost Management](#7-cost-management) · [Workbooks](#8-sentinel-workbooks--build-order) · [Build Checklist](#9-sentinel-build-checklist)

**Part II — Honeypot Network Design**
[Design Philosophy](#1-core-design-philosophy) · [Network Topology](#2-network-topology--azure-vnet-architecture) · [Honeypot Themes](#3-honeypot-themes--what-to-deploy-and-why) · [Software Stack](#4-honeypot-software-stack) · [Log Pipeline](#5-log-pipeline--honeypot--sentinel) · [Detection Rules](#6-sentinel-detection-rules-for-honeypots) · [Operations](#7-honeypot-operations--team-workflow) · [Build Checklist](#8-honeypot-build-checklist)

**Part III — AI-Agentic SOAR Workflow**
[Architecture Principles](#1-soar-architecture-principles) · [Automation Tiers](#2-the-three-automation-tiers) · [Full Pipeline](#3-full-soar-architecture) · [Playbooks](#4-logic-app-playbooks--build-order) · [Confidence Scoring](#5-ai-agentic-decision-model--confidence-scoring) · [Integrated Loop](#6-the-full-integrated-loop) · [Build Checklist](#7-soar-build-checklist)

---
<br/>

# Part I — Azure Sentinel Architecture

## 1. Foundation — Log Analytics Workspace Design

**Rule: one workspace to start. Expand only when there is a documented reason.**

Many architects over-engineer this early with multiple workspaces. That instinct is
resisted here. A single workspace delivers:

- Unified KQL queries across every data source
- Simpler RBAC (role-based access control) management
- Lower cost — no cross-workspace query fees
- Easier correlation rules

<div align="center">
<img width="1186" height="1327" alt="workspace-hierarchy" src="https://github.com/user-attachments/assets/c988a871-6a62-46cf-9937-70ff01eaaa8a" />
</div>

---

## 2. Data Connector Priority Order

Not all data sources are equal. Ingestion follows a strict tier order — each tier builds
on the last.

### Tier 1 — Connect These Day 1

| Connector | What It Gives You | How |
|---|---|---|
| **Microsoft Defender for Endpoint** | Process, file, network, and alert telemetry from every range endpoint | M365 Defender connector (native, free) |
| **Azure Active Directory** | Sign-in logs, audit logs, risky users, risky sign-ins | AAD Diagnostics Settings → LAW |
| **Azure Activity Logs** | Control plane — who changed what in Azure | Azure Policy / Diagnostic Settings |
| **Microsoft Defender for Cloud** | Vulnerability alerts, misconfiguration detections | Native connector |

### Tier 2 — Connect in Week 2

| Connector | What It Gives You |
|---|---|
| **Syslog (Linux range boxes)** | Raw OS-level events from range machines |
| **Windows Security Events** | Event IDs 4624 / 4625 / 4688 / 4698 — login, process, scheduled tasks |
| **DNS Logs** | Beaconing detection, DNS tunneling, C2 communication |
| **Azure Firewall / NSG Flow Logs** | East-west and north-south network visibility |

### Tier 3 — Connect When Honeypots Are Live

| Connector | What It Gives You |
|---|---|
| **Custom REST API / Syslog** | Honeypot hit data from OpenCanary or Thinkst |
| **Threat Intelligence Platforms** | MISP IOC feeds via TI connector |
| **CEF via AMA Agent** | Any appliance that speaks Common Event Format |

---

## 3. Data Ingestion Architecture

<div align="center">
<img width="1360" height="1240" alt="data-ingestion-architecture" src="https://github.com/user-attachments/assets/34311dd8-22d9-4ec9-9131-214a1ac49849" />
</div>

---

## 4. Analytics Rules — The Detection Layer

Sentinel supports four rule types. Knowing when to use each is the difference between
signal and noise.

### Scheduled Rules (The Primary Detection Engine)

KQL queries that run on a schedule. This is where Detection Engineering lives.

```kql
// Detect brute force against honeypot accounts
SecurityEvent
| where EventID == 4625
| where AccountType == "User"
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| extend Severity = "High"
```

**Key settings configured on every rule:**
- Query frequency — how often it runs, every 5 minutes versus every hour
- Lookup period — how far back it looks, must be ≥ frequency
- Alert threshold — how many results trigger an alert
- Entity mapping — map IPs, users, and hosts to Sentinel entities, critical for UEBA and automation

### Microsoft Security Rules
Auto-create Sentinel incidents from MDE alerts. Enabled for every Tier 1 alert category —
MDE does the heavy lifting, Sentinel creates the incident with full context.

### Anomaly Rules (Built-in ML)
Sentinel's UEBA engine, enabled for:
- Impossible travel detection
- Unusual login times
- Abnormal data access volumes

Good low-noise signal for T2 analysts.

### NRT Rules (Near Real-Time)
Reserved for the highest-priority detections — fires within roughly one minute of data
arriving. Used sparingly, for cases like:
- Honeypot credential use on production systems
- MDE isolation bypass attempts
- Azure admin role assignment outside a change window

---

## 5. RBAC — Access Control Design

Defined before anyone else touches the workspace.

<div align="center">
<img width="1024" height="1536" alt="rbac-tiers" src="https://github.com/user-attachments/assets/643f1d17-f2a1-4559-a30f-c6454a7d11aa" />
</div>

---

## 6. Watchlists — The Operational Intelligence Layer

Watchlists are lookup tables inside Sentinel that power smarter detections. Built early:

| Watchlist | Contents | Used For |
|---|---|---|
| **VIP_Accounts** | Admin accounts, service accounts | Escalate severity on any alert touching these |
| **Honeypot_Assets** | All honeypot IPs and hostnames | Any connection to these = instant High severity |
| **Known_Scanners** | Shodan, security research IPs | Reduce false positives on honeypot hits |
| **Range_Assets** | All live range machine IPs/names | Scope detection rules to range only |
| **IOC_Blocklist** | Malicious IPs/domains/hashes from MISP | Enrich alerts, drive automated blocking |

```kql
// Use a watchlist inside a detection rule
let HoneypotAssets = (_GetWatchlist('Honeypot_Assets') | project SearchKey);
SecurityEvent
| where Computer in (HoneypotAssets)
| where EventID == 4624 // Successful logon
```

---

## 7. Cost Management

Sentinel charges per GB ingested. A live cyber range with active attacks can generate
real volume — this gets ignored at the architecture's peril.

**Cost control levers:**

**Data Collection Rules (DCR) — filter before ingestion.** Noisy logs are never ingested
directly; DCRs filter at the agent level before data reaches the workspace.

```text
Security Events → DCR filter → Only EventID in (4624, 4625, 4648, 4688, 4698, 4720, 4768) → Workspace
```

**Commitment Tiers.** Once daily ingestion volume is known, Pay-As-You-Go switches to a
Commitment Tier — the 100GB/day tier saves roughly 15% versus PAYG. Azure's pricing
calculator gets checked monthly for the first two months.

**Basic Logs vs. Analytics Logs**
- **Analytics Logs** — full query capability, higher cost → security-critical tables
- **Basic Logs** — cheap storage, limited query → verbose raw logs (DNS, network flows)
- **Archive Tier** — cold storage, very cheap → compliance retention, rarely queried

**Recommended table tier assignments:**

| Tier | Tables |
|---|---|
| **Analytics (hot)** | SecurityAlert, SecurityEvent, MDE tables, AADSignInLogs |
| **Basic (warm)** | Syslog, WindowsEvent (verbose), AzureActivity |
| **Archive (cold)** | Raw network flows older than 90 days |

---

## 8. Sentinel Workbooks — Build Order

Analyst dashboards, built in this priority order:

1. **SOC Overview** — active incidents by severity, MTTD/MTTR trends, analyst workload
2. **MDE Alert Dashboard** — endpoint alert trends, top affected machines, alert categories
3. **Honeypot Activity** — hits by time, source geography, techniques observed
4. **Authentication Anomalies** — failed logins, impossible travel, off-hours access
5. **MITRE ATT&CK Coverage** — techniques detected versus techniques still blind to

Microsoft's free community workbook templates are imported from the Sentinel Content Hub
before building anything from scratch.

---

## 9. Sentinel Build Checklist

**Week 1**
- [ ] Create Resource Group and Log Analytics Workspace
- [ ] Enable Microsoft Sentinel on the workspace
- [ ] Connect MDE via M365 Defender connector
- [ ] Connect Azure Active Directory (sign-in + audit logs)
- [ ] Set log retention policy (90 days hot, archive decision made)
- [ ] Create RBAC groups and assign roles

**Week 2**
- [ ] Connect Windows Security Events (via AMA + DCR)
- [ ] Connect Syslog for Linux range machines
- [ ] Enable Azure Defender for Cloud connector
- [ ] Build watchlists: VIP_Accounts, Range_Assets, Honeypot_Assets
- [ ] Enable built-in Microsoft Security rules (MDE → Sentinel incidents)
- [ ] Enable top 5 Scheduled Analytics rules from Content Hub
- [ ] Build SOC Overview workbook

**Week 3**
- [ ] Connect DNS logs and NSG flow logs
- [ ] Build alert severity matrix (aligned with the roadmap)
- [ ] Configure entity mapping on all active analytics rules
- [ ] Enable UEBA (takes 7 days to baseline — start it now)
- [ ] Set up Sentinel cost alert in Azure Cost Management
- [ ] Begin KQL query library in shared repo

<br/>

---
<br/>

# Part II — Honeypot Network Design

> **The single most important rule:** the Honeypot DMZ must have **no** outbound route to
> the SOC Operations subnet. Attackers who compromise a honeypot get zero pivot path to
> the Sentinel workspace, Logic Apps, or analyst machines.

## 1. Core Design Philosophy

Honeypots serve **three simultaneous purposes**, designed for from the start:

| Purpose | What It Delivers |
|---|---|
| **Detection** | Attacker touches honeypot = instant high-fidelity alert |
| **Intelligence** | Captures TTPs, tools, and behaviors for the Threat Intel team |
| **Training** | Gives analysts real attacker traffic to investigate |

A honeypot that only detects but doesn't capture intelligence is a missed opportunity. A
honeypot that captures intelligence but isn't wired to Sentinel is an island. The pipeline
is designed first.

---

## 2. Network Topology — Azure VNet Architecture

<div align="center">
<img width="1213" height="1297" alt="vnet-topology" src="https://github.com/user-attachments/assets/1c364cfd-48af-4f65-9326-1e49e3a74d4c" />
</div>

---

## 3. Honeypot Themes — What to Deploy and Why

Each honeypot is designed to attract a specific attacker behavior. The goal is
**believability** — a convincing lure captures more intelligence than a generic one.

### Honeypot 1 — Fake Domain Controller *(Priority: Deploy First)*

**Why first:** domain controllers are the crown jewel of every Windows environment.
Attackers go for them automatically — any interaction is high-confidence and malicious.

| | |
|---|---|
| **Hostname** | CORP-DC01 |
| **IP** | 10.0.3.10 |
| **OS** | Windows Server 2019 |

**Lures:** live Active Directory with real LDAP responses; fake admin accounts
(`svc-backup`, `svc-sql`, `helpdesk-admin`); fake GPOs referencing a "finance share"; DNS
resolving fake internal hostnames; Kerberos responding to AS-REQ to capture Kerberoasting
attempts.

**Catches:** Kerberoasting, DCSync attempts, pass-the-hash / pass-the-ticket, enumeration
(BloodHound runs), credential spray against AD accounts.

### Honeypot 2 — Fake File Server

| | |
|---|---|
| **Hostname** | CORP-FILES01 |
| **IP** | 10.0.3.11 |
| **OS** | Windows Server 2019 |

**Lures:** SMB shares (`\\CORP-FILES01\Finance`, `\HR`, `\IT-Admin`); fake documents with
embedded canary tokens; a fake `credentials.txt` in the IT-Admin share; a "Confidential"
PDF in Finance with a canary token.

**Catches:** SMB enumeration, data exfiltration attempts, canary-token fires from anywhere
the bait file is opened, ransomware encryption attempts.

### Honeypot 3 — Fake Database Server

| | |
|---|---|
| **Hostname** | CORP-DB01 |
| **IP** | 10.0.3.12 |
| **OS** | Ubuntu 22.04 |
| **Services** | MySQL (3306), MSSQL (1433) — both listening, both fake |

**Lures:** a database named `HR_Employees` with fake PII records; a database named
`Finance_2024` with fake transaction data; a deliberately weak credential (`sa` /
`Password123`).

**Catches:** port scanning and service enumeration, SQL injection attempts, credential
brute force against DB ports, data dump attempts.

### Honeypot 4 — Fake Admin Jump Box

| | |
|---|---|
| **Hostname** | IT-ADMIN-JUMP |
| **IP** | 10.0.3.13 |
| **OS** | Windows 10 |

**Lures:** RDP open on 3389; saved RDP connections to "prod servers" in `.rdp` files on
the desktop; browser-saved passwords to fake internal systems; PuTTY saved sessions to
fake Linux servers.

**Catches:** RDP brute force, credential harvesting from browser/PuTTY, lateral movement
using harvested credentials.

### Honeypot 5 — Canary Tokens *(Distributed, Not a Server)*

Deployed everywhere — they cost nothing and give detection coverage in places honeypot
servers can't reach.

**Token types deployed:** Word document in every fake file share; fake AWS access key in a
`config.txt` on the file server; DNS canary token that fires on lookup of a fake internal
domain; web-bug token in a fake internal wiki page; Windows folder token that fires when a
"sensitive" directory is browsed.

**Tool:** [canarytokens.org](http://canarytokens.org) — free, self-hostable. Every token
alerts through a webhook into a Sentinel custom log table.

---

## 4. Honeypot Software Stack

**OpenCanary** *(free, primary choice for this range)* — a lightweight Python daemon that
simulates services without being a full OS. Runs on a single Linux VM and can emulate SSH,
FTP, HTTP, SMB, MySQL, VNC, and RDP banners simultaneously.

```bash
# Install on Ubuntu 22.04
pip install opencanary
opencanaryd --copyconfig      # generates opencanary.conf
# Edit conf to enable services
opencanaryd --start
```

```json
{
  "ssh.enabled": true,
  "ftp.enabled": true,
  "http.enabled": true,
  "smb.enabled": true,
  "mysql.enabled": true,
  "rdp.enabled": true,
  "logger": {
    "class": "PyLogger",
    "kwargs": {
      "formatters": { "plain": { "format": "%(message)s" } },
      "handlers": {
        "Syslog": {
          "class": "logging.handlers.SysLogHandler",
          "host": "<your-syslog-forwarder-IP>",
          "port": 514
        }
      }
    }
  }
}
```

**Thinkst Canary** *(commercial, roughly $7,500/yr for 5 devices)* — where budget allows,
this is best-in-class: physical or virtual appliances, highly realistic, with a management
console and built-in alerting. Worth it for a production-grade SOC training environment.

---

## 5. Log Pipeline — Honeypot → Sentinel

The most important piece of the honeypot architecture. Every hit lands in Sentinel with
full context, automatically.

<div align="center">
<img width="927" height="1696" alt="log-pipeline" src="https://github.com/user-attachments/assets/49760427-e889-4f11-bb04-5d113b637b96" />
</div>

**Custom table schema for `HoneypotEvents_CL`:**

```text
TimeGenerated     : datetime
HoneypotName      : string  -- which honeypot was hit
SourceIP          : string  -- attacker IP
DestPort          : int     -- service targeted
ServiceType       : string  -- SSH, RDP, SMB, HTTP, etc.
CredentialUsed    : string  -- username/password attempted (if applicable)
AttackTechnique   : string  -- MITRE ATT&CK technique tag
RawPayload        : string  -- full raw event for analysis
```

---

## 6. Sentinel Detection Rules for Honeypots

```kql
// Rule 1: ANY interaction with any honeypot asset (NRT Rule)
// Should NEVER fire for legitimate traffic — zero false positives
HoneypotEvents_CL
| where TimeGenerated > ago(5m)
| extend HoneypotIP = DestIP_s
| join kind=inner (_GetWatchlist('Honeypot_Assets')) on $left.HoneypotIP == $right.SearchKey
| project TimeGenerated, HoneypotName_s, SourceIP_s, DestPort_d, ServiceType_s, CredentialUsed_s
```

```kql
// Rule 2: Honeypot credential reuse on real systems
// Attacker grabbed creds from a honeypot and tried them on real systems
let HoneypotCreds = HoneypotEvents_CL
    | where CredentialUsed_s != ""
    | distinct CredentialUsed_s;
SecurityEvent
| where EventID == 4624 // Successful logon
| where TargetUserName in (HoneypotCreds)
| where Computer !in ((_GetWatchlist('Honeypot_Assets') | project SearchKey))
```

```kql
// Rule 3: Brute force pattern against a honeypot
HoneypotEvents_CL
| where ServiceType_s in ("SSH", "RDP", "SMB")
| summarize Attempts = count() by SourceIP_s, HoneypotName_s, bin(TimeGenerated, 5m)
| where Attempts > 5
```

---

## 7. Honeypot Operations — Team Workflow

Defined before the Mini SOC team starts operating.

**Daily checklist (honeypot shift)**
- [ ] Review `HoneypotEvents_CL` for the last 24h — any new source IPs?
- [ ] Check OpenCanary service health — all services responding?
- [ ] New IPs → enrich in MISP, tag with first-seen date
- [ ] New TTPs observed → brief Detection Engineering (weekly)
- [ ] Canary token fires → full investigation, treated as Severity High

**Weekly**
- [ ] Draft the Monthly Honeypot Activity Report
- [ ] Send new IOCs to the Threat Intel team
- [ ] Evaluate whether current honeypot themes are still attracting traffic
- [ ] Review any honeypot showing zero hits — redesign the lure

**Escalation trigger**
If a honeypot credential is successfully used on a *non-honeypot* system, it is
immediately escalated to the T2 / IR team — this means an attacker is pivoting out of the
honeypot network.

---

## 8. Honeypot Build Checklist

**Week 1**
- [ ] Create Honeypot DMZ subnet (10.0.3.0/24) in Azure
- [ ] Configure NSG rules (no pivot path to SOC Ops subnet)
- [ ] Deploy Syslog Forwarder VM (Ubuntu, AMA agent installed)
- [ ] Deploy OpenCanary on first VM — fake DC theme
- [ ] Configure log forwarding: OpenCanary → rsyslog → AMA → LAW
- [ ] Validate `HoneypotEvents_CL` table is receiving data
- [ ] Build "Any Honeypot Interaction" NRT rule in Sentinel

**Week 2**
- [ ] Deploy fake file server honeypot + embed canary tokens
- [ ] Deploy OpenCanary fake DB server theme
- [ ] Add `Honeypot_Assets` watchlist entries for all live honeypots
- [ ] Build honeypot dashboard workbook in Sentinel
- [ ] Configure SOAR playbook for auto IP-enrichment on honeypot hits
- [ ] Brief Threat Intel and Mini SOC teams on log format

**Week 3+**
- [ ] Deploy fake admin jump box
- [ ] Distribute canary tokens throughout the range environment
- [ ] Establish honeypot health monitoring (alert if no logs for 1hr)
- [ ] Publish the first Monthly Honeypot Activity Report

<br/>

---
<br/>

# Part III — AI-Agentic SOAR Workflow — Deep Dive

## 1. SOAR Architecture Principles

Before any automation is built, four rules are established as law.

**Principle 1 — Enrich first, act second.**
Never automate a containment action without first enriching the alert. Automation without
context causes more damage than it prevents.

**Principle 2 — Human-in-the-loop for containment, until Week 8+.**

| Action | Status |
|---|---|
| Auto-enrich | Yes, from Day 1 |
| Auto-close | Yes, for known-safe patterns after 2 weeks of validation |
| Auto-isolate host | No, until alert fidelity is validated for 4+ weeks |
| Auto-block IP | Yes, for honeypot-sourced IPs — zero false-positive risk |

**Principle 3 — Every playbook has a manual override.**
Every automated action must be reversible by a T2 analyst in under 2 minutes.

**Principle 4 — Log every automation action.**
Every action a playbook takes is written back to Sentinel as a comment on the incident, so
analysts can reconstruct exactly what automation did and why.

---

## 2. The Three Automation Tiers

<div align="center">
<img width="1021" height="1541" alt="automation-tiers" src="https://github.com/user-attachments/assets/85570475-6e18-44cf-ac4d-9865c0fe7045" />
</div>

---

## 3. Full SOAR Architecture

<div align="center">
<img width="1024" height="1536" alt="soar-pipeline" src="https://github.com/user-attachments/assets/489b1c26-7915-4ccf-a19d-7b7ebcae3ac0" />
</div>

---

## 4. Logic App Playbooks — Build Order

*(Reference: [Sentinel Playbook Documentation](https://learn.microsoft.com/en-us/azure/sentinel/automation/create-playbooks?tabs=defender-portal%2Cconsumption))*

### Playbook 1: IP Enrichment *(Build This First)*

**Trigger:** new Sentinel incident

**Actions:**
1. Parse incident entities for IP addresses
2. For each IP — call VirusTotal API for detection count, call IPinfo.io for country/ASN/org, query MISP for IOC library match
3. Compose an enrichment summary string
4. Add a comment to the Sentinel incident via API
5. If VirusTotal detections exceed 5, change incident severity to High

**APIs needed:** VirusTotal (free tier, 500 req/day, or paid) · IPinfo.io (free tier, 50k req/mo) · MISP (self-hosted, free)

### Playbook 2: User Context Enrichment

**Trigger:** new incident with a user entity

**Actions:**
1. Call Azure AD Graph API for department, manager, job title, MFA status, account creation date, and last successful sign-in
2. Call MDE API for the device associated with the user — risk score, active alerts
3. Check the `VIP_Accounts` watchlist — if matched, escalate severity and page T2 immediately
4. Add a comment to the incident with all context

### Playbook 3: Honeypot Response Automation

**Trigger:** `HoneypotEvents_CL` rule fires

**Actions:**
1. Run IP Enrichment (Playbook 1)
2. Add the IP to MISP as a new IOC
3. Update the `IOC_Blocklist` Sentinel watchlist
4. Call the Azure Firewall API to block the IP at the network edge
5. Post to the Threat Intel team channel with IP, service, geo, ASN, and block status
6. Create an enriched Sentinel incident with full context

> **Note:** this is the one place where auto-block is safe from Day 1 — any IP hitting a
> honeypot has zero legitimate reason to be there.

### Playbook 4: MDE Host Isolation *(Week 4+)*

**Trigger:** critical-severity incident with specific rule tags — ransomware, confirmed C2
beacon, credential theft

**Actions:**
1. Get the device ID from the MDE entity in the incident
2. Confirm the device is *not* on the exclusion list (servers, critical assets)
3. POST to the MDE API to isolate the machine
4. Log the isolation action with a timestamp to the incident comment
5. Page the IR team to review and confirm or release
6. Create a follow-up task — an analyst must confirm within 30 minutes

```text
POST https://api.securitycenter.microsoft.com/api/machines/{id}/isolate
Body: {"Comment": "Isolated by SOAR - Incident [ID]", "IsolationType": "Full"}
```

### Playbook 5: AI-Generated Analyst Brief *(The AI-Agentic Layer)*

**Trigger:** Medium/High incident, after enrichment is complete

**Actions:**
1. Gather all enrichment data from incident comments
2. Pull related alerts from the last 7 days for the same entities
3. Call the AI-agentic model with a structured prompt

```text
"You are a SOC analyst. Here is a security incident:
Alert: [alert name]
Source IP: [IP] | Reputation: [VT result] | Geo: [country]
User: [name] | Risk: [score] | MFA: [status]
Device: [hostname] | Risk score: [score]
Related alerts (7d): [list]

Provide:
1. One paragraph executive summary (non-technical)
2. Likely attack scenario (2-3 sentences)
3. Immediate recommended actions (numbered list, max 5)
4. MITRE ATT&CK technique mapping
5. Confidence: Low/Medium/High with reasoning"
```

4. Post the AI brief as a Sentinel incident comment
5. Assign to the correct analyst queue based on the AI confidence score

---

## 5. AI Agentic Decision Model — Confidence Scoring

The AI-agentic layer outputs a structured confidence score, not free text, so it can drive
routing decisions directly.

```json
{
  "incident_id": "12345",
  "ai_risk_score": 78,
  "confidence": "High",
  "likely_technique": "T1078 - Valid Accounts",
  "attack_stage": "Initial Access",
  "recommended_tier": "T2",
  "immediate_actions": [
    "Reset user password immediately",
    "Review all sign-ins from source IP in last 30 days",
    "Check for lateral movement from affected device"
  ],
  "auto_actions_taken": [
    "IP added to MISP IOC library",
    "User manager notified via email"
  ],
  "requires_human_decision": true,
  "reasoning": "User account accessed from known-malicious IP during off-hours. MFA was bypassed. Device risk score elevated. High confidence this is account compromise, not false positive."
}
```

---

## 6. The Full Integrated Loop

<div align="center">
<img width="1024" height="1536" alt="full-integrated-loop" src="https://github.com/user-attachments/assets/62d0b10c-e7c8-449d-b18e-0f08d72eabae" />
</div>

---

## 7. SOAR Build Checklist

**Week 1–2 (Enrich Only)**
- [ ] Create Logic App: IP Enrichment playbook
- [ ] Connect VirusTotal API (free API key)
- [ ] Connect IPinfo.io API
- [ ] Configure the Sentinel incident trigger
- [ ] Test: create a test incident, verify the enrichment comment appears
- [ ] Create Logic App: User Context playbook (Azure AD Graph API)

**Week 3 (Triage Assist)**
- [ ] Build scoring logic in the Logic App (weighted conditions)
- [ ] Configure severity escalation rules
- [ ] Build the honeypot auto-block playbook (safe to deploy)
- [ ] Connect the MISP API for IOC lookups and writes
- [ ] Set up team notification channel (Teams/Slack webhook)
- [ ] Build the "SOAR Action Log" workbook in Sentinel

**Week 4–6 (AI-Agentic Layer)**
- [ ] Build the AI-agentic brief playbook
- [ ] Define the structured prompt template
- [ ] Test AI output quality against 20 real incidents
- [ ] Iterate on the prompt until analyst feedback is positive
- [ ] Integrate the AI confidence score into routing logic

**Week 7–8 (Controlled Response)**
- [ ] Define approved auto-response rules, with team sign-off
- [ ] Build the MDE isolation playbook with an exclusion-list check
- [ ] Deploy with an approval gate first — a human confirms before action executes
- [ ] Run for 2 weeks with human approval required
- [ ] Remove the approval gate only after zero false actions in a 2-week window

**Ongoing**
- [ ] Monthly playbook review — what fired, what helped, what caused problems
- [ ] Track time saved per analyst per shift by automation
- [ ] Add new enrichment sources as the Threat Intel team identifies them

<br/>

---

<div align="center">

*Every layer of this architecture — signal, detection, automation, and response —*
*was built to be provably safe before it was made.*

</div>
