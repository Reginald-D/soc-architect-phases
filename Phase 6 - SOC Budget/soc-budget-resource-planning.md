<div align="center">

# SOC BUDGET, RESOURCE PLANNING & COMPLIANCE FRAMEWORK
### Phase VI — Funding, Justifying, and Auditing the SOC

*Three-year budget model · ROI justification · NIST CSF 2.0 and CIS Controls v8 mapping*

![Budget](https://img.shields.io/badge/Model-3--Year%20Budget-0078D4?style=flat-square)
![ROI](https://img.shields.io/badge/Justification-ROI%20Model-2ea44f?style=flat-square)
![Compliance](https://img.shields.io/badge/Framework-NIST%20CSF%202.0-5C2D91?style=flat-square)
![Controls](https://img.shields.io/badge/Controls-CIS%20v8-D7263D?style=flat-square)
![Status](https://img.shields.io/badge/Status-Phase%206-2b2b2b?style=flat-square)

</div>

<br/>

> *A SOC that can't be funded doesn't get built, and a SOC that can't be audited doesn't*
> *get trusted. This is the layer that turns everything in the previous six phases into a*
> *budget leadership will approve and a control set an auditor will sign off on.*

<br/>

---

## Contents

**Part I — SOC Budget & Resource Planning Model**
[Budget Philosophy](#1-budget-framework-philosophy) · [Three-Year Budget](#2-full-budget-model--three-year-view) · [Cost Optimization](#3-cost-optimization-strategies) · [ROI Justification](#4-roi-justification-model) · [Cost Dashboard](#5-budget-tracking--sentinel-cost-dashboard)

**Part II — Compliance & Audit Framework**
[Compliance Landscape](#1-compliance-landscape-for-the-soc) · [NIST CSF 2.0 Mapping](#2-nist-csf-20-mapping--the-soc-against-the-framework) · [CIS Controls v8](#3-cis-controls-v8--implementation-status) · [Audit Evidence Library](#4-audit-evidence-library--what-any-audit-needs) · [Internal Audit Process](#5-internal-audit-process--run-this-quarterly) · [Compliance KQL Queries](#6-key-compliance-kql-queries)

---
<br/>

# Part I — SOC Budget & Resource Planning Model

## 1. Budget Framework Philosophy

<div align="center">
<img src="images/budget-framework-philosophy.png" alt="Budget framework philosophy — the most common budgeting mistake is buying tools first and figuring out staffing later, resulting in expensive shelfware and burned-out analysts; the correct approach is the 40/40/20 rule, allocating 40 percent to people, 40 percent to technology, and 20 percent to operations, because tools without skilled operators are just noise generators" width="500"/>
</div>

---

## 2. Full Budget Model — Three-Year View

<div align="center">
<img src="images/budget-year1-build-phase.png" alt="Year 1 build phase budget covering roadmap phases 1-3, totaling 555,370 dollars across people at 410,000 including a SOC Architect, one T2 analyst, four part-time T1 analysts, and shared threat intel and detection engineering resources; technology at 107,700 covering Sentinel, MDE, Azure infrastructure, Thinkst Canary, Tenable, and free open-source tools; training and certifications at 19,500; and operations at 18,170 including a 10 percent contingency" width="640"/>
</div>

<div align="center">
<img src="images/budget-year2-expand-phase.png" alt="Year 2 expand phase budget covering roadmap phases 3-4, totaling 1,270,200 dollars, a 129 percent increase over Year 1, with people costs at 1,025,000 as analysts move to full-time and headcount grows to two T2 and six T1 analysts, technology at 186,200 reflecting expanded range and MDE licensing, and training and certifications at 31,000 for SANS-level certs" width="640"/>
</div>

<div align="center">
<img src="images/budget-year3-sustain-phase.png" alt="Year 3 sustain phase budget covering roadmap phase 5 full 24/7 operations, totaling 2,360,000 dollars, with people costs at 2,065,000 across three shifts including nine T1 analysts, three T2 analysts, and three shift leads, technology at 225,000 for the mature stack, training at 40,000, and operations at 30,000, bringing the three-year total investment to approximately 4,185,570 dollars" width="640"/>
</div>

---

## 3. Cost Optimization Strategies

**Strategy 1 — Commitment tiers for Sentinel.** Move from Pay-As-You-Go to a 100GB/day
commitment tier once daily ingest volume is understood. Savings: 15–25% versus PAYG on the
same volume.

**Strategy 2 — Use free tools where enterprise tools are overkill.**

| Substitution | Savings |
|---|---|
| MISP instead of ThreatConnect | $40,000/year |
| OpenCanary instead of all-Thinkst | $10,000/year |
| GitHub Actions instead of Jenkins | $8,000/year |
| ATT&CK Navigator instead of custom-built | $15,000/year |
| **Total open-source savings** | **~$73,000/year** |

**Strategy 3 — Azure Reserved Instances.** For SOC Ops VMs running 24/7, switching to
1-year reserved pricing saves 30–40% versus on-demand for always-on compute.

**Strategy 4 — Basic Logs tier for verbose tables.** DNS logs and raw network flows moved
to the Basic tier in Sentinel instead of Analytics — same data, roughly 80% cheaper.
Estimated savings: $8,000–15,000/year depending on volume.

**Strategy 5 — Intern/part-time model for T1 (Phase 1–2).** The roadmap already accounts
for this — part-time T1 analysts during Phase 1–2 reduce Year 1 people costs by roughly
40%, transitioning to full-time employees at Year 2 as the program matures.

---

## 4. ROI Justification Model

Leadership will ask: **"Why should we spend this money?"** The answer, ready in advance:

**Cost of a breach — what this prevents.** From the IBM Cost of a Data Breach Report
(2025 averages): the average cost of a data breach is $4,880,000; average dwell time
without a SOC is 207 days versus 28 days with a mature SOC; a dedicated IR team reduces the
cost of a breach by roughly $1,500,000.

**The SOC ROI calculation.** Year 1 investment: $555,370. A single breach prevented, even
partially, is worth $2,000,000+. Year 1 ROI if one breach is prevented: 360%.

**Ongoing value beyond breach prevention:** regulatory fine avoidance (HIPAA penalties run
up to $1.9M per incident); cyber insurance premium reduction of 15–30% with a mature SOC;
a competitive differentiator — SOC capability as a selling point; and a training ground
that produces certified security talent.

**Measurable risk reduction:** detection coverage moves from 0% to 40%+ in Year 1; MTTD
moves from unknown to under 15 minutes; attack dwell time moves from potentially months
down to hours.

---

## 5. Budget Tracking — Sentinel Cost Dashboard

```kql
// Monthly Sentinel ingestion cost tracker
// Run this at month end to track against budget
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize
    TotalGB = sum(Quantity) / 1024,
    EstimatedCost = sum(Quantity) / 1024 * 2.76 // $2.76/GB PAYG rate
    by DataType, bin(TimeGenerated, 1d)
| summarize
    MonthlyGB = sum(TotalGB),
    MonthlyCost = sum(EstimatedCost)
    by DataType
| order by MonthlyCost desc
// Top tables by cost = first candidates for Basic Logs tier evaluation
```

<br/>

---
<br/>

# Part II — Compliance & Audit Framework

## 1. Compliance Landscape for the SOC

The cyber range SOC aligns with these frameworks — not because a regulator is watching
today, but because building compliant from the start costs a fraction of retrofitting it
later.

<div align="center">
<img src="images/compliance-landscape.png" alt="Compliance framework landscape — NIST CSF 2.0 as the architecture language every CISO speaks, mapping directly to the six teams and five phases; NIST SP 800-61 as the IR standard playbooks should cite; MITRE ATT&CK as the detection coverage language already embedded; SOC 2 Type II required for client-facing operation with documented controls and an audit trail; ISO 27001 as the international standard driving documentation discipline the roadmap already requires; and CIS Controls v8 as a practical checklist mapping directly to tooling decisions" width="700"/>
</div>

---

## 2. NIST CSF 2.0 Mapping — The SOC Against the Framework

<div align="center">
<img src="images/nist-csf-mapping.png" alt="NIST CSF 2.0 function mapping — Govern covers the SOC charter, policies, RBAC model, risk register, budget model, and leadership reporting; Identify covers asset inventory, Tenable vulnerability management, risk assessment, and ATT&CK coverage gap analysis; Protect covers MDE endpoint protection, Azure AD Conditional Access and MFA, network segmentation, and analyst RBAC; Detect covers Microsoft Sentinel, the KQL detection rule library, the honeypot network, and MISP threat intelligence; Respond covers the IR playbook library, shift operations workflow, SOAR automation, and the major incident communication plan; Recover covers Azure VM snapshots and backup procedures, the disaster recovery plan, post-incident review process, and lessons-learned documentation" width="560"/>
</div>

---

## 3. CIS Controls v8 — Implementation Status

| CIS Control | Evidence Artifact |
|---|---|
| **1 — Asset Inventory** | Tool inventory doc (Phase 1), MDE device list |
| **2 — Software Asset Management** | MDE software inventory |
| **3 — Data Protection** | Sentinel retention policy doc, RBAC model |
| **4 — Secure Configuration** | Infrastructure security hardening doc |
| **5 — Account Management** | Azure AD RBAC doc, Sentinel role assignments |
| **6 — Access Control Management** | Conditional Access policies, MFA enforcement |
| **7 — Continuous Vulnerability Management** | Tenable scan reports |
| **8 — Audit Log Management** | Sentinel LAW retention policy, DCR config |
| **9 — Email and Web Browser Protections** | MDE web content filtering on analyst machines |
| **10 — Malware Defenses** | MDE AV/EDR on all SOC machines |
| **13 — Network Monitoring and Defense** | NSG flow logs, DNS logs in Sentinel, honeypot network |
| **16 — Application Software Security** | Detection-as-Code pipeline (peer review gate) |
| **17 — Incident Response Management** | IR Playbook library, shift operations workflow |
| **18 — Penetration Testing** | Purple team exercise framework and scorecards |

---

## 4. Audit Evidence Library — What Any Audit Needs

This folder structure is the complete audit trail.

```text
SOC-AUDIT-EVIDENCE/
│
├── 01_GOVERNANCE/
│   ├── SOC_Charter.pdf                    ← Mission, scope, authority
│   ├── RACI_Matrix.pdf                    ← Who owns what
│   ├── Data_Classification_Policy.pdf
│   ├── Acceptable_Use_Policy.pdf
│   └── SOC_Risk_Register.xlsx
│
├── 02_ACCESS_CONTROL/
│   ├── RBAC_Model.pdf                     ← Sentinel role assignments
│   ├── Access_Review_Log.xlsx             ← Quarterly access reviews
│   ├── Privileged_Account_Register.pdf
│   └── MFA_Enforcement_Screenshots/
│
├── 03_CHANGE_MANAGEMENT/
│   ├── Change_Log.xlsx                    ← All tool config changes
│   ├── GitHub_PR_History/                 ← Detection rule changes
│   └── Detection_Rule_Deployment_Log.csv
│
├── 04_INCIDENT_RESPONSE/
│   ├── IR_Playbook_Library/               ← All PB-IR-XXX docs
│   ├── Incident_Register.xlsx             ← All closed incidents
│   ├── Post_Incident_Reviews/             ← PIR for significant incidents
│   └── Tabletop_Exercise_Reports/
│
├── 05_MONITORING/
│   ├── Sentinel_Connector_Health_Logs/    ← Monthly health checks
│   ├── ATT&CK_Coverage_Reports/           ← Monthly gap reports
│   ├── Alert_Volume_Reports/              ← Monthly trend reports
│   └── SOAR_Execution_Logs/
│
├── 06_VULNERABILITY_MANAGEMENT/
│   ├── Tenable_Scan_Reports/               ← Quarterly scans
│   └── Remediation_Tracking.xlsx
│
├── 07_TRAINING_AND_AWARENESS/
│   ├── Analyst_Certification_Records/      ← Signed-off cert checklists
│   ├── Training_Completion_Log.xlsx
│   └── Purple_Team_Scorecards/
│
└── 08_METRICS_AND_REPORTING/
    ├── Monthly_SOC_Reports/
    ├── KPI_Dashboard_Exports/
    └── SLA_Compliance_Reports/
```

---

## 5. Internal Audit Process — Run This Quarterly

**Access Control Review (Week 1 of quarter)**
- [ ] Export all Sentinel role assignments and compare to the approved list
- [ ] Identify any access not matching current role assignments
- [ ] Review service account usage — any accounts inactive over 60 days?
- [ ] Confirm MFA is enforced for every analyst account
- [ ] Document findings in `Access_Review_Log.xlsx`

**Detection Effectiveness Review (Week 2)**
- [ ] Run the false-positive rate query for the last 90 days
- [ ] Rules with an FP rate above 30% go to the tuning backlog
- [ ] Rules with zero hits in 90 days require investigation
- [ ] Calculate and document the new ATT&CK coverage percentage
- [ ] Schedule a purple team exercise if none has run this quarter

**Process Compliance Review (Week 3)**
- [ ] Sample 10 closed incidents and review documentation quality
- [ ] Sample 5 shift handoffs and review completeness
- [ ] Verify post-incident reviews were completed for all High/Critical incidents
- [ ] Check the SLA compliance rate against the 95% target
- [ ] Verify playbooks were updated after any incident that exposed a gap

**Tool Health Review (Week 4)**
- [ ] Review Sentinel connector health for the 90-day period
- [ ] Identify any data gaps — hours with zero events indicate a potential blind spot
- [ ] Confirm MISP feed health — are all feeds updating on schedule?
- [ ] Review honeypot activity — are all honeypots actively logging?
- [ ] Review Azure cost against budget for any surprises

**Audit Report (End of quarter)**
- [ ] Document all findings with severity (Critical/High/Medium/Low)
- [ ] Assign a remediation owner and deadline for each finding
- [ ] Share results with leadership in the Monthly SOC Report
- [ ] Track open findings to closure in the risk register

---

## 6. Key Compliance KQL Queries

```kql
// Audit 1 -- SOC privileged configuration changes
AuditLogs
| where TimeGenerated > ago(90d)
| where Category in ("Policy", "RoleManagement")
| where OperationName has_any (
    "Add member to role", "Remove member from role",
    "Update policy", "Add analytics rule", "Delete analytics rule"
)
| project TimeGenerated, OperationName,
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    TargetResource = tostring(TargetResources[0].displayName)
| order by TimeGenerated desc
```

```kql
// Audit 2 -- Retention compliance
union SecurityEvent, AADSignInLogs, DeviceEvents
| summarize Earliest = min(TimeGenerated), Latest = max(TimeGenerated), Total = count() by Type
| extend
    RetentionDays = datetime_diff("day", Latest, Earliest),
    Status = iff(RetentionDays >= 90, "Compliant", "Gap")
| project Type, Earliest, Latest, RetentionDays, Total, Status
```

```kql
// Audit 3 -- Closed incident documentation completeness
SecurityIncident
| where TimeGenerated > ago(90d) and Status == "Closed"
| summarize
    Total = count(),
    MissingClassification = countif(isempty(Classification)),
    MissingComment = countif(isempty(Comments)),
    MissingOwner = countif(isempty(Owner))
| extend DocumentationScore = round((Total - MissingClassification - MissingComment) * 100.0 / Total, 1)
```

<br/>

---

## Everything Built — The Complete SOC Enterprise Blueprint

<div align="center">
<img src="images/complete-blueprint-session-index.png" alt="Complete eight-session build index — Session 1 Azure Sentinel Architecture, Session 2 Honeypot Network Design, Session 3 AI Agentic SOAR Workflow, Session 4 KQL Detection Library and MISP Platform, Session 5 MITRE ATT&CK Coverage Mapping and Detection-as-Code Pipeline, Session 6 Analyst Shift Operations, IR Playbook Library, and Purple Team Exercise Framework, Session 7 SOC Metrics and KPI Framework, Analyst Onboarding, and 24/7 Operational Readiness, and Session 8 Budget and Resource Planning Model, Compliance and Audit Framework, and Leadership Presentation — totaling a complete enterprise-grade SOC built from the ground up, every team, every phase, every deliverable" width="640"/>
</div>

<br/>

<div align="center">

*A detection library nobody can fund never gets deployed, and a SOC nobody can audit*
*never gets trusted. This document is what turns a technically sound build into one*
*leadership can approve and an auditor can verify.*

</div>
