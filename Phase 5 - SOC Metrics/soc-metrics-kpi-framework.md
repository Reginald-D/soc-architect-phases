<div align="center">

# SOC METRICS, ANALYST ONBOARDING & 24/7 READINESS
### Phase V — Measuring, Staffing, and Maturing the SOC

*KPI framework and reporting · 14-day analyst onboarding · Eight-dimension 24/7 readiness assessment*

![Metrics](https://img.shields.io/badge/Framework-KPI%20%26%20Metrics-0078D4?style=flat-square)
![Onboarding](https://img.shields.io/badge/Program-Analyst%20Onboarding-2ea44f?style=flat-square)
![Readiness](https://img.shields.io/badge/Assessment-24%2F7%20Readiness-D7263D?style=flat-square)
![Status](https://img.shields.io/badge/Status-Phase%205-5C2D91?style=flat-square)

</div>

<br/>

> *A SOC that can't measure itself can't improve itself, a SOC that can't onboard an*
> *analyst in two weeks can't scale, and a SOC that hasn't scored its own readiness is*
> *guessing about whether it can actually run at 3 a.m. This is the layer that turns a*
> *well-built SOC into a durable one.*

<br/>

---

## Contents

**Part I — SOC Metrics & KPI Framework**
[Metrics Philosophy](#1-metrics-philosophy--measure-what-matters) · [The KPI Framework](#2-the-complete-kpi-framework) · [KQL Metric Queries](#3-kql-queries--pull-every-metric-from-sentinel) · [Dashboard Workbook](#4-soc-metrics-dashboard--workbook-structure) · [Monthly Report Template](#5-monthly-soc-report-template)

**Part II — Analyst Onboarding Program**
[Onboarding Philosophy](#1-onboarding-philosophy) · [Day-by-Day Schedule](#2-day-by-day-onboarding-schedule) · [Certification Checklist](#3-analyst-certification-checklist) · [Development Path](#4-analyst-development-path)

**Part III — 24/7 Operational Readiness Assessment**
[What Readiness Means](#1-what-247-readiness-actually-means) · [Full Scorecard](#2-the-readiness-assessment--full-scorecard) · [Score Interpretation](#3-readiness-score-interpretation) · [Gap Remediation](#4-gap-remediation-roadmap) · [Transition Plan](#5-the-247-transition-plan--phase-5-of-the-roadmap) · [Overnight Considerations](#6-overnight-shift-special-considerations)

---
<br/>

# Part I — SOC Metrics & KPI Framework

## 1. Metrics Philosophy — Measure What Matters

Most SOCs measure the wrong things. Ticket counts and closure rates look good on
dashboards but say nothing about whether the team is actually getting better at stopping
attackers. Every metric tracked here is built around three questions.

<div align="center">
<img src="images/metrics-philosophy.png" alt="Three metrics questions — Are we detecting faster, mapped to detection metrics; Are we responding better, mapped to response metrics; and Are we improving over time, mapped to program health metrics" width="640"/>
</div>

Every metric tracked must answer one of those three questions. If it doesn't, it gets cut.

---

## 2. The Complete KPI Framework

**Tier 1 — Operational Metrics (Measured Daily)**

<div align="center">
<img src="images/kpi-tier1-operational.png" alt="Tier 1 daily operational metrics — MTTD target under 15 minutes, MTTA under 5 minutes, MTTR under 4 hours for High and 1 hour for Critical, MTTC under 2 hours for High and 30 minutes for Critical, stable alert volume, false positive rate under 20 percent, and escalation rate between 10 and 20 percent" width="640"/>
</div>

**Tier 2 — Detection Quality Metrics (Measured Weekly)**

<div align="center">
<img src="images/kpi-tier2-detection-quality.png" alt="Tier 2 weekly detection quality metrics — detection coverage targeting 40 percent by Phase 3 and 60 percent by Phase 5, purple team detection rate above 80 percent per exercise, rule efficacy above 70 percent, a downward-trending detection backlog, tracked honeypot hit rate, and IOC feed quality above 5 percent hit rate" width="640"/>
</div>

**Tier 3 — Program Health Metrics (Measured Monthly)**

<div align="center">
<img src="images/kpi-tier3-program-health.png" alt="Tier 3 monthly program health metrics — analyst throughput trending up, SLA compliance above 95 percent, automation coverage above 80 percent, analyst dwell time under 20 minutes for T1 and 60 minutes for T2, playbook coverage above 85 percent by Phase 4, documentation currency above 90 percent, and analyst retention above 80 percent" width="640"/>
</div>

---

## 3. KQL Queries — Pull Every Metric from Sentinel

```kql
// METRIC 1: MTTD -- Mean Time to Detect
// Time from first evidence of attack to Sentinel alert creation
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| extend
    FirstEventTime = todatetime(AdditionalData.FirstEventTime),
    AlertCreatedTime = CreatedTime
| extend MTTD_Minutes = datetime_diff('minute', AlertCreatedTime, FirstEventTime)
| where MTTD_Minutes > 0 and MTTD_Minutes < 1440 // Exclude outliers
| summarize
    Avg_MTTD = avg(MTTD_Minutes),
    P50_MTTD = percentile(MTTD_Minutes, 50),
    P90_MTTD = percentile(MTTD_Minutes, 90),
    P99_MTTD = percentile(MTTD_Minutes, 99)
    by bin(TimeGenerated, 7d), Severity
| order by TimeGenerated desc
```

```kql
// METRIC 2: MTTA -- Mean Time to Acknowledge
SecurityIncident
| where TimeGenerated > ago(30d)
| where isnotempty(Owner)
| extend
    CreatedTime = CreatedTime,
    AssignedTime = LastModifiedTime // Proxy for first assignment
| extend MTTA_Minutes = datetime_diff('minute', AssignedTime, CreatedTime)
| where MTTA_Minutes > 0 and MTTA_Minutes < 480
| summarize
    Avg_MTTA = avg(MTTA_Minutes),
    P90_MTTA = percentile(MTTA_Minutes, 90),
    SLABreaches = countif(
        (Severity == "High" and MTTA_Minutes > 15) or
        (Severity == "Medium" and MTTA_Minutes > 30)
    )
    by bin(TimeGenerated, 7d), Severity
```

```kql
// METRIC 3: MTTR -- Mean Time to Respond
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| extend MTTR_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
| where MTTR_Hours >= 0 and MTTR_Hours < 168
| summarize
    Avg_MTTR_Hours = round(avg(MTTR_Hours), 1),
    P50 = round(percentile(MTTR_Hours, 50), 1),
    P90 = round(percentile(MTTR_Hours, 90), 1),
    TotalIncidents = count(),
    SLABreached = countif(
        (Severity == "Critical" and MTTR_Hours > 1) or
        (Severity == "High" and MTTR_Hours > 4) or
        (Severity == "Medium" and MTTR_Hours > 24)
    )
    by bin(TimeGenerated, 7d)
| extend SLAComplianceRate = round((1.0 - (SLABreached * 1.0 / TotalIncidents)) * 100, 1)
```

```kql
// METRIC 4: False Positive Rate Per Rule
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| extend Resolution = tostring(Classification)
| summarize
    TotalFired = count(),
    FalsePositives = countif(Classification == "FalsePositive"),
    TruePositives = countif(Classification == "TruePositive")
    by Title // Title = rule name
| extend FPRate = round((FalsePositives * 100.0) / TotalFired, 1)
| where TotalFired > 5 // Exclude rules with too few data points
| order by FPRate desc
// High FP rate rules go straight to the Detection Engineering tuning backlog
```

```kql
// METRIC 5: Alert Volume Trend
SecurityAlert
| where TimeGenerated > ago(90d)
| summarize
    Total = count(),
    Critical = countif(AlertSeverity == "High"),
    High = countif(AlertSeverity == "Medium"),
    Medium = countif(AlertSeverity == "Low"),
    Low = countif(AlertSeverity == "Informational")
    by bin(TimeGenerated, 7d)
| extend NoisyWeek = iff(Total > (prev(Total) * 1.5), "Yes", "No")
| render timechart
```

```kql
// METRIC 6: Analyst Performance by Shift
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| extend AnalystName = tostring(Owner.assignedTo)
| where isnotempty(AnalystName)
| summarize
    IncidentsClosed = count(),
    AvgResolutionHours = round(avg(datetime_diff('hour', ClosedTime, CreatedTime)), 1),
    TruePositives = countif(Classification == "TruePositive"),
    FalsePositives = countif(Classification == "FalsePositive"),
    Escalations = countif(Severity in ("High", "Critical"))
    by AnalystName, bin(TimeGenerated, 7d)
| extend AccuracyRate = round((TruePositives * 100.0) / (TruePositives + FalsePositives), 1)
| order by TimeGenerated desc, IncidentsClosed desc
```

---

## 4. SOC Metrics Dashboard — Workbook Structure

Built as a Sentinel Workbook — seven sections, one page each.

**Tab 1: Executive Summary** — current-month MTTD/MTTA/MTTR versus last month; SLA
compliance gauge (green/yellow/red); incidents by severity this month; detection coverage
percentage in a single large number.

**Tab 2: Detection Performance** — alert volume trend (90-day line chart); false-positive
rate by rule, sorted worst to best; top 10 firing rules this month; silent rules — deployed
but zero hits in 30 days.

**Tab 3: Response Performance** — MTTR trend by severity (90-day line chart); SLA breach
heatmap by day of week versus hour; incident age distribution; T1→T2 escalation rate
trend.

**Tab 4: Analyst Metrics** — incidents per analyst per week; average dwell time per alert
by analyst; accuracy rate (true positive vs. false positive decisions) by analyst — used
for coaching, never for punishment.

**Tab 5: Threat Intel Health** — new IOCs added per week from MISP; IOC hit rate by feed
source; honeypot activity trend; MITRE techniques observed in the range as an ATT&CK
heatmap.

**Tab 6: Automation Health** — percentage of alerts receiving SOAR enrichment; playbook
execution success rate; auto-close rate and its false-positive rate; the SOAR action log.

**Tab 7: Program Improvement** — detection backlog size trend; new rules deployed this
month; rules retired or deprecated; purple team scores from the last three exercises;
ATT&CK coverage trend over time.

---

## 5. Monthly SOC Report Template

**SOC Monthly Report — [Month Year]**
`Prepared by: SOC Architect | Distribution: Leadership + Team Leads`

**Executive Summary**

This month the SOC processed [N] alerts, identified [N] true positive incidents, and
maintained [N]% SLA compliance. Detection coverage improved from [N]% to [N]% of MITRE
ATT&CK techniques. Two significant detections were made via honeypot intelligence. No
critical incidents required after-hours escalation.

**Key Metrics — This Month vs. Last Month**

<div align="center">
<img src="images/monthly-report-key-metrics.png" alt="Monthly SOC report metrics comparison showing MTTD improving from 18 to 12 minutes, MTTA from 6 to 4 minutes, MTTR High from 4.8 to 3.2 hours, false positive rate dropping from 24 to 18 percent, SLA compliance rising from 91 to 96 percent, and ATT&CK coverage rising from 31 to 38 percent, alongside an alert volume increase flagged for attention" width="560"/>
</div>

**Significant Incidents**

`INC-0089:` Kerberoasting attempt against the `svc-backup` account. Detected in 2 minutes.
Contained in 18 minutes. Confirmed external attacker using honeypot credentials. No
lateral movement. Attacker IP added to MISP.

**Detection Improvements**

Rules added: 4 new rules (T1550.002, T1055, T1087, T1482). Rules tuned: 3 rules had their
false-positive rate reduced. Rules retired: 1 deprecated, replaced by an improved version.

**Next Month Priorities**
1. Reduce the alert volume spike — investigate the noisy rule
2. Purple team exercise targeting C2 and exfiltration techniques
3. Onboard 2 new T1 analysts (Phase 3 ramp-up)
4. Deploy the MTTR dashboard for shift leads

<br/>

---
<br/>

# Part II — Analyst Onboarding Program

## 1. Onboarding Philosophy

**Goal:** a new analyst is fully operational within 14 days — not just tool access, but
actually capable of handling a real shift independently.

**Approach:** Week 1 — observe and learn (shadow, read, lab work). Week 2 — do with
supervision (handle real alerts with a buddy). Week 3 — independent with check-ins (solo
shift, T2 available). Week 4 — full integration, no different from any other analyst.

---

## 2. Day-by-Day Onboarding Schedule

### Week 1 — Orient and Absorb

**Day 1 — Welcome and Access**

*Morning:* meet the team — every team lead, not just SOC. Access provisioning walkthrough:
Azure AD account and MFA setup, Sentinel Reader role, MDE read-only access, MISP read-only
access, GitHub repo access (pull only), and team communication channels. Receive the
onboarding kit: SOC Operations Manual, Analyst Quick Reference Card, tool access guide,
and escalation contact list.

*Afternoon:* environment tour — the cyber range explained, what machines exist and what
roles they play, where the honeypots are and what they do, how data flows from the range
into Sentinel. Read the Detection Engineering rule naming convention. Complete the Azure
fundamentals self-paced course (2 hours).

**Day 2 — Tools Deep Dive**

Sentinel walkthrough guided by a T2 buddy: incident queue navigation, how to open and work
an incident, entity explorer, investigation graph, running KQL queries. MDE walkthrough:
device inventory, alert queue, timeline view on a device, a Live Response demo (observe
only). Hands-on lab: investigate 5 closed historical incidents, reading the notes and
identifying which KQL query answered the key question.

**Day 3 — Detection Knowledge**

Read the top 20 detection rules in the library (YAML files in GitHub) and understand what
each detects and why. Read the top 10 MITRE ATT&CK techniques for the environment.
Complete the ATT&CK Navigator exercise — pull up the coverage layer, identify 3 blind
spots, and explain why they matter. Quiz: identify the MITRE technique from a sample alert
description.

**Day 4 — Triage Process**

Read the full triage checklist walkthrough and all IR playbooks (PB-IR-001 through
current). Tabletop: walk through PB-IR-001 (Ransomware) verbally, with the Exercise Lead
playing the scenario. Hands-on: triage 10 historical alerts using the decision tree,
documenting each decision and why, with T2 buddy review and feedback.

**Day 5 — Threat Intel and Honeypots**

MISP walkthrough: how to search for an IOC, how events are structured, how to read
confidence and TLP levels. Honeypot dashboard review: what's been hitting the honeypots
this week, how a hit flows into a Sentinel incident. Shift observation: sit with an
experienced analyst for a full shift, watching every decision and noting questions. End of
week check-in with the onboarding lead.

### Week 2 — Supervised Doing

**Day 6–7 — Buddy System**

Handle real alerts with a T2 buddy watching — the buddy does not intervene unless the
analyst is about to make a consequential mistake. Debrief after each alert (5 minutes):
what was decided, why, and what the buddy would have done differently. Minimum of 20
alerts handled with a buddy by end of Day 7.

**Day 8 — KQL Fundamentals**

KQL training lab (2 hours): basic operators (`where`, `project`, `summarize`, `extend`),
time filtering (`ago()`, `between()`), joining tables (`join`, `union`), string operations
(`contains`, `has`, `startswith`). Exercise: write 5 KQL queries from scratch — an entity
timeline for a given IP, all failed logins for a user in 24 hours, top 10 processes by
machine in the last hour, hosts that communicated with a specific IP, and all new service
installs in the last 7 days. T2 buddy reviews and grades each query.

**Day 9 — Incident Documentation**

Standards review: what information is required in a good incident note, tone and format,
what goes in a closed incident versus an escalation. Exercise: rewrite 3 deliberately
poorly documented historical incidents. Shift handoff exercise: receive a real handoff
document, prepare one for a fictional shift, and have the Shift Lead review it.

**Day 10 — First Solo Triage Block**

Handle a 2-hour alert queue solo, with the T2 buddy available on call but not co-located.
Full debrief afterward — every decision reviewed, any escalation decisions evaluated.
Final sign-off quiz: a 10-question written scenario test, requiring an 80%+ score to
proceed to solo shifts, with additional targeted training for any gaps.

### Week 3+ — Independent Operation

**Day 11–14 — Independent Shifts**

Full solo shifts with T2 on-call but not co-located. Shift Lead checks in at shift start
and end. Daily 15-minute debrief with the onboarding lead. Any escalated incident gets a
full post-debrief.

**Week 4 — Full Integration**

No different from any other T1 analyst. Monthly 1-on-1 with the shift lead for the first 3
months, with a development goal assigned from the metrics dashboard (for example, "your
MTTA is above average — let's work on that").

---

## 3. Analyst Certification Checklist

Signed off before any analyst handles a shift solo.

**Analyst Readiness Certification**
`Analyst Name: __________  Start Date: __________`
`Evaluator: __________  Cert Date: __________`

**Tools Competency**
- [ ] Can navigate the Sentinel incident queue and work an incident
- [ ] Can run the KQL entity timeline query from memory
- [ ] Can use the MDE device timeline to trace process execution
- [ ] Can search MISP for an IOC and interpret the result
- [ ] Can read the ATT&CK Navigator coverage layer

**Process Competency**
- [ ] Can execute the full shift start checklist in under 15 minutes
- [ ] Can complete the tool health check and escalate failures
- [ ] Can triage a Medium severity alert in under 20 minutes
- [ ] Correctly applies false-positive criteria (scored on 10 historical alerts)
- [ ] Knows exactly when to escalate versus resolve independently
- [ ] Can write a complete, accurate shift handoff document

**Knowledge Competency**
- [ ] Can name the top 10 techniques observed in the range
- [ ] Can identify the correct playbook for ransomware, ATO, and lateral movement
- [ ] Understands what each honeypot theme is designed to catch
- [ ] Understands SOAR enrichment — what runs automatically and what it produces
- [ ] Can explain the severity matrix and SLA windows from memory

**Scenario pass (80%+ required):** Score `_____ / 10`

**Sign-off:** T2 Buddy `__________` Date `__________` · Shift Lead `__________` Date
`__________` · SOC Architect `__________` Date `__________`

**Status:** ☐ Certified — ready for solo shifts · ☐ Not yet — additional training required in `__________`

---

## 4. Analyst Development Path

Growth continues after onboarding — stagnation means turnover.

| Stage | Goal | Metrics Tracked | Learning | Milestone |
|---|---|---|---|---|
| **Month 1–3: T1 Analyst** | Handle the full alert queue independently, under 20% FP rate | MTTA, FP rate, escalation accuracy | KQL library, all playbooks, 1 purple team exercise | — |
| **Month 4–6: Senior T1** | Mentor new T1 analysts, begin writing hunting queries | Above, plus coaching quality | Detection Engineering fundamentals, MITRE deep-dives | Write and deploy 1 detection rule through the pipeline |
| **Month 7–12: T2 Candidate** | Handle escalations independently, run tabletop exercises | MTTR on escalated incidents, playbook accuracy | Full IR methodology, MISP event creation, purple team execution | Lead 1 purple team exercise start to finish |
| **Month 12+: T2 Analyst** | Complex incident ownership, cross-team coordination | Incident closure quality, playbook improvement rate | Detection-as-Code, Sentinel rule authoring, threat modeling | Author and deploy 5+ production detection rules |

<br/>

---
<br/>

# Part III — 24/7 Operational Readiness Assessment

## 1. What 24/7 Readiness Actually Means

Most SOCs think 24/7 readiness means "do we have enough people?" Real readiness answers
eight questions.

<div align="center">
<img src="images/readiness-eight-questions.png" alt="Eight 24/7 readiness questions — Coverage: can three shifts be staffed with no single points of failure; Automation: can the SOC function overnight with minimal human load; Tooling: are all tools stable enough to run unattended for eight hours; Escalation: what happens if something critical occurs at 3am; Documentation: can a T1 analyst handle any alert without help; Resilience: what is the backup if Sentinel goes down overnight; Knowledge: is knowledge distributed or held by one person; Process: are processes defined enough for overnight execution without the architect available" width="640"/>
</div>

---

## 2. The Readiness Assessment — Full Scorecard

Run this assessment quarterly. Each item is scored 1–5.

<div align="center">
<img src="images/readiness-dim1-staffing.png" alt="Dimension 1, Staffing Readiness scorecard — minimum three certified T1 analysts per shift slot, T2 on-call for every shift, no analyst working more than two consecutive shifts, weekend coverage plan, backup coverage for absences, designated shift lead, and a current escalation contact list, scored out of 35" width="560"/>
</div>

<div align="center">
<img src="images/readiness-dim2-automation.png" alt="Dimension 2, Automation Readiness scorecard — SOAR enrichment on 90 percent-plus of alerts, playbook failure rate under 2 percent, validated auto-close rate, AI agentic brief attached before analyst review, error-free honeypot auto-IOC pipeline, MISP to Sentinel sync on schedule, and accurate alert routing, scored out of 35" width="560"/>
</div>

<div align="center">
<img src="images/readiness-dim3-tooling.png" alt="Dimension 3, Tooling Stability scorecard — Sentinel uptime above 99.5 percent over 90 days, no MDE connector gaps in 30 days, continuous honeypot logging, tested automated health check alerts, a tested tool failure playbook, a backup alerting channel, and a documented log retention policy, scored out of 35" width="560"/>
</div>

<div align="center">
<img src="images/readiness-dim4-escalation.png" alt="Dimension 4, Escalation Readiness scorecard — a posted escalation matrix, tested T2 on-call response under 15 minutes, documented emergency-contact criteria, a tested major incident communication plan, a documented tool-failure escalation path, configured after-hours critical alert paging, and current external escalation contacts, scored out of 35" width="560"/>
</div>

<div align="center">
<img src="images/readiness-dim5-documentation.png" alt="Dimension 5, Documentation Readiness scorecard — a complete shift start checklist, authored and annotated detection rules, a playbook for every alert type with more than five hits monthly, a SOC Operations Manual reviewed in the last 60 days, an onboarding guide that produces a certified analyst in 14 days, a current false-positive list, and monthly validated watchlists, scored out of 35" width="560"/>
</div>

<div align="center">
<img src="images/readiness-dim6-resilience.png" alt="Dimension 6, Resilience Readiness scorecard — a Sentinel failure playbook tested in the last 90 days, an MDE fallback detection method, network isolation possible without Sentinel, a backup communication channel, tested MISP backup and restore, a configured Azure budget alert, and tested disaster recovery for SOC tooling, scored out of 35" width="560"/>
</div>

<div align="center">
<img src="images/readiness-dim7-knowledge.png" alt="Dimension 7, Knowledge Distribution scorecard — no single person holding undocumented critical knowledge, two-plus admin analysts per tool, every playbook executed by more than one analyst, purple team knowledge not held by one person, Detection Engineering resilient to a single absence, fully documented threat intel feed management, and analyst onboarding that does not require the original creator, scored out of 35" width="560"/>
</div>

<div align="center">
<img src="images/readiness-dim8-process.png" alt="Dimension 8, Process Maturity scorecard — consistently high shift handoff quality, SLA compliance above 95 percent for 30 days, an alert queue that never backs up more than two hours, post-incident reviews within 72 hours, change management followed for all tools, weekly metrics review by shift leads, and purple team exercises run on cadence, scored out of 35" width="560"/>
</div>

---

## 3. Readiness Score Interpretation

<div align="center">
<img src="images/readiness-score-interpretation.png" alt="Readiness score interpretation out of a total possible 280 points — 0 to 140 (50 percent) is Not Ready with significant gaps to fix before any 24/7 discussion, 141 to 196 (70 percent) is Approaching Readiness with a 90-day plan to close gaps, 197 to 238 (85 percent) is Operational Ready for 24/7 with known risk areas documented, and 239 to 280 (95 percent) is Fully Ready as a mature 24/7 SOC capable of sustained operations" width="640"/>
</div>

---

## 4. Gap Remediation Roadmap

When the assessment reveals gaps, remediation follows priority order.

**Priority 1 — Blocking Gaps (fix before any 24/7 operation)**
- Any Escalation item scoring below 3/5
- Any Staffing item scoring below 3/5
- Sentinel health monitoring not in place
- No playbook for Critical severity alerts

**Priority 2 — High Risk (fix within 30 days)**
- Automation failure rate above 5%
- Single-person knowledge dependencies identified
- Post-incident reviews not happening
- Tool disaster recovery untested

**Priority 3 — Improvement (fix within 90 days)**
- Documentation currency below 90%
- False-positive rate above target
- Onboarding taking longer than 14 days to certification
- SLA compliance below 95%

---

## 5. The 24/7 Transition Plan — Phase 5 of the Roadmap

<div align="center">
<img src="images/road-to-247-gates.png" alt="Road to 24/7 with eight milestone gates — readiness score above 85 percent across all dimensions, minimum nine certified analysts, all critical playbooks tested by two or more analysts, SOAR enrichment above 90 percent for 30 straight days, SLA compliance above 95 percent for 60 consecutive days, zero tool health gaps in 30 days, overnight shift staffed and trained, and a passed overnight tabletop exercise — followed by a transition sequence running overnight shadow mode in weeks 1-2, low-severity-only handling in weeks 3-4, full alerts with T2 on-call in weeks 5-6, and full 24/7 operation from week 7 onward" width="700"/>
</div>

---

## 6. Overnight Shift Special Considerations

The overnight shift is the hardest — five challenges are addressed specifically.

**Challenge 1: Fatigue.** Solution: an 8-hour hard cap, no back-to-back overnight shifts.
Metric: track alert acknowledgment times — degradation is a fatigue signal.

**Challenge 2: Lower Alert Volume (a false sense of safety).** Solution: the overnight
shift must run proactive hunting queries. Mandatory hunting tasks per shift: run the
beaconing hunt query against the last 8 hours, review honeypot hits since the last shift,
check for silent rules indicating data ingestion gaps, and review MISP for new
high-confidence IOCs from feeds.

**Challenge 3: Harder Escalations.** Solution: T2 on-call paging must be tested and
responsive. Escalation rule: if a Critical alert fires at 3 a.m. and T2 doesn't respond
within 15 minutes, escalate to the next tier immediately, no waiting.

**Challenge 4: Knowledge Gaps on Complex Incidents.** Solution: overnight T1 should never
hold a complex investigation alone. If it can't be resolved in 30 minutes, document
everything, preserve evidence, and hand it to the incoming morning shift with full
context — better to hand off cleanly than guess wrong at 2 a.m.

**Challenge 5: Tool Failures Overnight.** Tool failure protocol when Infrastructure isn't
online: document exactly what broke and when, activate the backup alerting method, notify
Infrastructure via PagerDuty or on-call page, log all alerts manually until the tool is
restored, and have the morning shift review any coverage gaps from the failure window.

<br/>

---

## The Complete SOC Blueprint — Everything Built

<div align="center">
<img src="images/soc-fully-designed-blueprint.png" alt="The fully designed SOC as eight connected layers — Intelligence via MISP, honeypots, and external feeds; Detection via a 200-plus rule MITRE-mapped KQL library deployed through Detection-as-Code; Monitoring via Sentinel, MDE, and Azure Defender with SOAR enrichment under 90 seconds; Operations via shift workflow and T1/T2/Lead structure with SLAs; Response via the IR playbook library and MDE/AAD/Firewall containment; Improvement via monthly-to-biweekly purple team exercises and ATT&CK coverage gap reports; Measurement via the full tiered KPI framework and monthly leadership reporting; People via 14-day onboarding to certification and a T1-to-T2 development path; and Readiness via the eight-dimension 24/7 assessment and gate-based transition to round-the-clock operations" width="640"/>
</div>

<br/>

<div align="center">

*A detection nobody measures is a guess about whether it's working. A team nobody*
*certifies is a guess about whether it's ready. This is the layer that removes the*
*guessing.*

</div>
