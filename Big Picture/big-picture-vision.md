# Big Picture Vision

This is a well-structured roadmap — six teams, five phases, roughly 150 deliverables,
built around a live cyber range. Approached as the incoming SOC Architect, layered on
top of the existing Azure / MDE / AI-agentic stack, the objective is not just standing up
a SOC — it's building a **living training ground**, where real attacks, real detections,
and real analyst workflows create a self-reinforcing loop. The cyber range is the engine.
Everything else is built around making that engine meaningful.

Think of it in three layers:

![Three-layer model — Signal, Detection, and Response](images/three-layer-model.png)

---

## Where to Start — Phase 1 Priorities for the Architect

![Phase 1 priorities — Azure Sentinel baseline, MDE onboarding, SOAR playbook taxonomy, network segmentation, and team leads](images/phase-1-priorities.png)

---

## Tool Recommendations by Function

How the existing stack extends, intentionally:

| Function | Current Stack | Recommended Addition |
|---|---|---|
| **SIEM** | Microsoft Sentinel | Already solid — focus on KQL tuning |
| **EDR / SOAR** | MDE | Add Defender for Identity for lateral movement detection |
| **Honeypot Management** | TBD | OpenCanary (lightweight, free) or Thinkst Canary (commercial, best-in-class) |
| **Threat Intel** | TBD | MISP (free, self-hosted) for IOC management, plus free feeds (AlienVault OTX, Abuse.ch) |
| **Vulnerability Visibility** | TBD | Tenable — already referenced in the roadmap, prioritize it |
| **Detection-as-Code** | — | Sigma rules plus a GitHub repo — rules are version-controlled and portable |
| **AI Agentic Automation** | Already in use | Wire it to Sentinel Logic Apps for auto-enrichment workflows |
| **MITRE Coverage Mapping** | Manual | ATT&CK Navigator (free, web-based) — the Detection team needs this on Day 1 |

---

## The Architecture You're Building Toward

![Target architecture — Honeypot DMZ through Microsoft Sentinel, AI Agentic layer, and SOC analyst workflow](images/target-architecture.png)

---

## Your First 30 Days — Concrete Action Items

**Week 1**
- Stand up the Sentinel workspace, connect MDE, validate data is flowing
- Create the Azure VNet topology (Range / Honeypot / SOC / Lab)
- Deploy the first honeypot (fake domain controller or fake file server)
- Assign team leads to all six roadmap teams

**Week 2**
- Complete the alert inventory (Detection Engineering Phase 1, Deliverable 1) — do this personally if needed, it's foundational
- Set up ATT&CK Navigator and baseline current detection coverage (it will be sparse — that's expected, and that's the point)
- Set up MISP, or at minimum start an IOC spreadsheet, for the Threat Intel team
- Define severity levels and the SOAR auto-close / enrich / contain tiers

**Week 3**
- Run the first tabletop with whoever is on Triage & IR — walk through one realistic scenario manually before playbooks exist
- Establish the GitHub repo for detection rules (Sigma format)
- Publish the integration map — which tools talk to which, even if it's just Sentinel + MDE today

**Month 2 Onward**
- Execute the Phase 2 roadmap across all six teams in parallel
- Shift from builder to coordinator — unblocking teams, reviewing deliverables, enforcing standards

---

## Architect-Level Pitfalls to Avoid

![Architect-level pitfalls — test/lab environment, premature AI automation, honeypot threat intel, and log retention](images/architect-pitfalls.png)
