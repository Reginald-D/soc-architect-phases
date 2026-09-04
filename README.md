# SOC Phases 1-6

This repository documents the full build of an enterprise Security Operations Center, architected from the ground up inside a live cyber range — not a static lab with sample data, but an environment where real attacker behavior drives every design decision.

The build progresses across six deliberate phases, each one hardening the SOC a layer further: from foundational architecture and detection engineering, through threat intelligence and automation, to full operational maturity and long-term resilience. Nothing here was built out of order. Every phase exists because the one before it made it necessary.

What follows is the record of that build — decision by decision, phase by phase.

| Date       | Phase | GitHub | Description |
|-----------|-----------------|------------|------------|
| 2026 | Big Picture Vision | [Link](https://github.com/Reginald-D/soc-architect-phases/blob/main/Big%20Picture/big-picture-vision.md) | This is a well-structured roadmap — six teams, five phases, roughly 150 deliverables, built around a live cyber range. |
| 2026 | Phase 1 - Azure Sentinel Architecture | [Link](https://github.com/Reginald-D/soc-architect-phases/blob/main/Phase%201%20-%20Azure%20Sentinel%20Architecture/azure-sentinel-architecture.md) | Log Analytics design · Honeypot network engineering · AI-agentic SOAR |
| 2026 | Phase 2 - Detection Engineering | [Link](https://github.com/Reginald-D/soc-architect-phases/blob/main/Phase%202%20-%20Detection%20Engineering/kql-query-library.md) | Version-controlled detection logic · Honeypot instrumentation · MISP threat intel integration |
| 2026 | Phase 3 - MITRE ATT&CK Coverage Mapping | [Link](https://github.com/Reginald-D/soc-architect-phases/blob/main/Phase%203%20-%20MITRE%20ATT%26CK%20Coverage%20Mapping/mitre-attack-coverage-mapping.md) | Coverage baselining · Priority-driven detection engineering · CI/CD for Sentinel rules |
| 2026 | Phase 4 - Analyst IR | [Link](https://github.com/Reginald-D/soc-architect-phases/blob/main/Phase%204%20-%20Analyst%20IR/analyst-shift-operations-workflow.md) | Shift workflow and SLAs · Incident response playbooks · Purple team exercise framework |
| 2026 | Phase 5 - SOC Metrics | [Link](https://github.com/Reginald-D/soc-architect-phases/blob/main/Phase%205%20-%20SOC%20Metrics/soc-metrics-kpi-framework.md) | KPI framework and reporting · 14-day analyst onboarding · Eight-dimension 24/7 readiness assessment |
| 2026 | Phase 6 - SOC Budget | [Link](https://github.com/Reginald-D/soc-architect-phases/blob/main/Phase%206%20-%20SOC%20Budget/soc-budget-resource-planning.md) | Three-year budget model · ROI justification · NIST CSF 2.0 and CIS Controls v8 mapping |
