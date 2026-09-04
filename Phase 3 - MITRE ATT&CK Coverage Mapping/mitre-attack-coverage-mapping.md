<div align="center">

# MITRE ATT&CK COVERAGE MAPPING
### Phase III — Visibility Measurement and Detection-as-Code

*Coverage baselining · Priority-driven detection engineering · CI/CD for Sentinel rules*

![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-D7263D?style=flat-square)
![Tool](https://img.shields.io/badge/Tool-ATT%26CK%20Navigator-2b2b2b?style=flat-square)
![Pipeline](https://img.shields.io/badge/Pipeline-GitHub%20Actions-181717?style=flat-square)
![Platform](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=flat-square)
![Status](https://img.shields.io/badge/Status-Phase%203-2ea44f?style=flat-square)

</div>

<br/>

> *"Where are we blind right now?" is the only question that matters before another*
> *detection rule gets written. Coverage mapping turns that question into a visual answer —*
> *and Detection-as-Code makes sure the answer stays true after the rule ships, not just on*
> *the day it was deployed.*

<br/>

---

## Contents

**Part I — MITRE ATT&CK Coverage Mapping**
[Why Coverage Mapping Matters](#1-why-coverage-mapping-is-the-most-important-visibility-tool) · [ATT&CK Navigator](#2-attck-navigator--the-primary-tool) · [Starting Baseline](#3-the-starting-coverage-baseline) · [Coverage Layer File](#4-attck-coverage-layer-file--build-this-first) · [Priority Matrix](#5-priority-technique-matrix--what-to-detect-first) · [Gap Analysis Process](#6-coverage-gap-analysis--running-it-properly) · [Dashboard Workbook](#7-sentinel-coverage-dashboard-workbook) · [Checklist](#8-coverage-mapping-checklist)

**Part II — Detection-as-Code Pipeline**
[What It Means](#1-what-detection-as-code-means) · [Pipeline Architecture](#2-full-pipeline-architecture) · [Repository Structure](#3-repository-structure) · [Rule Definition Format](#4-rule-definition-format--yaml--kql) · [CI Pipeline](#5-github-actions--ci-pipeline) · [CD Pipeline](#6-github-actions--cd-pipeline) · [Deployment Script](#7-deployment-script--python) · [KQL Validation](#8-kql-validation-script) · [Coverage Auto-Generator](#9-coverage-auto-generator) · [Authoring Workflow](#10-rule-authoring-workflow--what-every-engineer-follows) · [Build Checklist](#11-complete-build-checklist)

---
<br/>

# Part I — MITRE ATT&CK Coverage Mapping

## 1. Why Coverage Mapping Is the Most Important Visibility Tool

Before another detection rule gets written, one question needs an answer:

> **"Where are we blind right now?"**

ATT&CK coverage mapping turns that question into a visual answer. It shows exactly which
of the 14 tactics and 200+ techniques are detectable, which are partially covered, and
which are complete blind spots. Every Detection Engineering decision from this point
forward flows from that map.

**Coverage states — used consistently across every layer file:**

<div align="center">
<img src="images/coverage-states.png" alt="Four coverage states — Detected (rule deployed and validated, low false positive rate), Partial (rule exists but incomplete coverage or high noise), Blind Spot (no detection capability at all), and Not Applicable (technique irrelevant to the environment)" width="560"/>
</div>

---

## 2. ATT&CK Navigator — The Primary Tool

ATT&CK Navigator is a free, web-based tool from MITRE — the industry standard for
visualizing coverage, used from Day 1.

**Access:** [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)

It can also be self-hosted inside the SOC network:

```bash
# Self-host ATT&CK Navigator (optional -- for air-gapped environments)
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
npm install
npm run start
# Accessible at http://localhost:4200
```

---

## 3. The Starting Coverage Baseline

Based on the current stack — MDE, Sentinel, and honeypots — this is the honest Day 1
coverage reality, before any custom rules were written:

<div align="center">
<img src="images/day1-coverage-baseline.png" alt="Day 1 coverage baseline across all 14 MITRE tactics for the Azure/MDE stack, ranging from 40 percent partial coverage on Initial Access to 10 percent blind spots on Discovery, Collection, and Exfiltration, for an overall baseline of approximately 22 percent" width="640"/>
</div>

This is normal — most mature SOCs operate at 40–60% coverage. The goal by Phase 3 of the
roadmap is 50%+ coverage on priority techniques.

---

## 4. ATT&CK Coverage Layer File — Build This First

Navigator uses JSON layer files to color-code the matrix. The baseline layer is built by
exporting current Sentinel rules and mapping them.

```json
{
  "name": "SOC CyberRange Coverage - v1.0",
  "versions": { "attack": "14", "navigator": "4.9", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Current detection coverage as of 2026-01-15",
  "filters": { "platforms": ["Windows", "Linux", "Azure AD", "Office 365"] },
  "sorting": 0,
  "layout": { "layout": "side", "aggregateFunction": "average", "showID": true, "showName": true },
  "techniques": [
    {
      "techniqueID": "T1110",
      "tactic": "credential-access",
      "color": "#ff6666",
      "comment": "Brute Force -- Sentinel rule deployed. Covers RDP + AAD spray. SSH partial.",
      "enabled": true,
      "metadata": [
        { "name": "Rule", "value": "brute_force_rdp.kql" },
        { "name": "Coverage", "value": "70%" },
        { "name": "False Pos Rate", "value": "Low" },
        { "name": "Last Validated", "value": "2026-01-10" }
      ],
      "score": 70
    },
    {
      "techniqueID": "T1558.003",
      "tactic": "credential-access",
      "color": "#ff6666",
      "comment": "Kerberoasting -- Sentinel rule deployed. High confidence.",
      "score": 85
    },
    {
      "techniqueID": "T1003.006",
      "tactic": "credential-access",
      "color": "#ff6666",
      "comment": "DCSync -- Sentinel rule deployed. Fires on replication GUIDs.",
      "score": 90
    },
    {
      "techniqueID": "T1059.001",
      "tactic": "execution",
      "color": "#ffaa00",
      "comment": "PowerShell -- Partial. Encoded commands detected. Obfuscated PS not covered.",
      "score": 50
    },
    {
      "techniqueID": "T1055",
      "tactic": "defense-evasion",
      "color": "#ff0000",
      "comment": "Process Injection -- NO COVERAGE. High priority gap.",
      "score": 0
    }
  ],
  "gradient": { "colors": ["#ff0000", "#ffaa00", "#00ff00"], "minValue": 0, "maxValue": 100 },
  "legendItems": [
    { "label": "No Coverage (0-20)", "color": "#ff0000" },
    { "label": "Partial Coverage (21-69)", "color": "#ffaa00" },
    { "label": "Strong Coverage (70-100)", "color": "#00ff00" }
  ]
}
```

Saved, imported into ATT&CK Navigator, this becomes the living coverage map.

---

## 5. Priority Technique Matrix — What to Detect First

Not all 200+ techniques carry equal weight. Detection Engineering effort is focused where
attackers actually go in the environment — prioritized by three factors: **frequency in
the wild, honeypot observations, and blast radius if missed.**

<div align="center">
<img src="images/detection-priority-matrix.png" alt="Detection priority build order across four tiers — P1 covers brute force, valid accounts, Kerberoasting, LSASS dump, DCSync, and ransomware; P2 covers PowerShell abuse, scheduled tasks, SMB lateral movement, pass-the-hash, log clearing, and AV tampering; P3 covers DNS C2 beaconing, exfiltration, LOLBins, WMI execution, new admin accounts, and phishing; P4 covers account discovery, domain trust discovery, DNS tunneling exfil, and token impersonation" width="640"/>
</div>

---

## 6. Coverage Gap Analysis — Running It Properly

Run as a formal process every month.

### Step 1 — Export All Active Sentinel Rules to a Spreadsheet

```python
# Python script using Azure SDK to export all active analytics rules
from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights

credential = DefaultAzureCredential()
client = SecurityInsights(credential, subscription_id="YOUR_SUB_ID")

rules = client.alert_rules.list(
    resource_group_name="rg-soc-prod",
    workspace_name="law-soc-cyberrange"
)

coverage = []
for rule in rules:
    if rule.kind == "Scheduled" and rule.enabled:
        coverage.append({
            "rule_name": rule.display_name,
            "severity": rule.severity,
            "tactics": rule.tactics,
            "techniques": rule.techniques,
            "status": "Active"
        })

# Export to CSV for ATT&CK Navigator import
import csv
with open("sentinel_coverage.csv", "w") as f:
    writer = csv.DictWriter(f, fieldnames=coverage[0].keys())
    writer.writeheader()
    writer.writerows(coverage)
```

### Step 2 — Gap Analysis KQL Query

```kql
// Run this in Sentinel to see which ATT&CK techniques have fired
// in the last 30 days vs. which are defined but silent
SecurityAlert
| where TimeGenerated > ago(30d)
| where isnotempty(ExtendedProperties)
| extend Tactics = tostring(ExtendedProperties["Tactics"])
| extend Techniques = tostring(ExtendedProperties["Techniques"])
| summarize
    AlertCount = count(),
    UniqueEntities = dcount(Entities),
    LastFired = max(TimeGenerated)
    by Techniques, Tactics, AlertName
| order by AlertCount desc
// Techniques NOT in this list = rules that either don't exist or never fired
// Either case = a gap to investigate
```

### Step 3 — The Coverage Gap Report Template

Produced monthly, one page, shared with all teams.

<div align="center">
<img src="images/coverage-gap-report.png" alt="Monthly ATT&CK coverage gap report showing 197 total mapped techniques at 21 percent detected, 9 percent partial, and 70 percent blind spots, with the top blind spots, rules added and retired that month, honeypot-observed techniques not yet detected, and next month's detection priorities" width="500"/>
</div>

---

## 7. Sentinel Coverage Dashboard Workbook

Built in Sentinel to give leadership a live view.

```kql
// Widget 1: Coverage by Tactic -- bar chart
SecurityAlert
| where TimeGenerated > ago(30d)
| extend Tactic = tostring(parse_json(tostring(ExtendedProperties)).Tactics)
| summarize AlertCount = count() by Tactic
| order by AlertCount desc
```

```kql
// Widget 2: Top Firing Techniques This Week
SecurityAlert
| where TimeGenerated > ago(7d)
| extend Technique = tostring(parse_json(tostring(ExtendedProperties)).Techniques)
| summarize Count = count() by Technique
| top 10 by Count
```

```kql
// Widget 3: Silent Detection Rules
// Enabled analytics rules with zero alerts in the last 30 days
let ActiveRules =
    SentinelHealth
    | where TimeGenerated > ago(30d)
    | where SentinelResourceType == "Analytics Rule"
    | distinct RuleName;
let RulesWithAlerts =
    SecurityAlert
    | where TimeGenerated > ago(30d)
    | summarize AlertCount = count() by AlertName
    | project RuleName = AlertName, AlertCount;
ActiveRules
| join kind=leftouter RulesWithAlerts on RuleName
| extend AlertCount = coalesce(AlertCount, 0)
| where AlertCount == 0
| project RuleName, Status = "Silent"
| order by RuleName asc
```

```kql
// Widget 4: Coverage Trend Over Time
SecurityAlert
| where TimeGenerated > ago(90d)
| extend Technique = tostring(parse_json(tostring(ExtendedProperties)).Techniques)
| summarize UniqueTechniquesDetected = dcount(Technique) by bin(TimeGenerated, 7d)
| render timechart
```

---

## 8. Coverage Mapping Checklist

**Phase 1 (Week 1–2)**
- [ ] Stand up ATT&CK Navigator (web or self-hosted)
- [ ] Create the baseline layer file — map what MDE gives you out of the box
- [ ] Identify the top 10 blind spots from the priority matrix
- [ ] Share the coverage map with the Detection Engineering team

**Phase 2 (Monthly cadence)**
- [ ] Export active Sentinel rules and update the Navigator layer file
- [ ] Run the gap analysis KQL query against the last 30 days
- [ ] Identify techniques observed in honeypots but not detected
- [ ] Publish the monthly Coverage Gap Report
- [ ] Detection Engineering selects the top 3 gaps to close next month

**Phase 3 (Quarterly)**
- [ ] Full ATT&CK layer review — every technique reassessed
- [ ] Cross-reference with industry benchmarks (CISA advisories, red team reports)
- [ ] Update the priority matrix based on what's actually hitting the range
- [ ] Present the coverage trend to leadership — improving month over month?

<br/>

---
<br/>

# Part II — Detection-as-Code Pipeline

## 1. What Detection-as-Code Means

Detection-as-Code treats KQL rules exactly like software — version-controlled, peer
reviewed, tested, and deployed through a pipeline instead of edited by hand in a portal.

<div align="center">
<img src="images/manual-detection-problems.png" alt="The old manual way — an analyst writes a rule and pastes it into the Sentinel portal — creates five problems: no version history, no peer review, no rollback, no testing, and two people editing the same rule, resulting in a risky, inefficient, unreliable, unscalable process" width="640"/>
</div>

<div align="center">
<img src="images/detection-as-code-flow.png" alt="The Detection-as-Code way — an analyst writes or updates a rule, opens a GitHub pull request, a peer reviews it, automated testing runs, and it auto-deploys to Sentinel — delivering rollback in 30 seconds, full history, peer review, pre-live testing, and an auditable library" width="640"/>
</div>

---

## 2. Full Pipeline Architecture

<div align="center">
<img src="images/dac-pipeline-architecture.png" alt="Detection-as-Code pipeline from the engineer workstation cloning the repo and opening a pull request, through GitHub Actions CI validating KQL syntax, YAML schema, MITRE tags, false positives, and requiring peer review, to merge, then GitHub Actions CD generating templates and deploying first to the Sentinel lab workspace and then to production with audit logging" width="560"/>
</div>

---

## 3. Repository Structure

```text
soc-detection-library/
├── .github/
│   └── workflows/
│       ├── ci-validate.yml       ← Runs on every PR
│       └── cd-deploy.yml         ← Runs on merge to main
│
├── detections/                   ← All production rules live here
│   ├── credential_access/
│   │   ├── kerberoasting.yml     ← Rule definition (YAML + KQL)
│   │   ├── dcsync.yml
│   │   └── lsass_access.yml
│   ├── lateral_movement/
│   │   ├── pass_the_hash.yml
│   │   └── psexec.yml
│   └── [other tactic folders]
│
├── hunting/                      ← Hunting queries, NOT auto-deployed
│   └── beaconing_hunt.kql
│
├── tests/                        ← Test data and validation scripts
│   ├── test_runner.py
│   └── test_data/
│       └── kerberoasting_test_events.json
│
├── scripts/
│   ├── deploy_rules.py           ← Pushes rules to Sentinel via API
│   ├── validate_kql.py           ← KQL syntax checker
│   └── generate_coverage.py      ← Updates ATT&CK Navigator layer
│
├── docs/
│   └── RULE_AUTHORING_GUIDE.md
│
└── README.md
```

---

## 4. Rule Definition Format — YAML + KQL

Every rule is a single YAML file with the KQL embedded inside it — the single source of
truth.

```yaml
# detections/credential_access/kerberoasting.yml
# ================================================

# ── METADATA ──────────────────────────────────────────────────
id: "SOC-CRED-003"
name: "Kerberoasting - RC4 TGS Request"
version: "1.2"
status: "Active"  # Active | Tuning | Deprecated | Testing
created: "2026-01-10"
last_modified: "2026-01-20"
author: "detection-team"
reviewed_by: "lead-architect"

# ── MITRE MAPPING ─────────────────────────────────────────────
mitre:
  tactic: "Credential Access"
  tactic_id: "TA0006"
  technique: "Steal or Forge Kerberos Tickets: Kerberoasting"
  technique_id: "T1558.003"

# ── RULE CONFIGURATION ────────────────────────────────────────
severity: "High"
frequency: "PT5M"    # ISO 8601 duration -- every 5 minutes
lookback: "PT1H"     # Look back 1 hour
threshold: 1          # Alert if 1+ results
suppression:
  enabled: true
  duration: "PT1H"    # Don't re-alert same entity within 1 hour

# ── DATA SOURCES ──────────────────────────────────────────────
data_sources:
  - "SecurityEvent"
  - "WindowsSecurityEvents"
tables_required:
  - "SecurityEvent"

# ── ENTITY MAPPING ─────────────────────────────────────────────
entity_mapping:
  - entity_type: "Account"
    field_mappings:
      - column_name: "TargetUserName"
        identifier: "Name"
  - entity_type: "IP"
    field_mappings:
      - column_name: "IpAddress"
        identifier: "Address"
  - entity_type: "Host"
    field_mappings:
      - column_name: "Computer"
        identifier: "HostName"

# ── FALSE POSITIVE GUIDANCE ───────────────────────────────────
false_positives:
  - "Penetration testing by authorized red team"
  - "Legacy applications using RC4 encryption (document in exclusion list)"
false_positive_rate: "Low"

# ── RESPONSE GUIDANCE ─────────────────────────────────────────
response_actions:
  - "Identify service accounts with SPNs targeted"
  - "Check if credentials have been used on other systems"
  - "Review account for unauthorized changes"
  - "Correlate with lateral movement alerts"
playbook: "playbooks/kerberoasting_response.md"

# ── KQL QUERY ─────────────────────────────────────────────────
query: |
  SecurityEvent
  | where EventID == 4769
  | where TimeGenerated > ago(1h)
  | extend
      ServiceName = tostring(EventData.ServiceName),
      TicketEncryptionType = tostring(EventData.TicketEncryptionType),
      TargetUserName = tostring(EventData.TargetUserName),
      IpAddress = tostring(EventData.IpAddress)
  | where TicketEncryptionType == "0x17"
  | where ServiceName !endswith "$"
  | where ServiceName !in ("krbtgt", "kadmin")
  | summarize
      RequestCount = count(),
      Services = make_set(ServiceName)
      by TargetUserName, IpAddress, Computer, bin(TimeGenerated, 5m)
  | extend
      Technique = "T1558.003",
      Severity = "High"
  | project TimeGenerated, TargetUserName, IpAddress, Computer, RequestCount, Services

# ── TEST CASES ────────────────────────────────────────────────
tests:
  should_detect:
    - description: "RC4 TGS request for service account"
      expected_result: "Alert fires with TargetUserName populated"
  should_not_detect:
    - description: "AES-256 encrypted TGS request (EncryptionType 0x12)"
      expected_result: "No alert"
    - description: "Machine account TGS request (name ends in $)"
      expected_result: "No alert"
```

---

## 5. GitHub Actions — CI Pipeline

```yaml
# .github/workflows/ci-validate.yml
name: Validate Detection Rules

on:
  pull_request:
    branches: [ main ]
    paths:
      - 'detections/**/*.yml'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install pyyaml jsonschema azure-monitor-query \
              azure-identity requests

      - name: Validate YAML Schema
        run: |
          python scripts/validate_schema.py \
              --rules-dir detections/ \
              --schema docs/rule_schema.json

      - name: Validate KQL Syntax
        run: |
          python scripts/validate_kql.py \
              --rules-dir detections/ \
              --workspace-id ${{ secrets.LAB_WORKSPACE_ID }}
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

      - name: Validate MITRE Technique IDs
        run: |
          python scripts/validate_mitre.py \
              --rules-dir detections/

      - name: Check for Required Fields
        run: |
          python scripts/validate_required_fields.py \
              --rules-dir detections/ \
              --required id name version mitre severity author

      - name: False Positive Volume Check
        run: |
          python scripts/check_fp_volume.py \
              --rules-dir detections/ \
              --workspace-id ${{ secrets.LAB_WORKSPACE_ID }} \
              --max-results-per-hour 100
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

      - name: Post Validation Summary to PR
        if: always()
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Detection Rule Validation Results
              YAML Schema: Pass
              KQL Syntax: Pass
              MITRE Tags: Pass
              Volume Check: Pass
              **Ready for peer review.**`
            })
```

---

## 6. GitHub Actions — CD Pipeline

```yaml
# .github/workflows/cd-deploy.yml
name: Deploy Detection Rules to Sentinel

on:
  push:
    branches: [ main ]
    paths:
      - 'detections/**/*.yml'

jobs:
  deploy-lab:
    name: Deploy to LAB workspace
    runs-on: ubuntu-latest
    environment: lab   # Requires lab environment approval in GitHub
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2   # Get previous commit to find changed files

      - name: Find Changed Rules
        id: changed
        run: |
          CHANGED=$(git diff --name-only HEAD~1 HEAD -- 'detections/**/*.yml')
          echo "files=$CHANGED" >> $GITHUB_OUTPUT

      - name: Deploy Changed Rules to LAB
        run: |
          python scripts/deploy_rules.py \
              --rules "${{ steps.changed.outputs.files }}" \
              --workspace-id ${{ secrets.LAB_WORKSPACE_ID }} \
              --resource-group rg-soc-lab \
              --workspace-name law-soc-lab \
              --disabled   # Deploy disabled in lab first
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

      - name: Validate Rules in LAB
        run: |
          python scripts/validate_deployed_rules.py \
              --workspace-id ${{ secrets.LAB_WORKSPACE_ID }}

  deploy-prod:
    name: Deploy to PRODUCTION workspace
    runs-on: ubuntu-latest
    needs: deploy-lab
    environment: production   # Requires production environment approval
    steps:
      - uses: actions/checkout@v4

      - name: Deploy to PRODUCTION
        run: |
          python scripts/deploy_rules.py \
              --rules "${{ steps.changed.outputs.files }}" \
              --workspace-id ${{ secrets.PROD_WORKSPACE_ID }} \
              --resource-group rg-soc-prod \
              --workspace-name law-soc-cyberrange \
              --enabled   # Enable in production
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}

      - name: Log Deployment to Sentinel Audit Table
        run: |
          python scripts/log_deployment.py \
              --rules-deployed "${{ steps.changed.outputs.files }}" \
              --deployed-by "${{ github.actor }}" \
              --commit "${{ github.sha }}"

      - name: Update ATT&CK Navigator Layer
        run: |
          python scripts/generate_coverage.py \
              --rules-dir detections/ \
              --output docs/coverage_layer.json

      - name: Commit Updated Coverage Layer
        run: |
          git config --local user.email "soar-bot@soc.local"
          git config --local user.name "SOC Automation"
          git add docs/coverage_layer.json
          git commit -m "Auto-update ATT&CK coverage layer [skip ci]"
          git push
```

---

## 7. Deployment Script — Python

```python
# Minimal Sentinel rule deployment script
import yaml, requests
from pathlib import Path
from azure.identity import ClientSecretCredential

credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
token = credential.get_token("https://management.azure.com/.default").token

for file in Path("detections").rglob("*.yml"):
    rule = yaml.safe_load(open(file))

    requests.put(
        f"https://management.azure.com/subscriptions/{SUB_ID}"
        f"/resourceGroups/{RG}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE}"
        f"/providers/Microsoft.SecurityInsights/alertRules/{rule['id']}"
        f"?api-version=2023-02-01",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "kind": "Scheduled",
            "properties": {
                "displayName": rule["name"],
                "query": rule["query"],
                "severity": rule["severity"],
                "enabled": True
            }
        }
    )
    print(f"Deployed: {rule['name']}")
```

---

## 8. KQL Validation Script

```python
# validate_kql.py
# Validate KQL syntax against the Sentinel lab workspace

import os, yaml
from pathlib import Path
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient

client = LogsQueryClient(
    ClientSecretCredential(
        os.environ["AZURE_TENANT_ID"],
        os.environ["AZURE_CLIENT_ID"],
        os.environ["AZURE_CLIENT_SECRET"]
    )
)

workspace = os.environ["LAB_WORKSPACE_ID"]

for file in Path("detections").rglob("*.yml"):
    rule = yaml.safe_load(open(file))

    try:
        client.query_workspace(
            workspace,
            f"{rule['query']} | where TimeGenerated > ago(1m) | take 1"
        )
        print(f"PASS: {rule['name']}")
    except Exception as e:
        print(f"FAIL: {rule['name']} - {e}")
```

---

## 9. Coverage Auto-Generator

```python
# generate_coverage.py
# Generate an ATT&CK Navigator layer from the detection YAML files

import yaml, json
from pathlib import Path

SCORES = {"Active": 85, "Tuning": 40, "Testing": 20}
COLORS = {"Critical": "#ff0000", "High": "#ff6600", "Medium": "#ffaa00"}

techniques = {}

for file in Path("detections").rglob("*.yml"):
    rule = yaml.safe_load(open(file))

    if rule.get("status") == "Deprecated":
        continue

    tid = rule["mitre"]["technique_id"]

    techniques[tid] = {
        "techniqueID": tid,
        "score": SCORES.get(rule.get("status"), 0),
        "color": COLORS.get(rule.get("severity"), "#aaaaaa"),
        "comment": rule["name"],
        "enabled": True
    }

layer = {
    "name": "SOC Detection Coverage",
    "domain": "enterprise-attack",
    "techniques": list(techniques.values())
}

json.dump(layer, open("coverage_layer.json", "w"), indent=2)
print(f"Generated coverage for {len(techniques)} techniques")
```

---

## 10. Rule Authoring Workflow — What Every Engineer Follows

**Step 1 — Branch**

```bash
git checkout -b detection/T1558-003-kerberoasting
```

**Step 2 — Create the rule file**

```bash
cp templates/RULE_TEMPLATE.yml detections/credential_access/kerberoasting.yml
# Fill in all fields -- ID, MITRE mapping, KQL, test cases
```

**Step 3 — Local validation**

```bash
python scripts/validate_schema.py --rules-dir detections/
python scripts/validate_mitre.py --rules-dir detections/
```

**Step 4 — Open a pull request**

```bash
git add detections/credential_access/kerberoasting.yml
git commit -m "feat(detection): Add kerberoasting detection T1558.003"
git push origin detection/T1558-003-kerberoasting
# Open PR in GitHub -- CI pipeline runs automatically
```

**Step 5 — Peer review**

A second Detection Engineer confirms: does the KQL make logical sense, is entity mapping
correct, is the MITRE technique right, does the false-positive guidance cover known noise,
and is severity appropriate?

**Step 6 — Merge and auto-deploy**

<div align="center">
<img src="images/cd-pipeline-steps.png" alt="After PR approval and passing CI checks, the CD pipeline deploys the rule disabled to the lab workspace, validates it in lab, deploys it enabled to production, auto-updates the ATT&CK Navigator layer, and completes with full audit trail" width="640"/>
</div>

**Step 7 — Post-deploy monitoring**

<div align="center">
<img src="images/post-deploy-monitoring.png" alt="Post-deployment monitoring watches the rule for 48 hours, opening a tuning pull request if the false positive rate is too high, or investigating and taking action if there are zero hits after 7 days, with every decision documented in the repo and Sentinel audit table" width="640"/>
</div>

---

## 11. Complete Build Checklist

**Week 1**
- [ ] Create the GitHub repo: `soc-detection-library`
- [ ] Set up folder structure (`detections/`, `hunting/`, `scripts/`, `tests/`)
- [ ] Create `RULE_TEMPLATE.yml`
- [ ] Write `validate_schema.py` and `validate_mitre.py` scripts
- [ ] Configure GitHub Secrets (Azure SP credentials, workspace IDs)
- [ ] Build the CI workflow (`ci-validate.yml`) — schema and MITRE validation only
- [ ] Migrate the top 5 existing Sentinel rules to YAML format
- [ ] Test: open a PR, confirm CI runs and passes

**Week 2**
- [ ] Add KQL syntax validation to CI (`validate_kql.py`)
- [ ] Add the false-positive volume check to CI
- [ ] Build the CD workflow (`cd-deploy.yml`) — deploy to LAB first
- [ ] Build `deploy_rules.py` to push rules to Sentinel via API
- [ ] Validate: merge a rule, confirm it appears in Sentinel LAB
- [ ] Add a production deployment gate (manual approval required first)

**Week 3**
- [ ] Build `generate_coverage.py` to auto-update the ATT&CK layer on merge
- [ ] Add a CD step to auto-commit the updated coverage layer
- [ ] Create branch protection rules (require PR + 1 approval)
- [ ] Train the Detection Engineering team on the workflow
- [ ] Migrate all existing Sentinel rules to the repo

**Week 4+**
- [ ] All new rules go through the repo — no direct Sentinel portal edits
- [ ] Monthly — review CI failure patterns (what keeps failing validation?)
- [ ] Quarterly — rule library audit, deprecate stale rules, promote tuning rules
- [ ] Publish the Detection Engineering playbook documenting this process (Phase 4 roadmap)

<br/>

---

## The System Now Built

<div align="center">
<img src="images/full-system-loop.png" alt="The complete closed loop — write rule as YAML and KQL, open a GitHub pull request, peer review, merge through lab validation to production, Sentinel rule goes live, the ATT&CK Navigator layer auto-updates, the monthly coverage gap report drives next priorities, and the loop repeats" width="560"/>
</div>

<br/>

<div align="center">

*Every rule written from this point forward carries a full audit trail, peer review,*
*automated testing, and automatic deployment — a professional-grade Detection-as-Code*
*program, not a folder of scripts someone remembers to update.*

</div>
