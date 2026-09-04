# SOC Phases 1-6

This repository documents the full build of an enterprise Security Operations Center, architected from the ground up inside a live cyber range — not a static lab with sample data, but an environment where real attacker behavior drives every design decision.

The build progresses across six deliberate phases, each one hardening the SOC a layer further: from foundational architecture and detection engineering, through threat intelligence and automation, to full operational maturity and long-term resilience. Nothing here was built out of order. Every phase exists because the one before it made it necessary.

What follows is the record of that build — decision by decision, phase by phase.

| Date       | Phase | GitHub | Description |
|-----------|-----------------|------------|------------|
| 2026 | Big Picture Vision | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-213010-remediation) | Configures the kernel parameter to restrict access to kernel message logs |
| 11/4/2025 | RHEL-09-213060 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-213060-remediation) | Disables the SCTP kernel module to minimize potential attack vectors |
| 11/4/2025 | RHEL-09-231055 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-231055-remediation) | Prevents code execution on user home directories by enabling the "noexec" mount option |
| 11/4/2025 | RHEL-09-611090 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-611090-remediation) | Ensures minlen=15 in pwquality configs for RHEL 9 compliance |
| 11/4/2025 | RHEL-09-611105 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-611105-remediation) | Ensures RHEL 9 prevents the use of dictionary words for passwords |
| 11/4/2025 | RHEL-09-611110 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-611110-remediation) | Enforce password complexity by strengthening defense against brute-force guessing attacks |
| 11/4/2025 | RHEL-09-651025 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-651025-remediation) | Configures AIDE to enforce cryptographic integrity verification for RHEL 9 audit tools |
| 11/4/2025 | RHEL-09-654115 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-654115-remediation) | Ensures RHEL 9 audits all uses of the pam_timestamp_check command |
| 11/4/2025 | RHEL-09-654120 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-654120-remediation) | audit all uses of the passwd command, ensuring traceability |
| 11/4/2025 | RHEL-09-654135 | [Link](https://github.com/Reginald-D/rhel9-stig-remediation-bash-scripts/blob/main/RHEL-09-654135-remediation) | Configures RHEL 9 to audit all uses of the ssh-agent command |
