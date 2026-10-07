\# End-to-End Workflow



This document walks through the full lifecycle of an identity risk assessment using the toolkit.



\## Overview



```

&#x20;  +-----------+     +--------+     +-----------+     +-------------+     +--------+     +-------+

&#x20;  | Discover  | --> | Assess | --> | Prioritize| --> | Simulate    | --> | Remediate| --> | Audit |

&#x20;  +-----------+     +--------+     +-----------+     +-------------+     +--------+     +-------+

```



\## Step 1 - Discover



Run the assessment pipeline against your Entra tenant:



```powershell

.\\scripts\\Invoke-EntraRiskAssessment.ps1

```



Produces:

\- `output/PIMEligibilityReport.json`

\- `output/PermanentRoleReport.json`

\- `output/RiskScoreReport.json`



\## Step 2 - Snapshot baseline



Before making any changes, freeze the current state:



```powershell

Copy-Item .\\output\\RiskScoreReport.json .\\output\\RiskScoreReport.baseline.json -Force

```



This is what re-validation will diff against later.



\## Step 3 - Review the plan



Generate a human-readable runbook:



```powershell

.\\scripts\\Remediation\\New-EntraRemediationPlan.ps1

```



Open `output/RemediationPlan.md` and review the prioritized list.



\## Step 4 - Generate scenarios automatically



Rather than hand-crafting scenario files, let the toolkit derive them from

the current risk report:



```powershell

.\\scripts\\Remediation\\New-AutoRemediationScenarios.ps1 -MinTier Medium

```



This writes one scenario file per principal at or above the chosen tier

into `scenarios/generated/`. Each scenario contains the recommended

changes for that principal, derived entirely from the live findings.



\## Step 5 - Simulate (What-If)



Before touching the tenant, test the impact in dry form. Point at any

generated scenario:



```powershell

.\\scripts\\RiskEngine\\Invoke-WhatIfSimulation.ps1 -ScenarioPath .\\scenarios\\generated\\<file>.scenario.json

```



Compare before/after scores to decide if the change is safe.



\## Step 6 - Remediate (guarded)



Dry-run by default:



```powershell

.\\scripts\\Remediation\\Invoke-EntraRemediation.ps1 -ScenarioPath .\\scenarios\\generated\\<file>.scenario.json

```



Apply with explicit confirmation:



```powershell

.\\scripts\\Remediation\\Invoke-EntraRemediation.ps1 -ScenarioPath .\\scenarios\\generated\\<file>.scenario.json -Apply -Confirm

```



All actions are written to `output/RemediationAudit.log`.



\## Step 7 - Re-validate



Re-scan the tenant and diff against the baseline:



```powershell

.\\scripts\\Invoke-EntraRiskAssessment.ps1

.\\scripts\\Remediation\\Compare-EntraRemediationOutcome.ps1

```



Review `output/ReValidationReport.md`.



\## Step 8 - Audit



Bundle everything into a timestamped package:



```powershell

.\\scripts\\Remediation\\Export-EntraAuditBundle.ps1

```



Open `output/audit-\*/audit-report.html` in a browser.



\## Scheduled runs



For unattended execution (Azure Automation / Task Scheduler):



```powershell

.\\scripts\\Invoke-ScheduledAssessment.ps1 -NonInteractive

```



This runs discovery + plan + bundle, never remediation. Run log at

`output/ScheduledRun.log`.

