\# Audit Model



Every action taken by the toolkit is recorded. This document describes what is captured and how it can be reviewed.



\## Audit artifacts



| File | Contents | Written by |

|------|----------|------------|

| `output/RemediationAudit.log` | Raw append-only event log | Executor, re-validator |

| `output/audit-<timestamp>/audit-log.csv` | Structured CSV parsed from the raw log | Bundle exporter |

| `output/audit-<timestamp>/audit-report.html` | Printable HTML summary | Bundle exporter |

| `output/audit-<timestamp>/bundle-manifest.txt` | Contents + metadata | Bundle exporter |

| `output/ScheduledRun.log` | Unattended run log with structured summary blocks | Scheduled wrapper |



\## Audit event format



Each line in `RemediationAudit.log` follows:



```

\[timestamp] | MODE | ACTION | principal=<id> | role=<name> | result=<result> \[| detail=<detail>]

```



\### Mode values



\- `DRYRUN` - simulated, no tenant change

\- `LIVE` - actually applied to the tenant

\- `REVALIDATE` - re-validation summary



\### Result values



\- `SIMULATED` - dry-run only

\- `ELIGIBLE\_CREATED` - eligible PIM assignment created

\- `PERMANENT\_REMOVED` - permanent assignment removed

\- `BLOCKED\_LAST\_GA` - safety guard blocked the removal

\- `FAILED` / `FAILED\_ELIGIBLE\_CREATE` / `FAILED\_PERMANENT\_REMOVE` - operation errors

\- `NO\_PERMANENT\_FOUND` - target had no permanent assignment

\- `UNSUPPORTED` - action not implemented



\## Safety guarantees



1\. \*\*No live change\*\* without both `-Apply` and `-Confirm`.

2\. \*\*Last-GA guard\*\*: refuses to remove the last permanent Global Administrator.

3\. \*\*Full audit trail\*\*: every action is logged, whether simulated or applied.

4\. \*\*Read-only scheduled runs\*\*: the scheduled wrapper never applies remediation.



\## Review process



1\. Open the latest `audit-report.html` in a browser.

2\. Check the "Audit Results Breakdown" table for `BLOCKED\_LAST\_GA` or `FAILED` results.

3\. Export the CSV for offline analysis (Excel, Splunk, etc.).

4\. Compare `RemediationPlan.md` (recommended) against `ReValidationReport.md` (outcome) to verify closure.

