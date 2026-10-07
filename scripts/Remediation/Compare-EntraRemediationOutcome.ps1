<#
.SYNOPSIS
    Compares a baseline risk score report against a post-remediation one.

.DESCRIPTION
    Loads a baseline RiskScoreReport.json and a current RiskScoreReport.json,
    computes a diff per principal (score delta, tier delta, resolution), and
    writes a Markdown report. Appends a summary line to the audit log.

    This is the "re-validation" step of the toolkit:
        discover -> assess -> remediate -> re-validate -> audit

.PARAMETER BaselinePath
    Path to the baseline score report. Defaults to ./output/RiskScoreReport.baseline.json

.PARAMETER CurrentPath
    Path to the current score report. Defaults to ./output/RiskScoreReport.json

.PARAMETER OutputPath
    Path to write the Markdown diff report. Defaults to ./output/ReValidationReport.md

.PARAMETER AuditLogPath
    Path to append the summary audit line. Defaults to ./output/RemediationAudit.log

.EXAMPLE
    .\Compare-EntraRemediationOutcome.ps1

.NOTES
    Requires no Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$BaselinePath = "./output/RiskScoreReport.baseline.json",
    [string]$CurrentPath  = "./output/RiskScoreReport.json",
    [string]$OutputPath   = "./output/ReValidationReport.md",
    [string]$AuditLogPath = "./output/RemediationAudit.log"
)

# --- Validate inputs ---
if (-not (Test-Path $BaselinePath)) {
    Write-Error "Baseline report not found at $BaselinePath. Snapshot a baseline first."
    return
}
if (-not (Test-Path $CurrentPath)) {
    Write-Error "Current report not found at $CurrentPath. Run the assessment after remediation."
    return
}

Write-Host "[*] Loading baseline and current score reports..." -ForegroundColor Cyan

$baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json
$current  = Get-Content $CurrentPath  -Raw | ConvertFrom-Json
if ($baseline -isnot [array]) { $baseline = @($baseline) }
if ($current  -isnot [array]) { $current  = @($current)  }

# --- Build lookup maps by PrincipalId ---
$baselineMap = @{}
foreach ($p in $baseline) { $baselineMap[$p.PrincipalId] = $p }

$currentMap = @{}
foreach ($p in $current) { $currentMap[$p.PrincipalId] = $p }

# --- Union of principal IDs ---
$allIds = @($baselineMap.Keys + $currentMap.Keys) | Sort-Object -Unique

$tierOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "-" = 4 }

# --- Build diff rows ---
$diffs = foreach ($id in $allIds) {
    $b = $baselineMap[$id]
    $c = $currentMap[$id]

    $beforeScore = if ($b) { [int]$b.Score } else { 0 }
    $afterScore  = if ($c) { [int]$c.Score } else { 0 }
    $beforeTier  = if ($b) { $b.Tier } else { "-" }
    $afterTier   = if ($c) { $c.Tier } else { "-" }
    $name        = if ($c) { $c.PrincipalName } elseif ($b) { $b.PrincipalName } else { $id }

    $scoreDelta = $afterScore - $beforeScore
    $tierDelta  = $tierOrder[$afterTier] - $tierOrder[$beforeTier]

    $status = if ($afterScore -eq 0 -and $beforeScore -gt 0) { "Resolved" }
              elseif ($scoreDelta -lt 0) { "Improved" }
              elseif ($scoreDelta -gt 0) { "REGRESSED" }
              else { "Unchanged" }

    [PSCustomObject]@{
        PrincipalId   = $id
        PrincipalName = $name
        BeforeScore   = $beforeScore
        AfterScore    = $afterScore
        ScoreDelta    = $scoreDelta
        BeforeTier    = $beforeTier
        AfterTier     = $afterTier
        TierDelta     = $tierDelta
        Status        = $status
    }
}

# --- Sort: regressions first, then improvements, then unchanged ---
$statusOrder = @{ "REGRESSED" = 0; "Improved" = 1; "Resolved" = 2; "Unchanged" = 3 }
$diffs = $diffs | Sort-Object @{ Expression = { $statusOrder[$_.Status] } },
                                 @{ Expression = { $_.ScoreDelta } }

# --- Aggregate stats ---
$improved   = @($diffs | Where-Object { $_.Status -eq "Improved"   }).Count
$resolved   = @($diffs | Where-Object { $_.Status -eq "Resolved"   }).Count
$regressed  = @($diffs | Where-Object { $_.Status -eq "REGRESSED"  }).Count
$unchanged  = @($diffs | Where-Object { $_.Status -eq "Unchanged"  }).Count

$totalBefore = ($diffs | Measure-Object -Property BeforeScore -Sum).Sum
$totalAfter  = ($diffs | Measure-Object -Property AfterScore  -Sum).Sum
$netDelta    = $totalAfter - $totalBefore

# --- Build Markdown ---
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine("# Entra ID Remediation Re-Validation Report")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  ")
$null = $sb.AppendLine("**Baseline:** ``$BaselinePath``  ")
$null = $sb.AppendLine("**Current:** ``$CurrentPath``  ")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("---")
$null = $sb.AppendLine("")

# --- Executive summary ---
$null = $sb.AppendLine("## Executive Summary")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("| Metric | Value |")
$null = $sb.AppendLine("|--------|-------|")
$null = $sb.AppendLine("| Principals evaluated | $($diffs.Count) |")
$null = $sb.AppendLine("| Resolved (score -> 0) | $resolved |")
$null = $sb.AppendLine("| Improved | $improved |")
$null = $sb.AppendLine("| Unchanged | $unchanged |")
$null = $sb.AppendLine("| **REGRESSED** | **$regressed** |")
$null = $sb.AppendLine("| Aggregate score before | $totalBefore |")
$null = $sb.AppendLine("| Aggregate score after  | $totalAfter |")
$null = $sb.AppendLine("| Net delta | $netDelta |")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("---")
$null = $sb.AppendLine("")

# --- Regressions warning ---
if ($regressed -gt 0) {
    $null = $sb.AppendLine("## WARNING - Regressions Detected")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("The following principals scored HIGHER after remediation. Investigate before continuing.")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("| Principal | Before | After | Delta | Before Tier | After Tier |")
    $null = $sb.AppendLine("|-----------|--------|-------|-------|-------------|------------|")
    foreach ($d in ($diffs | Where-Object { $_.Status -eq "REGRESSED" })) {
        $null = $sb.AppendLine("| $($d.PrincipalName) | $($d.BeforeScore) | $($d.AfterScore) | +$($d.ScoreDelta) | $($d.BeforeTier) | $($d.AfterTier) |")
    }
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("")
}

# --- Full diff table ---
$null = $sb.AppendLine("## Per-Principal Diff")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("| Principal | Status | Before | After | Delta | Before Tier | After Tier |")
$null = $sb.AppendLine("|-----------|--------|--------|-------|-------|-------------|------------|")
foreach ($d in $diffs) {
    $deltaStr = if ($d.ScoreDelta -gt 0) { "+$($d.ScoreDelta)" } else { "$($d.ScoreDelta)" }
    $null = $sb.AppendLine("| $($d.PrincipalName) | $($d.Status) | $($d.BeforeScore) | $($d.AfterScore) | $deltaStr | $($d.BeforeTier) | $($d.AfterTier) |")
}
$null = $sb.AppendLine("")
$null = $sb.AppendLine("_End of re-validation report._")

# --- Ensure output folder exists ---
$dir = Split-Path $OutputPath -Parent
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$sb.ToString() | Out-File $OutputPath -Encoding UTF8

# --- Append audit log summary ---
$auditDir = Split-Path $AuditLogPath -Parent
if ($auditDir -and -not (Test-Path $auditDir)) {
    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
}
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$auditLine = "[$ts] | REVALIDATE | run | principals=$($diffs.Count) | resolved=$resolved | improved=$improved | regressed=$regressed | netDelta=$netDelta"
Add-Content -Path $AuditLogPath -Value $auditLine -Encoding UTF8

# --- Console output ---
Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  RE-VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  Principals evaluated : $($diffs.Count)"
Write-Host "  Resolved             : $resolved" -ForegroundColor Green
Write-Host "  Improved             : $improved" -ForegroundColor Green
Write-Host "  Unchanged            : $unchanged" -ForegroundColor Gray

if ($regressed -gt 0) {
    Write-Host "  REGRESSED            : $regressed" -ForegroundColor Red
} else {
    Write-Host "  Regressed            : 0" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Aggregate before     : $totalBefore"
Write-Host "  Aggregate after      : $totalAfter"
Write-Host "  Net delta            : $netDelta" -ForegroundColor Yellow
Write-Host ""
Write-Host "[OK] Report saved to: $OutputPath" -ForegroundColor Green
Write-Host "[OK] Audit appended to: $AuditLogPath" -ForegroundColor Green

# --- Top movers ---
Write-Host ""
Write-Host "Top movers:" -ForegroundColor Magenta
$diffs | Select-Object -First 5 | ForEach-Object {
    $deltaStr = if ($_.ScoreDelta -gt 0) { "+$($_.ScoreDelta)" } else { "$($_.ScoreDelta)" }
    Write-Host "  - $($_.PrincipalName): $($_.BeforeScore) -> $($_.AfterScore) ($deltaStr) [$($_.Status)]"
}