<#
.SYNOPSIS
    Packages audit artifacts into a timestamped bundle (CSV + HTML) for compliance review.

.DESCRIPTION
    Reads the toolkit's output folder and produces a self-contained audit bundle:
      - audit-log.csv          Structured audit log entries
      - audit-report.html      Printable HTML summary with tables and metrics
      - bundle-manifest.txt    Contents + generation metadata

    The bundle is written to ./output/audit-YYYYMMDD-HHMMSS/

    No Graph connectivity required - this is a local packaging tool.

.PARAMETER OutputFolder
    Source folder for input artifacts. Defaults to ./output

.PARAMETER BundleRoot
    Root folder where bundles are created. Defaults to ./output

.EXAMPLE
    .\Export-EntraAuditBundle.ps1

.NOTES
    Requires no Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "./output",
    [string]$BundleRoot   = "./output"
)

# --- Validate source folder ---
if (-not (Test-Path $OutputFolder)) {
    Write-Error "Output folder not found: $OutputFolder"
    return
}

# --- Create timestamped bundle folder ---
$stamp        = Get-Date -Format "yyyyMMdd-HHmmss"
$bundlePath   = Join-Path $BundleRoot "audit-$stamp"
if (-not (Test-Path $bundlePath)) {
    New-Item -ItemType Directory -Path $bundlePath -Force | Out-Null
}

Write-Host "[*] Creating audit bundle at: $bundlePath" -ForegroundColor Cyan

# =========================================================
# 1. Parse audit log into CSV
# =========================================================
$auditLogPath = Join-Path $OutputFolder "RemediationAudit.log"
$auditRows    = @()

if (Test-Path $auditLogPath) {
    Write-Host "[*] Parsing audit log..." -ForegroundColor Cyan

    foreach ($line in Get-Content $auditLogPath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # Pattern: [timestamp] | MODE | ACTION | principal=X | role=Y | result=Z [| detail=...]
        $pattern = '^\[(?<ts>[^\]]+)\]\s*\|\s*(?<mode>[^|]+)\|\s*(?<action>[^|]+)\|\s*(?<rest>.+)$'
        $m = [regex]::Match($line, $pattern)

        if (-not $m.Success) {
            $auditRows += [PSCustomObject]@{
                Timestamp   = ""
                Mode        = ""
                Action      = ""
                PrincipalId = ""
                RoleName    = ""
                Result      = ""
                Detail      = $line
            }
            continue
        }

        $ts     = $m.Groups['ts'].Value.Trim()
        $mode   = $m.Groups['mode'].Value.Trim()
        $action = $m.Groups['action'].Value.Trim()
        $rest   = $m.Groups['rest'].Value.Trim()

        # Extract key=value pairs from rest
        $kv = @{}
        foreach ($pair in ($rest -split '\s*\|\s*')) {
            if ($pair -match '^(?<k>[^=]+)=(?<v>.*)$') {
                $kv[$matches['k'].Trim()] = $matches['v'].Trim()
            }
        }

        $auditRows += [PSCustomObject]@{
            Timestamp   = $ts
            Mode        = $mode
            Action      = $action
            PrincipalId = if ($kv.ContainsKey('principal')) { $kv['principal'] } else { "" }
            RoleName    = if ($kv.ContainsKey('role'))      { $kv['role'] }      else { "" }
            Result      = if ($kv.ContainsKey('result'))    { $kv['result'] }    else { "" }
            Detail      = if ($kv.ContainsKey('detail'))    { $kv['detail'] }    else { "" }
        }
    }

    $csvPath = Join-Path $bundlePath "audit-log.csv"
    $auditRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "    [OK] $($auditRows.Count) audit entries -> audit-log.csv" -ForegroundColor Green
} else {
    Write-Host "    [SKIP] No audit log found at $auditLogPath" -ForegroundColor Yellow
    $auditRows = @()
}

# =========================================================
# 2. Load score report (for top risks table)
# =========================================================
$scoreReportPath = Join-Path $OutputFolder "RiskScoreReport.json"
$scored = @()
if (Test-Path $scoreReportPath) {
    Write-Host "[*] Loading risk score report..." -ForegroundColor Cyan
    $scored = Get-Content $scoreReportPath -Raw | ConvertFrom-Json
    if ($scored -isnot [array]) { $scored = @($scored) }
    Write-Host "    [OK] $($scored.Count) identities loaded" -ForegroundColor Green
}

# =========================================================
# 3. Load re-validation report if present (for summary)
# =========================================================
$revalPath = Join-Path $OutputFolder "ReValidationReport.md"
$revalExists = Test-Path $revalPath

# =========================================================
# 4. Compute metrics for HTML
# =========================================================
$modeCounts   = @{}
$resultCounts = @{}
foreach ($r in $auditRows) {
    if (-not $modeCounts.ContainsKey($r.Mode))     { $modeCounts[$r.Mode] = 0 }
    if (-not $resultCounts.ContainsKey($r.Result)) { $resultCounts[$r.Result] = 0 }
    $modeCounts[$r.Mode]++
    $resultCounts[$r.Result]++
}

$tierCounts = @{}
foreach ($p in $scored) {
    if (-not $tierCounts.ContainsKey($p.Tier)) { $tierCounts[$p.Tier] = 0 }
    $tierCounts[$p.Tier]++
}

# =========================================================
# 5. Build HTML report
# =========================================================
$html = New-Object System.Text.StringBuilder

$null = $html.AppendLine('<!DOCTYPE html>')
$null = $html.AppendLine('<html lang="en"><head><meta charset="utf-8">')
$null = $html.AppendLine('<title>Entra ID Risk Audit Bundle</title>')
$null = $html.AppendLine('<style>')
$null = $html.AppendLine('body{font-family:Segoe UI,Arial,sans-serif;background:#f5f6f8;color:#222;margin:0;padding:20px}')
$null = $html.AppendLine('h1{color:#0078d4;margin-top:0}')
$null = $html.AppendLine('h2{color:#333;border-bottom:2px solid #0078d4;padding-bottom:6px;margin-top:30px}')
$null = $html.AppendLine('.meta{background:#fff;padding:12px 18px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}')
$null = $html.AppendLine('.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}')
$null = $html.AppendLine('.card{background:#fff;padding:14px 18px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.1);min-width:150px}')
$null = $html.AppendLine('.card .label{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.5px}')
$null = $html.AppendLine('.card .value{font-size:26px;font-weight:600;color:#0078d4;margin-top:4px}')
$null = $html.AppendLine('table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1);border-radius:6px;overflow:hidden}')
$null = $html.AppendLine('th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #eef0f3;font-size:13px}')
$null = $html.AppendLine('th{background:#eef4fb;color:#333;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.5px}')
$null = $html.AppendLine('tr:hover td{background:#f9fbfd}')
$null = $html.AppendLine('.tier-Critical{color:#c00;font-weight:600}')
$null = $html.AppendLine('.tier-High{color:#e67e00;font-weight:600}')
$null = $html.AppendLine('.tier-Medium{color:#b8860b}')
$null = $html.AppendLine('.tier-Low{color:#2e7d32}')
$null = $html.AppendLine('.result-SIMULATED{color:#888}')
$null = $html.AppendLine('.result-BLOCKED_LAST_GA{color:#c00;font-weight:600}')
$null = $html.AppendLine('.result-FAILED{color:#c00}')
$null = $html.AppendLine('.result-PERMANENT_REMOVED{color:#2e7d32}')
$null = $html.AppendLine('.result-ELIGIBLE_CREATED{color:#2e7d32}')
$null = $html.AppendLine('.footer{margin-top:40px;color:#888;font-size:12px;text-align:center}')
$null = $html.AppendLine('@media print{body{background:#fff}.card,table{box-shadow:none;border:1px solid #ddd}}')
$null = $html.AppendLine('</style></head><body>')

# Header
$null = $html.AppendLine('<h1>Entra ID Privileged Access - Audit Bundle</h1>')
$null = $html.AppendLine('<div class="meta">')
$null = $html.AppendLine("<strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>")
$null = $html.AppendLine("<strong>Bundle:</strong> audit-$stamp<br>")
$null = $html.AppendLine("<strong>Toolkit:</strong> Entra-ID-Privileged-Access-Risk-Assessment-Toolkit")
$null = $html.AppendLine('</div>')

# Summary cards
$null = $html.AppendLine('<div class="cards">')
$null = $html.AppendLine("<div class='card'><div class='label'>Audit Events</div><div class='value'>$($auditRows.Count)</div></div>")
$null = $html.AppendLine("<div class='card'><div class='label'>Identities Scored</div><div class='value'>$($scored.Count)</div></div>")
foreach ($t in @("Critical","High","Medium","Low")) {
    $c = if ($tierCounts.ContainsKey($t)) { $tierCounts[$t] } else { 0 }
    $null = $html.AppendLine("<div class='card'><div class='label'>Tier $t</div><div class='value tier-$t'>$c</div></div>")
}
$null = $html.AppendLine('</div>')

# Audit results breakdown
if ($auditRows.Count -gt 0) {
    $null = $html.AppendLine('<h2>Audit Results Breakdown</h2>')
    $null = $html.AppendLine('<table><thead><tr><th>Result</th><th>Count</th></tr></thead><tbody>')
    foreach ($k in $resultCounts.Keys) {
        $null = $html.AppendLine("<tr><td class='result-$k'>$k</td><td>$($resultCounts[$k])</td></tr>")
    }
    $null = $html.AppendLine('</tbody></table>')
}

# Top risks
if ($scored.Count -gt 0) {
    $null = $html.AppendLine('<h2>Identity Risk Snapshot</h2>')
    $null = $html.AppendLine('<table><thead><tr><th>Principal</th><th>Score</th><th>Tier</th><th>High-Priv Roles</th><th>Findings</th></tr></thead><tbody>')
    foreach ($p in ($scored | Sort-Object Score -Descending)) {
        $null = $html.AppendLine("<tr><td>$($p.PrincipalName)</td><td>$($p.Score)</td><td class='tier-$($p.Tier)'>$($p.Tier)</td><td>$($p.HighPrivRoleCount)</td><td>$($p.Findings.Count)</td></tr>")
    }
    $null = $html.AppendLine('</tbody></table>')
}

# Audit log table
if ($auditRows.Count -gt 0) {
    $null = $html.AppendLine('<h2>Audit Log</h2>')
    $null = $html.AppendLine('<table><thead><tr><th>Timestamp</th><th>Mode</th><th>Action</th><th>Principal</th><th>Role</th><th>Result</th></tr></thead><tbody>')
    foreach ($r in $auditRows) {
        $null = $html.AppendLine("<tr><td>$($r.Timestamp)</td><td>$($r.Mode)</td><td>$($r.Action)</td><td>$($r.PrincipalId)</td><td>$($r.RoleName)</td><td class='result-$($r.Result)'>$($r.Result)</td></tr>")
    }
    $null = $html.AppendLine('</tbody></table>')
}

# Re-validation note
if ($revalExists) {
    $null = $html.AppendLine('<h2>Re-Validation</h2>')
    $null = $html.AppendLine("<p>A re-validation report is included in the source folder: <code>ReValidationReport.md</code></p>")
}

$null = $html.AppendLine("<div class='footer'>Generated by Entra-ID-Privileged-Access-Risk-Assessment-Toolkit - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>")
$null = $html.AppendLine('</body></html>')

$htmlPath = Join-Path $bundlePath "audit-report.html"
$html.ToString() | Out-File $htmlPath -Encoding UTF8
Write-Host "    [OK] HTML report -> audit-report.html" -ForegroundColor Green

# =========================================================
# 6. Bundle manifest
# =========================================================
$manifestPath = Join-Path $bundlePath "bundle-manifest.txt"
$manifest = @()
$manifest += "Entra ID Privileged Access - Audit Bundle"
$manifest += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$manifest += "Bundle:    audit-$stamp"
$manifest += ""
$manifest += "Contents:"
Get-ChildItem $bundlePath | ForEach-Object {
    $manifest += "  - $($_.Name)  ($($_.Length) bytes)"
}
$manifest += ""
$manifest += "Source artifacts:"
if (Test-Path $auditLogPath) { $manifest += "  - $auditLogPath" }
if (Test-Path $scoreReportPath) { $manifest += "  - $scoreReportPath" }
if ($revalExists) { $manifest += "  - $revalPath" }

$manifest | Out-File $manifestPath -Encoding UTF8
Write-Host "    [OK] Manifest -> bundle-manifest.txt" -ForegroundColor Green

# =========================================================
# 7. Console summary
# =========================================================
Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  AUDIT BUNDLE COMPLETE" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  Bundle path : $bundlePath"
Write-Host "  Audit rows  : $($auditRows.Count)"
Write-Host "  Identities  : $($scored.Count)"
Write-Host ""
Write-Host "  Files:"
Get-ChildItem $bundlePath | ForEach-Object {
    Write-Host "    - $($_.Name)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "[OK] Open $htmlPath in a browser to review." -ForegroundColor Green