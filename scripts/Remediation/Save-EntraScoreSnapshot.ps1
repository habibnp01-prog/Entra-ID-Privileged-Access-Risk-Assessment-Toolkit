<#
.SYNOPSIS
    Saves a timestamped snapshot of the current risk score report.

.DESCRIPTION
    Copies the current RiskScoreReport.json into output/history/ with a
    timestamped filename. Produces a compact history index that the
    dashboard can chart.

    Filenames include milliseconds to prevent collisions when the script is
    invoked multiple times within the same second.

.PARAMETER OutputFolder
    Toolkit output folder. Defaults to ./output

.PARAMETER HistoryFolder
    Where snapshots are stored. Defaults to <OutputFolder>/history

.PARAMETER Label
    Optional label for the snapshot (e.g., "post-remediation"). Appended to
    the filename and stored in the history index.

.EXAMPLE
    .\Save-EntraScoreSnapshot.ps1
    .\Save-EntraScoreSnapshot.ps1 -Label "post-remediation"

.NOTES
    Requires no Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder  = "./output",
    [string]$HistoryFolder = "",
    [string]$Label         = ""
)

if (-not $HistoryFolder) { $HistoryFolder = Join-Path $OutputFolder "history" }

$scorePath = Join-Path $OutputFolder "RiskScoreReport.json"
if (-not (Test-Path $scorePath)) {
    Write-Error "Score report not found at $scorePath. Run Discover first."
    return
}

if (-not (Test-Path $HistoryFolder)) {
    New-Item -ItemType Directory -Path $HistoryFolder -Force | Out-Null
}

$scored = Get-Content $scorePath -Raw | ConvertFrom-Json
if ($scored -isnot [array]) { $scored = @($scored) }

$ts = Get-Date
# Include milliseconds to avoid filename collisions on rapid consecutive runs
$stamp = $ts.ToString("yyyyMMdd-HHmmss-fff")
$safeLabel = if ($Label) { "-" + ($Label -replace '[^A-Za-z0-9\-_]', '_') } else { "" }
$fileName = "score-$stamp$safeLabel.json"
$filePath = Join-Path $HistoryFolder $fileName

# --- Copy the score report ---
Copy-Item $scorePath $filePath -Force

# --- Compute compact summary ---
$tierCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
$total = 0
foreach ($p in $scored) {
    if ($tierCounts.ContainsKey($p.Tier)) { $tierCounts[$p.Tier]++ }
    $total += [int]$p.Score
}

$summary = [PSCustomObject]@{
    Timestamp       = $ts.ToString("yyyy-MM-dd HH:mm:ss.fff")
    Label           = $Label
    File            = $fileName
    Principals      = $scored.Count
    AggregateScore  = $total
    Critical        = $tierCounts.Critical
    High            = $tierCounts.High
    Medium          = $tierCounts.Medium
    Low             = $tierCounts.Low
}

# --- Append to history index (JSON-lines for easy parsing) ---
$indexPath = Join-Path $HistoryFolder "history.jsonl"
$summary | ConvertTo-Json -Compress | Add-Content -Path $indexPath -Encoding UTF8

Write-Host ""
Write-Host "[OK] Snapshot saved: $filePath" -ForegroundColor Green
Write-Host "[*]  Principals: $($scored.Count)  Aggregate: $total" -ForegroundColor Cyan
Write-Host "     Critical: $($tierCounts.Critical)  High: $($tierCounts.High)  Medium: $($tierCounts.Medium)  Low: $($tierCounts.Low)" -ForegroundColor Gray
if ($Label) {
    Write-Host "[*]  Label: $Label" -ForegroundColor Cyan
}
Write-Host "[*]  History index: $indexPath" -ForegroundColor Cyan