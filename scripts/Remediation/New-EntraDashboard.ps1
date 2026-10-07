<#
.SYNOPSIS
    Generates a self-contained HTML dashboard from toolkit artifacts.

.DESCRIPTION
    Reads:
      - output/RiskScoreReport.json          (principal scores + findings)
      - output/RemediationAudit.log          (audit trail)
      - output/history/history.jsonl         (snapshot history for trend)
      - scenarios/generated/*.json           (auto-scenarios)

    Produces:
      - output/dashboard.html                (self-contained, interactive)

    No external dependencies. Pure HTML/CSS/JS with inline SVG charts.

.PARAMETER OutputFolder
    Toolkit output folder. Defaults to ./output

.PARAMETER ScenarioFolder
    Scenarios folder. Defaults to ./scenarios/generated

.PARAMETER DashboardPath
    Output HTML file. Defaults to <OutputFolder>/dashboard.html

.EXAMPLE
    .\New-EntraDashboard.ps1

.NOTES
    Requires no Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder   = "./output",
    [string]$ScenarioFolder = "./scenarios/generated",
    [string]$DashboardPath  = ""
)

if (-not $DashboardPath) { $DashboardPath = Join-Path $OutputFolder "dashboard.html" }

# --- Validate inputs ---
$scorePath = Join-Path $OutputFolder "RiskScoreReport.json"
$auditPath = Join-Path $OutputFolder "RemediationAudit.log"
$historyPath = Join-Path $OutputFolder "history\history.jsonl"

if (-not (Test-Path $scorePath)) {
    Write-Error "Score report not found at $scorePath. Run -Action Discover first."
    return
}

Write-Host "[*] Loading artifacts..." -ForegroundColor Cyan

# --- Load score report ---
$scored = Get-Content $scorePath -Raw | ConvertFrom-Json
if ($scored -isnot [array]) { $scored = @($scored) }

# --- Aggregate metrics ---
$tierCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
$totalScore = 0
$totalFindings = 0
foreach ($p in $scored) {
    if ($tierCounts.ContainsKey($p.Tier)) { $tierCounts[$p.Tier]++ }
    $totalScore += [int]$p.Score
    $totalFindings += @($p.Findings).Count
}
$aggregateScore = $totalScore

# --- Load audit log ---
$auditRows = @()
if (Test-Path $auditPath) {
    foreach ($line in Get-Content $auditPath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $pattern = '^\[(?<ts>[^\]]+)\]\s*\|\s*(?<mode>[^|]+)\|\s*(?<action>[^|]+)\|\s*(?<rest>.+)$'
        $m = [regex]::Match($line, $pattern)
        if ($m.Success) {
            $auditRows += [PSCustomObject]@{
                Timestamp = $m.Groups['ts'].Value.Trim()
                Mode      = $m.Groups['mode'].Value.Trim()
                Action    = $m.Groups['action'].Value.Trim()
                Rest      = $m.Groups['rest'].Value.Trim()
            }
        }
    }
}

# --- Load history for trend ---
$history = @()
if (Test-Path $historyPath) {
    foreach ($line in Get-Content $historyPath) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $h = $line | ConvertFrom-Json
            $history += $h
        } catch { }
    }
}

# --- Load scenarios ---
$scenarios = @()
if (Test-Path $ScenarioFolder) {
    foreach ($f in Get-ChildItem $ScenarioFolder -Filter "*.json" -ErrorAction SilentlyContinue) {
        try {
            $s = Get-Content $f.FullName -Raw | ConvertFrom-Json
            $scenarios += [PSCustomObject]@{
                File      = $f.Name
                Name      = $s.Name
                Changes   = @($s.Changes).Count
                Generated = $s.Generated
            }
        } catch { }
    }
}

# --- Helpers for HTML encoding ---
function HtmlEnc {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;')
}

function TierClass {
    param([string]$Tier)
    switch ($Tier) {
        "Critical" { return "tier-critical" }
        "High"     { return "tier-high" }
        "Medium"   { return "tier-medium" }
        "Low"      { return "tier-low" }
        default    { return "" }
    }
}

# --- Build SVG sparkline for aggregate score over time ---
function New-TrendSvg {
    param(
        [array]$Points,      # array of PSCustomObject with .Timestamp and .AggregateScore
        [int]$Width = 900,
        [int]$Height = 220,
        [int]$PaddingLeft = 50,
        [int]$PaddingRight = 30,
        [int]$PaddingTop = 20,
        [int]$PaddingBottom = 40
    )

    if ($Points.Count -eq 0) {
        return "<div style='color:#888;padding:20px 0'>No history yet. Run <code>-Action Snapshot</code> to record data points.</div>"
    }

    $innerW = $Width - $PaddingLeft - $PaddingRight
    $innerH = $Height - $PaddingTop - $PaddingBottom

    # Bounds
    $scores = $Points | ForEach-Object { [int]$_.AggregateScore }
    $minScore = ($scores | Measure-Object -Minimum).Minimum
    $maxScore = ($scores | Measure-Object -Maximum).Maximum
    if ($minScore -eq $maxScore) {
        $minScore = [math]::Max(0, $minScore - 5)
        $maxScore = $maxScore + 5
    } else {
        $pad = [math]::Max(1, [int](($maxScore - $minScore) * 0.1))
        $minScore = [math]::Max(0, $minScore - $pad)
        $maxScore = $maxScore + $pad
    }

    $n = $Points.Count
    $stepX = if ($n -gt 1) { $innerW / ($n - 1) } else { 0 }

    # Build polyline points
    $coords = @()
    for ($i = 0; $i -lt $n; $i++) {
        $x = $PaddingLeft + ($i * $stepX)
        $yRatio = ($Points[$i].AggregateScore - $minScore) / ($maxScore - $minScore)
        $y = $PaddingTop + ($innerH - ($yRatio * $innerH))
        $coords += [PSCustomObject]@{ X = $x; Y = $y; P = $Points[$i] }
    }

    $polylinePts = ($coords | ForEach-Object { "$([math]::Round($_.X,1)),$([math]::Round($_.Y,1))" }) -join " "

    # Area under curve
    $areaPts = "$PaddingLeft,$($PaddingTop + $innerH) " + $polylinePts + " $([math]::Round($coords[-1].X,1)),$($PaddingTop + $innerH)"

    # Y-axis grid + labels (4 steps)
    $gridLines = ""
    for ($g = 0; $g -le 4; $g++) {
        $frac = $g / 4
        $y = $PaddingTop + ($innerH * $frac)
        $val = [int]($maxScore - $frac * ($maxScore - $minScore))
        $gridLines += "<line x1='$PaddingLeft' y1='$([math]::Round($y,1))' x2='$($PaddingLeft + $innerW)' y2='$([math]::Round($y,1))' stroke='#eee' stroke-width='1'/>"
        $gridLines += "<text x='$($PaddingLeft - 8)' y='$([math]::Round($y + 4,1))' font-size='10' fill='#999' text-anchor='end'>$val</text>"
    }

    # Points (small circles)
    $dots = ""
    foreach ($c in $coords) {
        $dots += "<circle cx='$([math]::Round($c.X,1))' cy='$([math]::Round($c.Y,1))' r='4' fill='#0078d4' stroke='white' stroke-width='2'/>"
        # Tooltip
        $label = HtmlEnc $c.P.Timestamp
        $score = HtmlEnc $c.P.AggregateScore
        $lbl = HtmlEnc $c.P.Label
        $tipText = "$label&#10;Score: $score"
        if ($lbl) { $tipText += "&#10;Label: $lbl" }
        $dots += "<circle cx='$([math]::Round($c.X,1))' cy='$([math]::Round($c.Y,1))' r='10' fill='transparent'><title>$tipText</title></circle>"
    }

    # X-axis labels (first, middle, last only if too many)
    $xLabels = ""
    if ($n -le 6) {
        foreach ($c in $coords) {
            $ts = (HtmlEnc $c.P.Timestamp) -replace ':.*$',''  # strip seconds+ms
            $xLabels += "<text x='$([math]::Round($c.X,1))' y='$($Height - 10)' font-size='10' fill='#999' text-anchor='middle'>$ts</text>"
        }
    } else {
        $first = $coords[0]
        $last = $coords[-1]
        $firstTs = (HtmlEnc $first.P.Timestamp) -replace ':.*$',''
        $lastTs  = (HtmlEnc $last.P.Timestamp)  -replace ':.*$',''
        $xLabels += "<text x='$([math]::Round($first.X,1))' y='$($Height - 10)' font-size='10' fill='#999' text-anchor='start'>$firstTs</text>"
        $xLabels += "<text x='$([math]::Round($last.X,1))' y='$($Height - 10)' font-size='10' fill='#999' text-anchor='end'>$lastTs</text>"
    }

    $svg = @"
<svg viewBox="0 0 $Width $Height" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto">
  $gridLines
  <polygon points="$areaPts" fill="rgba(0,120,212,0.08)"/>
  <polyline points="$polylinePts" fill="none" stroke="#0078d4" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>
  $dots
  $xLabels
</svg>
"@
    return $svg
}

# Build trend points from history (chronological)
$trendPoints = @($history | Sort-Object Timestamp)
$trendSvg = New-TrendSvg -Points $trendPoints

# --- Build principal rows ---
$principalRows = foreach ($p in ($scored | Sort-Object Score -Descending)) {
    $findingRows = foreach ($f in $p.Findings) {
        $src = HtmlEnc $f.Source
        $role = HtmlEnc $f.Role
        $weight = HtmlEnc $f.Weight
        $reason = HtmlEnc $f.Reason
        "<tr><td>$src</td><td>$role</td><td>$weight</td><td>$reason</td></tr>"
    }
    $findingTable = "<table class='inner'><thead><tr><th>Source</th><th>Role</th><th>Weight</th><th>Reason</th></tr></thead><tbody>$($findingRows -join '')</tbody></table>"

    $tierClass = TierClass -Tier $p.Tier
    $name = HtmlEnc $p.PrincipalName
    $pid_ = HtmlEnc $p.PrincipalId
    $tier = HtmlEnc $p.Tier
    $score = HtmlEnc $p.Score
    $findingCount = @($p.Findings).Count
    $highPrivCount = HtmlEnc $p.HighPrivRoleCount

    @"
<div class="principal-card">
  <div class="principal-header" onclick="toggleCard(this)">
    <span class="tier-badge $tierClass">$tier</span>
    <span class="principal-name">$name</span>
    <span class="principal-score">Score: $score</span>
    <span class="principal-meta">$highPrivCount high-priv roles &middot; $findingCount findings</span>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="principal-body">
    <div class="principal-id">Principal ID: <code>$pid_</code></div>
    $findingTable
  </div>
</div>
"@
}

# --- Build audit rows ---
$auditTableRows = foreach ($r in ($auditRows | Select-Object -Last 50)) {
    $ts = HtmlEnc $r.Timestamp
    $mode = HtmlEnc $r.Mode
    $action = HtmlEnc $r.Action
    $rest = HtmlEnc $r.Rest
    "<tr><td>$ts</td><td>$mode</td><td>$action</td><td class='mono'>$rest</td></tr>"
}

# --- Build scenario rows ---
$scenarioRows = foreach ($s in $scenarios) {
    $file = HtmlEnc $s.File
    $name = HtmlEnc $s.Name
    $changes = HtmlEnc $s.Changes
    $gen = HtmlEnc $s.Generated
    "<tr><td class='mono'>$file</td><td>$name</td><td>$changes</td><td>$gen</td></tr>"
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$snapshotCount = $history.Count

# --- Compose HTML ---
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Entra ID Risk Dashboard</title>
<style>
  :root {
    --crit: #c0392b;
    --high: #e67e22;
    --med:  #f1c40f;
    --low:  #27ae60;
    --bg:   #f5f6f8;
    --card: #ffffff;
    --ink:  #222;
    --muted:#666;
    --line: #eef0f3;
    --accent:#0078d4;
  }
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--ink);
    margin: 0; padding: 24px;
  }
  h1 { color: var(--accent); margin: 0 0 4px 0; }
  .subtitle { color: var(--muted); margin-bottom: 24px; }
  h2 { margin-top: 36px; color: #333; border-bottom: 2px solid var(--accent); padding-bottom: 6px; }

  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; }
  .kpi {
    background: var(--card); padding: 16px 20px; border-radius: 8px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    border-left: 4px solid var(--accent);
  }
  .kpi.crit { border-left-color: var(--crit); }
  .kpi.high { border-left-color: var(--high); }
  .kpi.med  { border-left-color: var(--med); }
  .kpi.low  { border-left-color: var(--low); }
  .kpi .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); }
  .kpi .value { font-size: 30px; font-weight: 600; margin-top: 4px; }
  .kpi.crit .value { color: var(--crit); }
  .kpi.high .value { color: var(--high); }
  .kpi.med  .value { color: #b8860b; }
  .kpi.low  .value { color: var(--low); }

  .trend-card {
    background: var(--card); border-radius: 8px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    padding: 16px 20px; margin-top: 12px;
  }
  .trend-meta { color: var(--muted); font-size: 12px; margin-bottom: 6px; }

  table { width: 100%; border-collapse: collapse; background: var(--card);
          box-shadow: 0 1px 4px rgba(0,0,0,0.06); border-radius: 8px; overflow: hidden; margin-top: 12px; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--line); font-size: 13px; }
  th { background: #eef4fb; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; color: #333; }
  tr:hover td { background: #f9fbfd; }
  td.mono { font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; color: var(--muted); }

  .principal-card {
    background: var(--card); border-radius: 8px; margin-bottom: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06); overflow: hidden;
  }
  .principal-header {
    display: flex; align-items: center; gap: 14px; padding: 14px 18px;
    cursor: pointer; user-select: none;
  }
  .principal-header:hover { background: #fafbfd; }
  .tier-badge {
    font-size: 11px; font-weight: 700; letter-spacing: 0.5px;
    padding: 4px 10px; border-radius: 12px; text-transform: uppercase;
    background: #eee; color: #333;
  }
  .tier-critical { background: var(--crit); color: white; }
  .tier-high     { background: var(--high); color: white; }
  .tier-medium   { background: var(--med); color: #333; }
  .tier-low      { background: var(--low); color: white; }
  .principal-name { font-weight: 600; flex: 1; }
  .principal-score { font-weight: 600; color: var(--accent); }
  .principal-meta { color: var(--muted); font-size: 12px; }
  .chevron { color: var(--muted); transition: transform 0.2s; }
  .principal-body { padding: 0 18px 18px 18px; display: none; }
  .principal-card.expanded .principal-body { display: block; }
  .principal-card.expanded .chevron { transform: rotate(180deg); }
  .principal-id { color: var(--muted); font-size: 12px; margin-bottom: 10px; }
  table.inner { box-shadow: none; border-radius: 4px; border: 1px solid var(--line); margin-top: 0; }
  table.inner th { background: #f7f9fc; font-size: 10px; }
  table.inner td { font-size: 12px; padding: 8px 12px; }

  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line);
            text-align: center; color: var(--muted); font-size: 12px; }

  @media print {
    body { background: white; }
    .kpi, table, .principal-card, .trend-card { box-shadow: none; border: 1px solid #ddd; }
    .chevron { display: none; }
    .principal-body { display: block !important; }
  }
</style>
</head>
<body>

<h1>Entra ID Privileged Access &amp; Identity Risk Dashboard</h1>
<div class="subtitle">Generated $timestamp &middot; Source: <code>$scorePath</code></div>

<h2>Executive Summary</h2>
<div class="kpis">
  <div class="kpi"><div class="label">Principals scored</div><div class="value">$($scored.Count)</div></div>
  <div class="kpi crit"><div class="label">Critical</div><div class="value">$($tierCounts.Critical)</div></div>
  <div class="kpi high"><div class="label">High</div><div class="value">$($tierCounts.High)</div></div>
  <div class="kpi med"><div class="label">Medium</div><div class="value">$($tierCounts.Medium)</div></div>
  <div class="kpi low"><div class="label">Low</div><div class="value">$($tierCounts.Low)</div></div>
  <div class="kpi"><div class="label">Aggregate score</div><div class="value">$aggregateScore</div></div>
  <div class="kpi"><div class="label">Total findings</div><div class="value">$totalFindings</div></div>
  <div class="kpi"><div class="label">Scenarios ready</div><div class="value">$($scenarios.Count)</div></div>
</div>

<h2>Aggregate Score Trend</h2>
<div class="trend-card">
  <div class="trend-meta">$snapshotCount snapshot(s) in history &middot; Hover a point for details &middot; Run <code>-Action Snapshot</code> after each Discover to build the chart</div>
  $trendSvg
</div>

<h2>Principals by Risk</h2>
$($principalRows -join "`n")

<h2>Auto-Generated Scenarios</h2>
$(if ($scenarios.Count -gt 0) {
    "<table><thead><tr><th>File</th><th>Name</th><th>Changes</th><th>Generated</th></tr></thead><tbody>$($scenarioRows -join '')</tbody></table>"
} else {
    "<p style='color:var(--muted)'>No scenarios in $ScenarioFolder. Run <code>-Action Scenarios</code>.</p>"
})

<h2>Recent Audit Events</h2>
$(if ($auditRows.Count -gt 0) {
    "<table><thead><tr><th>Timestamp</th><th>Mode</th><th>Action</th><th>Details</th></tr></thead><tbody>$($auditTableRows -join '')</tbody></table>"
} else {
    "<p style='color:var(--muted)'>No audit events yet.</p>"
})

<div class="footer">
  Generated by Entra-ID-Privileged-Access-Risk-Assessment-Toolkit &middot; $timestamp
</div>

<script>
function toggleCard(el) {
  var card = el.parentElement;
  card.classList.toggle('expanded');
}
document.addEventListener('DOMContentLoaded', function() {
  var first = document.querySelector('.principal-card');
  if (first) first.classList.add('expanded');
});
</script>

</body>
</html>
"@

# --- Ensure output folder exists ---
$dir = Split-Path $DashboardPath -Parent
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# --- Write file (UTF-8, no BOM) ---
$resolvedDir = (Resolve-Path -LiteralPath $dir).Path
$finalPath = Join-Path $resolvedDir (Split-Path $DashboardPath -Leaf)
[System.IO.File]::WriteAllText($finalPath, $html, (New-Object System.Text.UTF8Encoding $false))

Write-Host ""
Write-Host "[OK] Dashboard saved to: $DashboardPath" -ForegroundColor Green
Write-Host "[*]  Principals : $($scored.Count)" -ForegroundColor Cyan
Write-Host "     Critical   : $($tierCounts.Critical)" -ForegroundColor Red
Write-Host "     High       : $($tierCounts.High)" -ForegroundColor DarkYellow
Write-Host "     Medium     : $($tierCounts.Medium)" -ForegroundColor Yellow
Write-Host "     Low        : $($tierCounts.Low)" -ForegroundColor Green
Write-Host "[*]  Scenarios  : $($scenarios.Count)" -ForegroundColor Cyan
Write-Host "[*]  Snapshots  : $snapshotCount" -ForegroundColor Cyan
Write-Host "[*]  Audit rows : $($auditRows.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "[i] Open in browser: $DashboardPath" -ForegroundColor Gray