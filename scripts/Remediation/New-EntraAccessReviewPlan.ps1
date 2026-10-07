<#
.SYNOPSIS
    Generates an access review plan from the current risk score report.

.DESCRIPTION
    Reads ./output/RiskScoreReport.json and produces:
      - output/AccessReviewPlan.md    (human-readable)
      - output/AccessReviewPlan.json  (machine-readable)

    For each high-privilege role held by one or more principals, the plan
    recommends a review cadence, suggested reviewers, and scope.

    This is a planning document only. It does NOT call Entra ID Governance APIs.

.PARAMETER ScoreReportPath
    Path to RiskScoreReport.json. Defaults to ./output/RiskScoreReport.json

.PARAMETER OutputFolder
    Where plans are written. Defaults to ./output

.EXAMPLE
    .\New-EntraAccessReviewPlan.ps1

.NOTES
    Requires no Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$ScoreReportPath = "./output/RiskScoreReport.json",
    [string]$OutputFolder    = "./output"
)

if (-not (Test-Path $ScoreReportPath)) {
    Write-Error "Score report not found at $ScoreReportPath. Run Discover first."
    return
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

Write-Host "[*] Loading risk score report..." -ForegroundColor Cyan
$scored = Get-Content $ScoreReportPath -Raw | ConvertFrom-Json
if ($scored -isnot [array]) { $scored = @($scored) }

# --- Determine review cadence from tier ---
function Get-ReviewCadence {
    param([string]$Tier)
    switch ($Tier) {
        "Critical" { return "Quarterly (every 90 days)" }
        "High"     { return "Semi-annual (every 180 days)" }
        "Medium"   { return "Annual (every 365 days)" }
        "Low"      { return "Annual / self-attestation" }
        default    { return "Annual" }
    }
}

# --- Suggested reviewer based on role type ---
function Get-SuggestedReviewer {
    param([string]$RoleName)
    if ($RoleName -match "Global Administrator|Privileged Role Administrator|Privileged Authentication Administrator") {
        return "Security leadership + CISO delegate"
    }
    if ($RoleName -match "Compliance|Purview|Data") {
        return "Compliance officer + Data owner"
    }
    if ($RoleName -match "Intune|Windows 365|Device") {
        return "Endpoint / Workplace team lead"
    }
    if ($RoleName -match "Application|Cloud Application") {
        return "Application owner + Identity team"
    }
    if ($RoleName -match "Exchange|SharePoint|Teams") {
        return "Collaboration platform owner"
    }
    return "Identity Governance team"
}

# --- Group findings by role ---
$roleGroups = @{}
foreach ($p in $scored) {
    foreach ($f in $p.Findings) {
        $role = $f.Role
        if (-not $role) { continue }
        if (-not $roleGroups.ContainsKey($role)) {
            $roleGroups[$role] = [PSCustomObject]@{
                RoleName    = $role
                Findings    = @()
                Principals  = @{}
                HighestTier = "Low"
            }
        }
        $roleGroups[$role].Findings += [PSCustomObject]@{
            PrincipalId   = $p.PrincipalId
            PrincipalName = $p.PrincipalName
            Tier          = $p.Tier
            Score         = $p.Score
            Source        = $f.Source
            Reason        = $f.Reason
        }
        $roleGroups[$role].Principals[$p.PrincipalId] = $p.PrincipalName

        $tierRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
        if ($tierRank[$p.Tier] -lt $tierRank[$roleGroups[$role].HighestTier]) {
            $roleGroups[$role].HighestTier = $p.Tier
        }
    }
}

# --- Sort roles: Critical first, then by principal count desc ---
$tierRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
$sortedRoles = $roleGroups.Values | Sort-Object `
    @{ Expression = { $tierRank[$_.HighestTier] } }, `
    @{ Expression = { -$_.Principals.Count } }

$generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# --- Build JSON plan ---
$planItems = foreach ($r in $sortedRoles) {
    [PSCustomObject]@{
        RoleName           = $r.RoleName
        HighestTier        = $r.HighestTier
        PrincipalCount     = $r.Principals.Count
        Principals         = @($r.Principals.Values)
        RecommendedCadence = (Get-ReviewCadence -Tier $r.HighestTier)
        SuggestedReviewer  = (Get-SuggestedReviewer -RoleName $r.RoleName)
        Findings           = $r.Findings
    }
}

$jsonPlan = [PSCustomObject]@{
    Generated  = $generatedAt
    Source     = $ScoreReportPath
    TotalRoles = @($planItems).Count
    Items      = @($planItems)
}

$jsonPath = Join-Path $OutputFolder "AccessReviewPlan.json"
$jsonPlan | ConvertTo-Json -Depth 8 | Out-File $jsonPath -Encoding UTF8

# --- Build Markdown plan ---
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine("# Entra ID Access Review Plan")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("**Generated:** $generatedAt  ")
$null = $sb.AppendLine("**Source:** ``$ScoreReportPath``  ")
$null = $sb.AppendLine("**Roles in scope:** $(@($planItems).Count)  ")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("> This plan recommends access reviews to close identified privileged-access risks.")
$null = $sb.AppendLine("> It does not call Entra ID Governance APIs. Create the reviews manually or via your org's automation.")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("---")
$null = $sb.AppendLine("")

$i = 1
foreach ($item in $planItems) {
    $null = $sb.AppendLine("## $i. $($item.RoleName)")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("| Field | Value |")
    $null = $sb.AppendLine("|-------|-------|")
    $null = $sb.AppendLine("| Highest risk tier | **$($item.HighestTier)** |")
    $null = $sb.AppendLine("| Principals affected | $($item.PrincipalCount) |")
    $null = $sb.AppendLine("| Recommended cadence | $($item.RecommendedCadence) |")
    $null = $sb.AppendLine("| Suggested reviewer | $($item.SuggestedReviewer) |")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("### Principals")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("| Principal | Tier | Score | Source | Reason |")
    $null = $sb.AppendLine("|-----------|------|-------|--------|--------|")
    foreach ($f in $item.Findings) {
        $null = $sb.AppendLine("| $($f.PrincipalName) | $($f.Tier) | $($f.Score) | $($f.Source) | $($f.Reason) |")
    }
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("### Recommended action")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("1. Create an access review in Entra ID Governance for role **$($item.RoleName)**.")
    $null = $sb.AppendLine("2. Scope: all users with permanent or PIM-eligible assignments to this role.")
    $null = $sb.AppendLine("3. Reviewer: $($item.SuggestedReviewer).")
    $null = $sb.AppendLine("4. Cadence: $($item.RecommendedCadence).")
    $null = $sb.AppendLine("5. Enable auto-apply on decision (remove access if not approved).")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("")
    $i++
}

$null = $sb.AppendLine("_End of access review plan._")

$mdPath = Join-Path $OutputFolder "AccessReviewPlan.md"
$sb.ToString() | Out-File $mdPath -Encoding UTF8

Write-Host ""
Write-Host "[OK] Access review plan generated" -ForegroundColor Green
Write-Host "[*]  Roles in scope : $(@($planItems).Count)" -ForegroundColor Cyan
Write-Host "[*]  Markdown       : $mdPath" -ForegroundColor Cyan
Write-Host "[*]  JSON           : $jsonPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Top 3 roles by tier:" -ForegroundColor Magenta
$planItems | Select-Object -First 3 | ForEach-Object {
    Write-Host "  - $($_.RoleName)  [$($_.HighestTier)]  $($_.PrincipalCount) principal(s)"
}