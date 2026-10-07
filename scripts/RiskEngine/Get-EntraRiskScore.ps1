<#
.SYNOPSIS
    Computes a weighted identity risk score from PIM and permanent role findings.

.DESCRIPTION
    Ingests the JSON outputs produced by Get-EntraPIMEligibilityReport.ps1 and
    Get-EntraPermanentRoleReport.ps1, correlates them per principal, and applies
    a weighted scoring model based on role privilege, assignment permanence,
    and blast radius (number of distinct high-privilege roles held).

.PARAMETER PIMReportPath
    Path to PIMEligibilityReport.json. Defaults to ./output/PIMEligibilityReport.json

.PARAMETER PermanentReportPath
    Path to PermanentRoleReport.json. Defaults to ./output/PermanentRoleReport.json

.PARAMETER OutputPath
    Path to write the scored report. Defaults to ./output/RiskScoreReport.json

.EXAMPLE
    .\Get-EntraRiskScore.ps1

.NOTES
    This script does NOT require Graph connectivity - it works on the JSON
    files produced by the discovery scripts (2.1 and 2.2).
#>

[CmdletBinding()]
param(
    [string]$PIMReportPath       = "./output/PIMEligibilityReport.json",
    [string]$PermanentReportPath = "./output/PermanentRoleReport.json",
    [string]$OutputPath          = "./output/RiskScoreReport.json"
)

# --- Validate inputs ---
if (-not (Test-Path $PIMReportPath)) {
    Write-Error "PIM report not found at $PIMReportPath. Run Get-EntraPIMEligibilityReport.ps1 first."
    return
}
if (-not (Test-Path $PermanentReportPath)) {
    Write-Error "Permanent role report not found at $PermanentReportPath. Run Get-EntraPermanentRoleReport.ps1 first."
    return
}

Write-Host "[*] Loading source reports..." -ForegroundColor Cyan
$pimData       = Get-Content $PIMReportPath       -Raw | ConvertFrom-Json
$permanentData = Get-Content $PermanentReportPath -Raw | ConvertFrom-Json

# --- Normalize: ensure arrays even if only one record ---
if ($pimData -isnot [array])       { $pimData       = @($pimData) }
if ($permanentData -isnot [array]) { $permanentData = @($permanentData) }

$highPrivilegeRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Authentication Administrator",
    "Helpdesk Administrator",
    "Password Administrator"
)

# --- Build a per-principal accumulator ---
$principals = @{}

function Get-OrCreatePrincipal {
    param([string]$Id, [string]$Name)
    if (-not $principals.ContainsKey($Id)) {
        $principals[$Id] = [PSCustomObject]@{
            PrincipalId       = $Id
            PrincipalName     = $Name
            Score             = 0
            Findings          = @()
            HighPrivRoleCount = 0
        }
    }
    return $principals[$Id]
}

# --- Process permanent findings (2.2) - highest weight ---
foreach ($f in $permanentData) {
    $p = Get-OrCreatePrincipal -Id $f.PrincipalId -Name $f.PrincipalName
    $isHigh = $highPrivilegeRoles -contains $f.RoleName

    if ($isHigh) {
        $weight = 50
        $p.HighPrivRoleCount++
    } else {
        $weight = 25
    }

    $p.Score += $weight
    $p.Findings += [PSCustomObject]@{
        Source = "PermanentRole"
        Role   = $f.RoleName
        Weight = $weight
        Reason = $f.Reason
    }
}

# --- Process PIM findings (2.1) ---
foreach ($f in $pimData) {
    $p = Get-OrCreatePrincipal -Id $f.PrincipalId -Name $f.PrincipalName
    $isHigh = $highPrivilegeRoles -contains $f.RoleName

    if ($f.AssignmentType -eq "Active" -and $isHigh) {
        $weight = 20
        $p.HighPrivRoleCount++
    }
    elseif ($f.AssignmentType -eq "Eligible" -and $isHigh) {
        $weight = 10
        $p.HighPrivRoleCount++
    }
    elseif ($f.ExpirationType -eq "NoExpiration" -or $null -eq $f.EndDateTime) {
        $weight = 5
    }
    else {
        $weight = 2
    }

    $p.Score += $weight
    $p.Findings += [PSCustomObject]@{
        Source = "PIM"
        Role   = $f.RoleName
        Weight = $weight
        Reason = "$($f.AssignmentType) - $($f.Reason)"
    }
}

# --- Apply blast-radius multiplier and cap at 100 ---
foreach ($key in $principals.Keys) {
    $p = $principals[$key]
    if ($p.HighPrivRoleCount -ge 3) {
        $p.Score = [math]::Round($p.Score * 1.5)
    }
    if ($p.Score -gt 100) { $p.Score = 100 }

    # --- Assign tier ---
    if     ($p.Score -ge 80) { $tier = "Critical" }
    elseif ($p.Score -ge 50) { $tier = "High" }
    elseif ($p.Score -ge 25) { $tier = "Medium" }
    else                     { $tier = "Low" }

    $p | Add-Member -NotePropertyName Tier         -NotePropertyValue $tier -Force
    $p | Add-Member -NotePropertyName FindingCount -NotePropertyValue $p.Findings.Count -Force
}

# --- Sort by score descending ---
$ranked = $principals.Values | Sort-Object Score -Descending

# --- Ensure output folder exists ---
$dir = Split-Path $OutputPath -Parent
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# --- Write JSON report ---
$ranked | ConvertTo-Json -Depth 6 | Out-File $OutputPath -Encoding UTF8

# --- Console summary ---
$critCount = ($ranked | Where-Object { $_.Tier -eq "Critical" }).Count
$highCount = ($ranked | Where-Object { $_.Tier -eq "High" }).Count
$medCount  = ($ranked | Where-Object { $_.Tier -eq "Medium" }).Count
$lowCount  = ($ranked | Where-Object { $_.Tier -eq "Low" }).Count

Write-Host ""
Write-Host "[OK] Risk score report saved to: $OutputPath" -ForegroundColor Green
Write-Host "[*]  Principals scored: $($ranked.Count)" -ForegroundColor Cyan
Write-Host "     Critical: $critCount" -ForegroundColor Red
Write-Host "     High:     $highCount" -ForegroundColor DarkYellow
Write-Host "     Medium:   $medCount"  -ForegroundColor Yellow
Write-Host "     Low:      $lowCount"  -ForegroundColor Green

# --- Top 5 preview ---
if ($ranked.Count -gt 0) {
    Write-Host ""
    Write-Host "[TOP 5] Highest-risk identities:" -ForegroundColor Magenta
    $ranked | Select-Object -First 5 |
        Format-Table PrincipalName, Score, Tier, HighPrivRoleCount, FindingCount -AutoSize
}