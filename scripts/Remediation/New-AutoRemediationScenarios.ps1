<#
.SYNOPSIS
    Auto-generates remediation scenarios from the current risk score report.

.DESCRIPTION
    Reads ./output/RiskScoreReport.json and emits one scenario file per
    principal whose risk tier is at or above a configurable threshold.

    Nothing is hardcoded: principals, roles, and actions are all derived from
    the report. Each scenario is safe to feed into Invoke-WhatIfSimulation.ps1
    or Invoke-EntraRemediation.ps1.

.PARAMETER ScoreReportPath
    Path to RiskScoreReport.json. Defaults to ./output/RiskScoreReport.json

.PARAMETER ScenariosFolder
    Where scenarios are written. Defaults to ./scenarios/generated

.PARAMETER MinTier
    Minimum tier to generate scenarios for.
    One of: Critical, High, Medium, Low. Defaults to High.

.EXAMPLE
    .\New-AutoRemediationScenarios.ps1
    .\New-AutoRemediationScenarios.ps1 -MinTier Medium

.NOTES
    Requires no Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$ScoreReportPath = "./output/RiskScoreReport.json",
    [string]$ScenariosFolder = "./scenarios/generated",
    [ValidateSet("Critical","High","Medium","Low")]
    [string]$MinTier = "High"
)

# --- Validate input ---
if (-not (Test-Path $ScoreReportPath)) {
    Write-Error "Score report not found at $ScoreReportPath. Run Get-EntraRiskScore.ps1 first."
    return
}

Write-Host "[*] Loading risk score report..." -ForegroundColor Cyan
$scored = Get-Content $ScoreReportPath -Raw | ConvertFrom-Json
if ($scored -isnot [array]) { $scored = @($scored) }

# --- Tier ordering ---
$tierOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3 }
$minRank   = $tierOrder[$MinTier]

# --- Filter principals at or above threshold ---
$targets = @($scored | Where-Object { $tierOrder[$_.Tier] -le $minRank })

Write-Host "[*] Selected $($targets.Count) principal(s) at tier >= $MinTier" -ForegroundColor Cyan

if ($targets.Count -eq 0) {
    Write-Host "[OK] Nothing to generate - no principals at or above $MinTier." -ForegroundColor Green
    return
}

# --- Ensure output folder ---
if (-not (Test-Path $ScenariosFolder)) {
    New-Item -ItemType Directory -Path $ScenariosFolder -Force | Out-Null
}

# --- Helper: build changes from a principal's findings ---
function New-ChangesFromFindings {
    param($Principal)

    $changes = @()

    foreach ($f in $Principal.Findings) {

        # Choose the action based on the finding source and reason
        $action = $null

        if ($f.Source -eq "PermanentRole") {
            # Convert permanent assignments to PIM eligible
            $action = "ConvertPermanentToEligible"
        }
        elseif ($f.Source -eq "PIM" -and $f.Reason -match "Active") {
            # Convert long-lived active PIM into time-bound eligible
            $action = "ConvertPermanentToEligible"
        }
        elseif ($f.Source -eq "PIM" -and $f.Reason -match "Eligible") {
            # Remove dangling eligible assignments
            $action = "RemoveEligible"
        }

        if ($action) {
            $changes += [PSCustomObject]@{
                Action      = $action
                PrincipalId = $Principal.PrincipalId
                RoleName    = $f.Role
            }
        }
    }

    return $changes
}

# --- Generate a scenario file per target ---
$written = 0

foreach ($p in $targets) {
    $changes = New-ChangesFromFindings -Principal $p

    if ($changes.Count -eq 0) {
        Write-Host "    [SKIP] $($p.PrincipalName) - no actionable findings" -ForegroundColor DarkYellow
        continue
    }

    # Safe filename: strip anything that isn't alnum/dash/underscore
    $safeName = ($p.PrincipalName -replace '[^A-Za-z0-9\-_]+', '_').Trim('_')
    if (-not $safeName) { $safeName = $p.PrincipalId }
    $fileName = "$safeName.scenario.json"
    $filePath = Join-Path $ScenariosFolder $fileName

    $scenario = [PSCustomObject]@{
        Name        = "Auto-generated remediation for $($p.PrincipalName) ($($p.Tier), score $($p.Score))"
        Description = "Derived from RiskScoreReport. Targets all actionable findings for this principal."
        Generated   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Source      = $ScoreReportPath
        Changes     = $changes
    }

    $scenario | ConvertTo-Json -Depth 6 | Out-File $filePath -Encoding UTF8
    Write-Host "    [OK] $fileName  ($($changes.Count) change(s))" -ForegroundColor Green
    $written++
}

# --- Summary ---
Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  SCENARIO GENERATION COMPLETE" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  Folder  : $ScenariosFolder"
Write-Host "  MinTier : $MinTier"
Write-Host "  Written : $written scenario file(s)"
Write-Host ""
Write-Host "[OK] Feed any of these into:" -ForegroundColor Green
Write-Host "       .\scripts\RiskEngine\Invoke-WhatIfSimulation.ps1 -ScenarioPath <file>" -ForegroundColor Gray
Write-Host "       .\scripts\Remediation\Invoke-EntraRemediation.ps1 -ScenarioPath <file>" -ForegroundColor Gray