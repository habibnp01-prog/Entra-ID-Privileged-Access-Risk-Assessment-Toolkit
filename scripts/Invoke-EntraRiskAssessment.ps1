<#
.SYNOPSIS
    End-to-end runner for the Entra ID Privileged Access & Identity Risk Assessment Toolkit.

.DESCRIPTION
    Orchestrates the full assessment pipeline:
      1. PIM eligibility + active assignment discovery (2.1)
      2. Permanent (non-PIM) role assignment detection (2.2)
      3. Weighted identity risk scoring (2.3)

    Produces a consolidated console summary plus JSON reports in ./output/.

.PARAMETER OutputFolder
    Folder where JSON reports are written. Defaults to ./output

.PARAMETER SkipDiscovery
    Skip Graph-connected discovery steps and reuse existing JSON files in
    OutputFolder. Useful for iterating on scoring logic without re-querying
    the tenant.

.PARAMETER HighPrivilegeOnly
    Pass-through to the permanent-role detector. Only reports high-privilege
    permanent assignments.

.EXAMPLE
    .\Invoke-EntraRiskAssessment.ps1
    .\Invoke-EntraRiskAssessment.ps1 -SkipDiscovery
    .\Invoke-EntraRiskAssessment.ps1 -OutputFolder C:\Reports\EntraRisk

.NOTES
    Requires Microsoft.Graph module for the discovery steps.
    If -SkipDiscovery is used, no Graph connection is required.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "./output",
    [switch]$SkipDiscovery,
    [switch]$HighPrivilegeOnly
)

# --- Resolve script root so it works from any working directory ---
$scriptRoot = $PSScriptRoot
$riskEngineDir = Join-Path $scriptRoot "RiskEngine"

# --- Ensure output folder exists ---
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$pimReport   = Join-Path $OutputFolder "PIMEligibilityReport.json"
$permReport  = Join-Path $OutputFolder "PermanentRoleReport.json"
$scoreReport = Join-Path $OutputFolder "RiskScoreReport.json"

$global:startedAt = Get-Date

function Write-Step {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

# =========================================================
# STEP 1 + 2 : Discovery (PIM + Permanent role assignments)
# =========================================================
if (-not $SkipDiscovery) {
    Write-Step "STEP 1/3 - Discovering PIM eligibility and active assignments"

    $pimScript = Join-Path $riskEngineDir "Get-EntraPIMEligibilityReport.ps1"
    if (-not (Test-Path $pimScript)) {
        Write-Error "Missing script: $pimScript"
        return
    }
    & $pimScript -OutputPath $pimReport

    Write-Step "STEP 2/3 - Detecting permanent (non-PIM) role assignments"

    $permScript = Join-Path $riskEngineDir "Get-EntraPermanentRoleReport.ps1"
    if (-not (Test-Path $permScript)) {
        Write-Error "Missing script: $permScript"
        return
    }
    if ($HighPrivilegeOnly) {
        & $permScript -OutputPath $permReport -HighPrivilegeOnly
    } else {
        & $permScript -OutputPath $permReport
    }
}
else {
    Write-Step "SKIP DISCOVERY - Reusing existing JSON files in $OutputFolder"

    if (-not (Test-Path $pimReport)) {
        Write-Error "Missing $pimReport. Run without -SkipDiscovery first."
        return
    }
    if (-not (Test-Path $permReport)) {
        Write-Error "Missing $permReport. Run without -SkipDiscovery first."
        return
    }
}

# =========================================================
# STEP 3 : Scoring
# =========================================================
Write-Step "STEP 3/3 - Computing weighted identity risk scores"

$scoreScript = Join-Path $riskEngineDir "Get-EntraRiskScore.ps1"
if (-not (Test-Path $scoreScript)) {
    Write-Error "Missing script: $scoreScript"
    return
}
& $scoreScript -PIMReportPath $pimReport `
               -PermanentReportPath $permReport `
               -OutputPath $scoreReport

# =========================================================
# Consolidated summary
# =========================================================
Write-Step "ASSESSMENT SUMMARY"

$elapsed = (Get-Date) - $global:startedAt

if (Test-Path $scoreReport) {
    $scored = Get-Content $scoreReport -Raw | ConvertFrom-Json
    if ($scored -isnot [array]) { $scored = @($scored) }

    $crit = @($scored | Where-Object { $_.Tier -eq "Critical" }).Count
    $high = @($scored | Where-Object { $_.Tier -eq "High" }).Count
    $med  = @($scored | Where-Object { $_.Tier -eq "Medium" }).Count
    $low  = @($scored | Where-Object { $_.Tier -eq "Low" }).Count

    Write-Host "  Reports written to: $OutputFolder"
    Write-Host "    - PIMEligibilityReport.json"
    Write-Host "    - PermanentRoleReport.json"
    Write-Host "    - RiskScoreReport.json"
    Write-Host ""
    Write-Host "  Principals scored : $($scored.Count)"
    Write-Host "  Critical          : $crit" -ForegroundColor Red
    Write-Host "  High              : $high" -ForegroundColor DarkYellow
    Write-Host "  Medium            : $med"  -ForegroundColor Yellow
    Write-Host "  Low               : $low"  -ForegroundColor Green
    Write-Host ""
    Write-Host "  Elapsed           : $([math]::Round($elapsed.TotalSeconds,2))s"

    if ($scored.Count -gt 0) {
        Write-Host ""
        Write-Host "  TOP 5 RISK IDENTITIES" -ForegroundColor Magenta
        Write-Host ("  " + ("-" * 66)) -ForegroundColor DarkGray
        $scored | Select-Object -First 5 |
            Format-Table PrincipalName, Score, Tier, HighPrivRoleCount -AutoSize
    }
}
else {
    Write-Warning "Scoring report not found at $scoreReport"
}

Write-Host ""
Write-Host "[DONE]" -ForegroundColor Green