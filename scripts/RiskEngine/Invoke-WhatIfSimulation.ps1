<#
.SYNOPSIS
    Simulates remediation scenarios against the current risk report.

.DESCRIPTION
    Loads the baseline PIM + permanent-role JSON reports and a user-provided
    scenario file describing proposed changes. Applies the changes in-memory,
    re-runs the weighted scoring logic, and prints a before/after comparison.

    No changes are made to Microsoft Entra ID. This is a pure simulation.

.PARAMETER ScenarioPath
    Path to the scenario JSON file. Defaults to ./scenarios/example-scenario.json

.PARAMETER PIMReportPath
    Path to PIMEligibilityReport.json. Defaults to ./output/PIMEligibilityReport.json

.PARAMETER PermanentReportPath
    Path to PermanentRoleReport.json. Defaults to ./output/PermanentRoleReport.json

.PARAMETER BaselineScorePath
    Optional path to the baseline RiskScoreReport.json for reference.
    Defaults to ./output/RiskScoreReport.json

.EXAMPLE
    .\Invoke-WhatIfSimulation.ps1
    .\Invoke-WhatIfSimulation.ps1 -ScenarioPath ./scenarios/remove-alice-admin.json

.NOTES
    Does not require Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$ScenarioPath        = "./scenarios/example-scenario.json",
    [string]$PIMReportPath       = "./output/PIMEligibilityReport.json",
    [string]$PermanentReportPath = "./output/PermanentRoleReport.json",
    [string]$BaselineScorePath   = "./output/RiskScoreReport.json"
)

# --- Validate inputs ---
$missing = @()
foreach ($p in @($ScenarioPath, $PIMReportPath, $PermanentReportPath)) {
    if (-not (Test-Path $p)) { $missing += $p }
}
if ($missing.Count -gt 0) {
    Write-Error "Missing required file(s):`n  $($missing -join "`n  ")"
    return
}

Write-Host "[*] Loading baseline reports and scenario..." -ForegroundColor Cyan
$pim        = Get-Content $PIMReportPath       -Raw | ConvertFrom-Json
$permanent  = Get-Content $PermanentReportPath -Raw | ConvertFrom-Json
$scenario   = Get-Content $ScenarioPath        -Raw | ConvertFrom-Json

if ($pim       -isnot [array]) { $pim       = @($pim) }
if ($permanent -isnot [array]) { $permanent = @($permanent) }
if ($null -eq $scenario.Changes) { $scenario.Changes = @() }

# --- Shared constants ---
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

# --- Shared scoring function used for both baseline and simulated runs ---
function Get-ScoredPrincipals {
    param(
        [array]$PimData,
        [array]$PermanentData
    )

    $principals = @{}

    function Get-OrCreate {
        param($Id, $Name)
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

    foreach ($f in $PermanentData) {
        $p = Get-OrCreate $f.PrincipalId $f.PrincipalName
        if ($highPrivilegeRoles -contains $f.RoleName) {
            $p.Score += 50
            $p.HighPrivRoleCount++
        } else {
            $p.Score += 25
        }
        $p.Findings += "PermanentRole:$($f.RoleName)"
    }

    foreach ($f in $PimData) {
        $p = Get-OrCreate $f.PrincipalId $f.PrincipalName
        $isHigh = $highPrivilegeRoles -contains $f.RoleName
        if ($f.AssignmentType -eq "Active" -and $isHigh) {
            $p.Score += 20; $p.HighPrivRoleCount++
        }
        elseif ($f.AssignmentType -eq "Eligible" -and $isHigh) {
            $p.Score += 10; $p.HighPrivRoleCount++
        }
        elseif ($f.ExpirationType -eq "NoExpiration" -or $null -eq $f.EndDateTime) {
            $p.Score += 5
        }
        else {
            $p.Score += 2
        }
        $p.Findings += "PIM:$($f.AssignmentType):$($f.RoleName)"
    }

    foreach ($key in $principals.Keys) {
        $p = $principals[$key]
        if ($p.HighPrivRoleCount -ge 3) {
            $p.Score = [math]::Round($p.Score * 1.5)
        }
        if ($p.Score -gt 100) { $p.Score = 100 }

        if     ($p.Score -ge 80) { $tier = "Critical" }
        elseif ($p.Score -ge 50) { $tier = "High" }
        elseif ($p.Score -ge 25) { $tier = "Medium" }
        else                     { $tier = "Low" }

        $p | Add-Member -NotePropertyName Tier         -NotePropertyValue $tier -Force
        $p | Add-Member -NotePropertyName FindingCount -NotePropertyValue $p.Findings.Count -Force
    }

    return $principals.Values | Sort-Object Score -Descending
}

# --- Compute BASELINE scores ---
$before = Get-ScoredPrincipals -PimData $pim -PermanentData $permanent

# --- Apply scenario changes in-memory ---
Write-Host "[*] Applying $($scenario.Changes.Count) change(s) from scenario..." -ForegroundColor Cyan

$pimSim       = @($pim       | ForEach-Object { $_ })
$permanentSim = @($permanent | ForEach-Object { $_ })

foreach ($change in $scenario.Changes) {
    switch ($change.Action) {
        "ConvertPermanentToEligible" {
            # Remove the permanent finding
            $permanentSim = @($permanentSim | Where-Object {
                -not ($_.PrincipalId -eq $change.PrincipalId -and $_.RoleName -eq $change.RoleName)
            })
            # Add an eligible PIM finding in its place
            $pimSim += [PSCustomObject]@{
                AssignmentType   = "Eligible"
                PrincipalId      = $change.PrincipalId
                PrincipalName    = ($permanent | Where-Object { $_.PrincipalId -eq $change.PrincipalId } | Select-Object -First 1).PrincipalName
                RoleName         = $change.RoleName
                RoleDefinitionId = ""
                ExpirationType   = "AfterDuration"
                EndDateTime      = (Get-Date).AddDays(90).ToString("yyyy-MM-ddTHH:mm:ssZ")
                Risk             = "Medium"
                Reason           = "Simulated: converted from permanent to eligible"
                Discovered       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }
        "RemoveEligible" {
            $pimSim = @($pimSim | Where-Object {
                -not ($_.PrincipalId -eq $change.PrincipalId -and
                      $_.RoleName -eq $change.RoleName -and
                      $_.AssignmentType -eq "Eligible")
            })
        }
        "RemoveActive" {
            $pimSim = @($pimSim | Where-Object {
                -not ($_.PrincipalId -eq $change.PrincipalId -and
                      $_.RoleName -eq $change.RoleName -and
                      $_.AssignmentType -eq "Active")
            })
        }
        "AddEligible" {
            $pimSim += [PSCustomObject]@{
                AssignmentType   = "Eligible"
                PrincipalId      = $change.PrincipalId
                PrincipalName    = $change.PrincipalName
                RoleName         = $change.RoleName
                RoleDefinitionId = ""
                ExpirationType   = "AfterDuration"
                EndDateTime      = (Get-Date).AddDays(90).ToString("yyyy-MM-ddTHH:mm:ssZ")
                Risk             = "Medium"
                Reason           = "Simulated: new eligible assignment"
                Discovered       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }
        default {
            Write-Warning "Unknown action '$($change.Action)' - skipping."
        }
    }
}

# --- Compute SIMULATED scores ---
$after = Get-ScoredPrincipals -PimData $pimSim -PermanentData $permanentSim

# --- Build comparison ---
$allIds = @($before.PrincipalId + $after.PrincipalId) | Sort-Object -Unique

$comparison = foreach ($id in $allIds) {
    $b = $before | Where-Object { $_.PrincipalId -eq $id } | Select-Object -First 1
    $a = $after  | Where-Object { $_.PrincipalId -eq $id } | Select-Object -First 1

    $name       = if ($a) { $a.PrincipalName } elseif ($b) { $b.PrincipalName } else { $id }
    $beforeScore= if ($b) { $b.Score } else { 0 }
    $afterScore = if ($a) { $a.Score } else { 0 }

    [PSCustomObject]@{
        PrincipalName = $name
        PrincipalId   = $id
        BeforeScore   = $beforeScore
        AfterScore    = $afterScore
        Delta         = $afterScore - $beforeScore
        BeforeTier    = if ($b) { $b.Tier } else { "-" }
        AfterTier     = if ($a) { $a.Tier } else { "-" }
    }
}

$comparison = $comparison | Sort-Object BeforeScore -Descending

# --- Console output ---
Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  WHAT-IF SIMULATION: $($scenario.Name)" -ForegroundColor Magenta
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  $($scenario.Description)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Changes applied:" -ForegroundColor Cyan
foreach ($c in $scenario.Changes) {
    Write-Host "    - $($c.Action) : $($c.PrincipalId) / $($c.RoleName)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  BEFORE / AFTER COMPARISON" -ForegroundColor Cyan
Write-Host ("  " + ("-" * 66)) -ForegroundColor DarkGray
$comparison | Format-Table PrincipalName, BeforeScore, AfterScore, Delta, BeforeTier, AfterTier -AutoSize

$totalBefore = ($comparison | Measure-Object -Property BeforeScore -Sum).Sum
$totalAfter  = ($comparison | Measure-Object -Property AfterScore  -Sum).Sum
$deltaTotal  = $totalAfter - $totalBefore

Write-Host "  Aggregate risk score:  $totalBefore  ->  $totalAfter  (delta $deltaTotal)" -ForegroundColor Yellow
Write-Host ""
Write-Host "[DONE] This was a simulation only - no changes were made to Entra ID." -ForegroundColor Green