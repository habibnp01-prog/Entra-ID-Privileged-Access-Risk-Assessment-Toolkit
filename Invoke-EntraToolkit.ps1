<#
.SYNOPSIS
    Single unified entry point for the Entra ID Privileged Access & Identity Risk Toolkit.

.DESCRIPTION
    Self-contained, integrated CLI that orchestrates every capability of the
    toolkit. Auto-detects missing prerequisites and prompts for installation
    when running interactively.

    Every action is controlled-destruction-safe:
      - Read-only actions never ask for confirmation.
      - Write actions (Remediate -Apply) show a preview and require typed
        confirmation ("yes") unless -NonInteractive + -Force are set.

    ACTIONS:
      Status      - Show toolkit state (no work)                          [local]
      Discover    - Assessment (PIM + permanent + scoring)                [Graph READ]
      Plan        - Markdown remediation plan                             [local]
      Scenarios   - Auto-generate scenarios from risk report              [local]
      WhatIf      - Simulate a scenario                                   [local]
      Remediate   - Apply a scenario (preview + confirmation required)    [Graph RW]
      Revalidate  - Diff baseline vs current                              [local]
      Audit       - Export CSV + HTML bundle                              [local]
      Dashboard   - Self-contained interactive HTML dashboard             [local]
      Full        - Discover + Plan + Scenarios + Dashboard + Audit       [Graph READ]

.PARAMETER Action
    One of the actions listed above.

.PARAMETER OutputFolder
    Output folder. Defaults to <repo>/output

.PARAMETER ScenarioFolder
    Scenarios folder. Defaults to <repo>/scenarios/generated

.PARAMETER ScenarioPath
    Scenario file for WhatIf or Remediate.

.PARAMETER MinTier
    Minimum tier for Plan/Scenarios/Full. Critical, High, Medium, Low.

.PARAMETER Apply
    For Remediate: actually write to the tenant. Requires typed confirmation.

.PARAMETER Force
    Skip the typed confirmation. Only valid with -NonInteractive.

.PARAMETER SkipGraphConnect
    Do not attempt Connect-MgGraph.

.PARAMETER NonInteractive
    Suppress all prompts. Missing prerequisites become hard errors.

.PARAMETER AutoInstall
    Install missing PowerShell modules without asking.

.EXAMPLE
    .\Invoke-EntraToolkit.ps1 -Action Status
    .\Invoke-EntraToolkit.ps1 -Action Discover
    .\Invoke-EntraToolkit.ps1 -Action Dashboard
    .\Invoke-EntraToolkit.ps1 -Action Full -MinTier Medium
    .\Invoke-EntraToolkit.ps1 -Action Remediate -ScenarioPath <file> -Apply
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Status","Discover","Plan","Scenarios","WhatIf","Remediate","Revalidate","Audit","Dashboard","Full")]
    [string]$Action,

    [string]$OutputFolder   = "",
    [string]$ScenarioFolder = "",
    [string]$ScenarioPath   = "",

    [ValidateSet("Critical","High","Medium","Low")]
    [string]$MinTier = "Medium",

    [switch]$Apply,
    [switch]$Force,
    [switch]$SkipGraphConnect,
    [switch]$NonInteractive,
    [switch]$AutoInstall
)

# =========================================================
# 0. Paths
# =========================================================
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }
$repoRoot = $scriptRoot

if (-not $OutputFolder)   { $OutputFolder   = Join-Path $repoRoot "output" }
if (-not $ScenarioFolder) { $ScenarioFolder = Join-Path $repoRoot "scenarios\generated" }

$S_assess     = Join-Path $repoRoot "scripts\Invoke-EntraRiskAssessment.ps1"
$S_plan       = Join-Path $repoRoot "scripts\Remediation\New-EntraRemediationPlan.ps1"
$S_scenarios  = Join-Path $repoRoot "scripts\Remediation\New-AutoRemediationScenarios.ps1"
$S_whatif     = Join-Path $repoRoot "scripts\RiskEngine\Invoke-WhatIfSimulation.ps1"
$S_remediate  = Join-Path $repoRoot "scripts\Remediation\Invoke-EntraRemediation.ps1"
$S_reval      = Join-Path $repoRoot "scripts\Remediation\Compare-EntraRemediationOutcome.ps1"
$S_audit      = Join-Path $repoRoot "scripts\Remediation\Export-EntraAuditBundle.ps1"
$S_dashboard  = Join-Path $repoRoot "scripts\Remediation\New-EntraDashboard.ps1"

$F_score     = Join-Path $OutputFolder "RiskScoreReport.json"
$F_scoreBase = Join-Path $OutputFolder "RiskScoreReport.baseline.json"
$F_pim       = Join-Path $OutputFolder "PIMEligibilityReport.json"
$F_perm      = Join-Path $OutputFolder "PermanentRoleReport.json"
$F_plan      = Join-Path $OutputFolder "RemediationPlan.md"
$F_auditLog  = Join-Path $OutputFolder "RemediationAudit.log"
$F_dashboard = Join-Path $OutputFolder "dashboard.html"

# =========================================================
# Helpers
# =========================================================
function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor DarkGray
}

function Write-Fix {
    param([string]$What, [string[]]$Steps)
    Write-Host ""
    Write-Host "[!] $What" -ForegroundColor Yellow
    $i = 1
    foreach ($s in $Steps) {
        Write-Host "    $i. $s" -ForegroundColor Gray
        $i++
    }
    Write-Host ""
}

function Test-Interactive {
    if ($NonInteractive) { return $false }
    if (-not [Environment]::UserInteractive) { return $false }
    return $true
}

function Ask-YesNo {
    param([string]$Prompt, [bool]$DefaultNo = $true)
    if (-not (Test-Interactive)) { return $false }
    $hint = if ($DefaultNo) { "[y/N]" } else { "[Y/n]" }
    $resp = Read-Host "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($resp)) { return (-not $DefaultNo) }
    return ($resp.Trim().ToLower() -in @("y","yes"))
}

function Ask-TypedConfirm {
    param([string]$Prompt, [string]$Expected)
    if (-not (Test-Interactive)) { return $false }
    Write-Host ""
    Write-Host "  To proceed, type exactly:  " -NoNewline -ForegroundColor Yellow
    Write-Host $Expected -ForegroundColor Red
    $resp = Read-Host "  >"
    return ($resp -ceq $Expected)
}

function Assert-Script {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Required toolkit script not found: $Path"
    }
}

# =========================================================
# Prerequisite checks
# =========================================================
function Ensure-Folders {
    foreach ($f in @($OutputFolder, $ScenarioFolder)) {
        if (-not (Test-Path $f)) {
            New-Item -ItemType Directory -Path $f -Force | Out-Null
        }
    }
}

function Install-ModuleCurrentUser {
    param([string]$ModuleName)
    Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

function Ensure-Module {
    param(
        [string]$ModuleName,
        [string]$Reason = ""
    )

    if (Get-Module -Name $ModuleName) { return $true }

    if (Get-Module -ListAvailable -Name $ModuleName) {
        try {
            Import-Module $ModuleName -ErrorAction Stop -Force
            Write-Host "[*] Imported module: $ModuleName" -ForegroundColor DarkGray
            return $true
        } catch {
            Write-Host "[!] $ModuleName is installed but failed to import." -ForegroundColor Yellow
            Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkGray
            Write-Host "    Attempting reinstall with -Scope CurrentUser..." -ForegroundColor Cyan
            try {
                Install-ModuleCurrentUser -ModuleName $ModuleName
                Import-Module $ModuleName -ErrorAction Stop -Force
                Write-Host "[OK] Reinstalled and imported $ModuleName" -ForegroundColor Green
                return $true
            } catch {
                Write-Host "[X] Reinstall failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Fix "Manual repair required." @(
                    "Uninstall-Module $ModuleName -AllVersions -Force",
                    "Install-Module $ModuleName -Scope CurrentUser -Force"
                )
                return $false
            }
        }
    }

    Write-Host ""
    Write-Host "[!] Required module not installed: $ModuleName" -ForegroundColor Yellow
    if ($Reason) { Write-Host "    Reason: $Reason" -ForegroundColor Gray }

    if ($AutoInstall) {
        Write-Host "[*] Installing $ModuleName (AutoInstall, CurrentUser scope)..." -ForegroundColor Cyan
        try {
            Install-ModuleCurrentUser -ModuleName $ModuleName
            Import-Module $ModuleName -ErrorAction Stop -Force
            Write-Host "[OK] Installed and imported $ModuleName" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[X] Failed: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }

    if (-not (Test-Interactive)) {
        Write-Fix "Cannot install in non-interactive mode." @(
            "Run interactively, or pass -AutoInstall.",
            "Or install manually: Install-Module $ModuleName -Scope CurrentUser -Force"
        )
        return $false
    }

    if (Ask-YesNo "Install $ModuleName now? (CurrentUser scope)" $false) {
        try {
            Install-ModuleCurrentUser -ModuleName $ModuleName
            Import-Module $ModuleName -ErrorAction Stop -Force
            Write-Host "[OK] Installed and imported $ModuleName" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[X] Failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    Try manually in an elevated PowerShell:" -ForegroundColor Yellow
            Write-Host "      Install-Module $ModuleName -Scope CurrentUser -Force" -ForegroundColor Gray
            return $false
        }
    }

    Write-Fix "Module required to continue." @(
        "Install-Module $ModuleName -Scope CurrentUser -Force"
    )
    return $false
}

function Ensure-Graph {
    if ($SkipGraphConnect) {
        Write-Host "[*] Skipping Graph connect (-SkipGraphConnect)" -ForegroundColor DarkGray
        return $true
    }

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.Governance",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )

    foreach ($m in $requiredModules) {
        if (-not (Ensure-Module -ModuleName $m -Reason "Required for Entra ID discovery")) {
            return $false
        }
    }

    if (Get-MgContext) {
        Write-Host "[*] Graph context OK" -ForegroundColor Green
        return $true
    }

    if (-not (Test-Interactive)) {
        Write-Fix "Not connected to Graph and running non-interactively." @(
            "Pre-authenticate before the run: Connect-MgGraph -Scopes RoleManagement.Read.Directory,Directory.Read.All",
            "Or omit -NonInteractive to allow interactive sign-in."
        )
        return $false
    }

    Write-Host ""
    Write-Host "[*] You are not signed in to Microsoft Graph." -ForegroundColor Yellow
    Write-Host "    Scopes required: RoleManagement.Read.Directory, Directory.Read.All" -ForegroundColor Gray

    if (-not (Ask-YesNo "Sign in to Microsoft Graph now?" $false)) {
        Write-Host "[X] Cancelled by user." -ForegroundColor Red
        return $false
    }

    try {
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All" -NoWelcome
        Write-Host "[OK] Connected to Microsoft Graph" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[X] Sign-in failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# =========================================================
# Actions
# =========================================================
function Invoke-ActionStatus {
    Write-Header "TOOLKIT STATUS"

    $rows = @()
    foreach ($c in @(
        @{ Name = "Score report";     Path = $F_score     }
        @{ Name = "Baseline report";  Path = $F_scoreBase }
        @{ Name = "PIM report";       Path = $F_pim       }
        @{ Name = "Permanent report"; Path = $F_perm      }
        @{ Name = "Remediation plan"; Path = $F_plan      }
        @{ Name = "Dashboard";        Path = $F_dashboard }
        @{ Name = "Audit log";        Path = $F_auditLog  }
    )) {
        $exists = Test-Path $c.Path
        $rows += [PSCustomObject]@{
            Artifact = $c.Name
            Status   = if ($exists) { "present" } else { "missing" }
            Path     = if ($exists) { $c.Path } else { "-" }
        }
    }
    $rows | Format-Table -AutoSize

    $scenarios = @(Get-ChildItem $ScenarioFolder -Filter "*.json" -ErrorAction SilentlyContinue)
    Write-Host "  Scenarios : $($scenarios.Count) in $ScenarioFolder" -ForegroundColor Cyan

    if (Test-Path $F_score) {
        $scored = Get-Content $F_score -Raw | ConvertFrom-Json
        if ($scored -isnot [array]) { $scored = @($scored) }
        $crit = @($scored | Where-Object { $_.Tier -eq "Critical" }).Count
        $high = @($scored | Where-Object { $_.Tier -eq "High" }).Count
        Write-Host "  Identities : $($scored.Count)  (Critical: $crit / High: $high)" -ForegroundColor Cyan
    } else {
        Write-Host "  Identities : (no score report yet)" -ForegroundColor Gray
    }
}

function Invoke-ActionDiscover {
    Assert-Script $S_assess
    if (-not (Ensure-Graph)) { throw "Graph prerequisites not met." }
    & $S_assess -OutputFolder $OutputFolder
}

function Invoke-ActionPlan {
    Assert-Script $S_plan
    if (-not (Test-Path $F_score)) {
        Write-Fix "Risk score report missing at $F_score." @(
            "Run: .\Invoke-EntraToolkit.ps1 -Action Discover"
        )
        throw "Cannot generate plan without a score report."
    }
    & $S_plan -ScoreReportPath $F_score -OutputPath $F_plan
}

function Invoke-ActionScenarios {
    Assert-Script $S_scenarios
    if (-not (Test-Path $F_score)) {
        Write-Fix "Risk score report missing at $F_score." @(
            "Run: .\Invoke-EntraToolkit.ps1 -Action Discover"
        )
        throw "Cannot generate scenarios without a score report."
    }
    & $S_scenarios -ScoreReportPath $F_score -ScenariosFolder $ScenarioFolder -MinTier $MinTier
}

function Invoke-ActionWhatIf {
    Assert-Script $S_whatif
    if (-not $ScenarioPath) {
        $first = Get-ChildItem $ScenarioFolder -Filter "*.json" -ErrorAction SilentlyContinue |
                 Sort-Object Name | Select-Object -First 1
        if (-not $first) {
            Write-Fix "No scenarios found." @(
                "Run: .\Invoke-EntraToolkit.ps1 -Action Scenarios -MinTier Medium"
            )
            throw "Cannot run What-If without a scenario."
        }
        $ScenarioPath = $first.FullName
        Write-Host "[*] No -ScenarioPath given; using $ScenarioPath" -ForegroundColor DarkGray
    }
    if (-not (Test-Path $ScenarioPath)) { throw "Scenario not found: $ScenarioPath" }

    & $S_whatif -ScenarioPath $ScenarioPath `
                -PIMReportPath $F_pim `
                -PermanentReportPath $F_perm `
                -BaselineScorePath $F_score
}

function Invoke-ActionRemediate {
    Assert-Script $S_remediate
    if (-not $ScenarioPath) {
        Write-Fix "Remediate requires a scenario file." @(
            "Pass -ScenarioPath <file>",
            "Or generate one: .\Invoke-EntraToolkit.ps1 -Action Scenarios -MinTier Medium"
        )
        throw "-Action Remediate requires -ScenarioPath."
    }
    if (-not (Test-Path $ScenarioPath)) { throw "Scenario not found: $ScenarioPath" }

    $scenario = Get-Content $ScenarioPath -Raw | ConvertFrom-Json
    $changes  = @($scenario.Changes)

    if (-not $Apply) {
        Write-Header "REMEDIATION - DRY RUN"
        Write-Host "  Scenario : $($scenario.Name)"
        Write-Host "  Changes  : $($changes.Count)"
        Write-Host ""
        Write-Host "  The following changes WOULD be applied in live mode:" -ForegroundColor Yellow
        Write-Host ""
        $i = 1
        foreach ($c in $changes) {
            Write-Host "    $i. [$($c.Action)] role='$($c.RoleName)' principal='$($c.PrincipalId)'" -ForegroundColor Gray
            $i++
        }
        Write-Host ""
        Write-Host "[i] To actually apply these, re-run with -Apply." -ForegroundColor Cyan
        Write-Host "[i] You will be asked to type 'yes' to confirm." -ForegroundColor Cyan

        & $S_remediate -ScenarioPath $ScenarioPath
        return
    }

    Write-Header "REMEDIATION - LIVE APPLY (CONTROLLED)"

    if (-not (Ensure-Graph)) { throw "Graph prerequisites not met." }

    Write-Host ""
    Write-Host "  Scenario : $($scenario.Name)" -ForegroundColor White
    Write-Host "  Changes  : $($changes.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "  THE FOLLOWING WILL BE WRITTEN TO YOUR TENANT:" -ForegroundColor Red
    Write-Host ""
    $i = 1
    foreach ($c in $changes) {
        $color = if ($c.Action -eq "ConvertPermanentToEligible") { "Yellow" } else { "Red" }
        Write-Host "    $i. [$($c.Action)] role='$($c.RoleName)' principal='$($c.PrincipalId)'" -ForegroundColor $color
        $i++
    }

    Write-Host ""
    Write-Host "  Safety guarantees active:" -ForegroundColor Green
    Write-Host "    - Last permanent Global Admin cannot be removed."
    Write-Host "    - Every action is logged to $F_auditLog"
    Write-Host ""

    if ($NonInteractive -and $Force) {
        Write-Host "[*] NonInteractive + Force set: proceeding without typed confirmation." -ForegroundColor Yellow
    } else {
        if (-not (Ask-TypedConfirm -Prompt "Confirm live remediation." -Expected "yes")) {
            Write-Host "[X] Not confirmed. No changes were made." -ForegroundColor Red
            return
        }
    }

    Write-Host ""
    Write-Host "[*] Applying remediation to tenant..." -ForegroundColor Cyan
    & $S_remediate -ScenarioPath $ScenarioPath -Apply -Confirm
}

function Invoke-ActionRevalidate {
    Assert-Script $S_reval
    if (-not (Test-Path $F_scoreBase)) {
        Write-Fix "Baseline score report missing." @(
            "Snapshot current score as baseline:",
            "  Copy-Item '$F_score' '$F_scoreBase'"
        )
        throw "No baseline to compare against."
    }
    if (-not (Test-Path $F_score)) {
        Write-Fix "Current score report missing." @(
            "Run: .\Invoke-EntraToolkit.ps1 -Action Discover"
        )
        throw "No current score to compare."
    }
    & $S_reval -BaselinePath $F_scoreBase -CurrentPath $F_score
}

function Invoke-ActionAudit {
    Assert-Script $S_audit
    & $S_audit -OutputFolder $OutputFolder -BundleRoot $OutputFolder
}

function Invoke-ActionDashboard {
    Assert-Script $S_dashboard
    if (-not (Test-Path $F_score)) {
        Write-Fix "Risk score report missing at $F_score." @(
            "Run: .\Invoke-EntraToolkit.ps1 -Action Discover"
        )
        throw "Cannot generate dashboard without a score report."
    }
    & $S_dashboard -OutputFolder $OutputFolder -ScenarioFolder $ScenarioFolder
}

function Invoke-ActionFull {
    Write-Header "FULL READ-ONLY PIPELINE"
    Invoke-ActionDiscover
    Invoke-ActionPlan
    Invoke-ActionScenarios
    Invoke-ActionDashboard
    Invoke-ActionAudit
    Write-Host ""
    Write-Host "[OK] Full read-only pipeline complete." -ForegroundColor Green
}

# =========================================================
# Pre-flight
# =========================================================
Ensure-Folders

# =========================================================
# Dispatch
# =========================================================
$startedAt = Get-Date

try {
    switch ($Action) {
        "Status"     { Invoke-ActionStatus }
        "Discover"   { Invoke-ActionDiscover }
        "Plan"       { Invoke-ActionPlan }
        "Scenarios"  { Invoke-ActionScenarios }
        "WhatIf"     { Invoke-ActionWhatIf }
        "Remediate"  { Invoke-ActionRemediate }
        "Revalidate" { Invoke-ActionRevalidate }
        "Audit"      { Invoke-ActionAudit }
        "Dashboard"  { Invoke-ActionDashboard }
        "Full"       { Invoke-ActionFull }
    }
} catch {
    Write-Host ""
    Write-Host "[X] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$elapsed = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
Write-Host ""
Write-Host "[OK] Action '$Action' completed in ${elapsed}s" -ForegroundColor Green
exit 0