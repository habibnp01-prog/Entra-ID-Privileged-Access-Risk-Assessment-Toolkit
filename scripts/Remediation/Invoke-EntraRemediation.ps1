<#
.SYNOPSIS
    Applies remediation actions to Microsoft Entra ID with multi-layer safety guards.

.DESCRIPTION
    Reads a scenario file and applies the requested remediation actions to
    Entra ID with:
      - DryRun default (no writes)
      - Typed confirmation required for live
      - Last-GA guard
      - Full audit trail
      - Explicit write-scope enforcement (auto-reconnect if missing)

.PARAMETER ScenarioPath
    Path to the scenario JSON file. Required.

.PARAMETER AuditLogPath
    Path to the audit log. Defaults to ./output/RemediationAudit.log

.PARAMETER Apply
    Actually perform changes. Requires -Confirm.

.PARAMETER Confirm
    Must be set to $true IN ADDITION to -Apply.

.EXAMPLE
    .\Invoke-EntraRemediation.ps1 -ScenarioPath .\scenarios\example-scenario.json
    .\Invoke-EntraRemediation.ps1 -ScenarioPath .\scenarios\example-scenario.json -Apply -Confirm

.NOTES
    Requires Microsoft.Graph submodules + RoleManagement.ReadWrite.Directory scope.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScenarioPath,

    [string]$AuditLogPath = "./output/RemediationAudit.log",

    [switch]$Apply,
    [switch]$Confirm
)

# =========================================================
# Layer 1 : Mode determination
# =========================================================
$dryRun = -not $Apply.IsPresent

if ($Apply.IsPresent -and -not $Confirm.IsPresent) {
    Write-Error "Refusing to apply changes without -Confirm:`$true. Use -Apply -Confirm:`$true explicitly."
    return
}

# =========================================================
# Validate scenario
# =========================================================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    return
}

$scenario = Get-Content $ScenarioPath -Raw | ConvertFrom-Json
if ($null -eq $scenario.Changes) {
    Write-Error "Scenario has no 'Changes' array."
    return
}

# =========================================================
# Audit log helper
# =========================================================
$auditDir = Split-Path $AuditLogPath -Parent
if ($auditDir -and -not (Test-Path $auditDir)) {
    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
}

function Write-Audit {
    param(
        [string]$Action,
        [string]$PrincipalId,
        [string]$RoleName,
        [string]$Result,
        [string]$Mode,
        [string]$Detail = ""
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] | $Mode | $Action | principal=$PrincipalId | role=$RoleName | result=$Result"
    if ($Detail) { $line += " | detail=$Detail" }
    Add-Content -Path $AuditLogPath -Value $line -Encoding UTF8
    Write-Host "    $line" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
if ($dryRun) {
    Write-Host "  REMEDIATION EXECUTOR - DRY RUN MODE (no changes will be made)" -ForegroundColor Yellow
} else {
    Write-Host "  REMEDIATION EXECUTOR - LIVE MODE (changes will be applied!)" -ForegroundColor Red
}
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Scenario : $($scenario.Name)"
Write-Host "  Changes  : $($scenario.Changes.Count)"
Write-Host "  AuditLog : $AuditLogPath"
Write-Host ""

# =========================================================
# Ensure required Graph submodules are loaded (live mode only)
# =========================================================
if (-not $dryRun) {

    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.Governance",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )

    foreach ($m in $requiredModules) {
        if (-not (Get-Module -Name $m)) {
            if (Get-Module -ListAvailable -Name $m) {
                Import-Module $m -Force -ErrorAction Stop
            } else {
                Write-Error "Required module '$m' not installed. Run: Install-Module $m -Scope CurrentUser -Force"
                return
            }
        }
    }

    # ---- Enforce WRITE scope presence ----
    $REQUIRED_WRITE_SCOPE = "RoleManagement.ReadWrite.Directory"

    $ctx = Get-MgContext
    $hasWrite = $false
    if ($ctx -and $ctx.Scopes) {
        foreach ($s in $ctx.Scopes) {
            if ($s -ieq $REQUIRED_WRITE_SCOPE) { $hasWrite = $true; break }
        }
    }

    if (-not $hasWrite) {
        Write-Host "[!] Current Graph session lacks '$REQUIRED_WRITE_SCOPE'." -ForegroundColor Yellow
        Write-Host "    Current scopes: $($ctx.Scopes -join ', ')" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "[*] Reconnecting to Microsoft Graph with write scopes..." -ForegroundColor Cyan
        Write-Host "    You will be prompted to consent to '$REQUIRED_WRITE_SCOPE'." -ForegroundColor Gray
        Write-Host ""

        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

        try {
            Connect-MgGraph -Scopes @($REQUIRED_WRITE_SCOPE, "Directory.Read.All") -NoWelcome -ErrorAction Stop
        } catch {
            Write-Error "Graph reconnect failed: $($_.Exception.Message)"
            return
        }

        $ctx = Get-MgContext
        $hasWrite = $false
        if ($ctx -and $ctx.Scopes) {
            foreach ($s in $ctx.Scopes) {
                if ($s -ieq $REQUIRED_WRITE_SCOPE) { $hasWrite = $true; break }
            }
        }

        if (-not $hasWrite) {
            Write-Host ""
            Write-Host "[X] After reconnect, '$REQUIRED_WRITE_SCOPE' is STILL missing." -ForegroundColor Red
            Write-Host "    New scopes: $($ctx.Scopes -join ', ')" -ForegroundColor DarkGray
            Write-Host ""
            Write-FixBlock @"
Your tenant or account does not permit the write scope. Possible causes:
  1. Your account is not a Privileged Role Administrator or Global Administrator.
  2. Tenant admin consent is required for Microsoft Graph Command Line Tools.
  3. Conditional Access is downgrading the token.

Fixes:
  - Sign in with an account that holds Privileged Role Administrator.
  - Ask a tenant admin to grant admin consent for 'Microsoft Graph Command Line Tools'.
  - Check Conditional Access policies targeting the Graph PowerShell app.
"@
            Write-Audit -Action "PRECHECK" -PrincipalId "" -RoleName "" `
                        -Result "WRITE_SCOPE_MISSING" -Mode "LIVE" `
                        -Detail "required=$REQUIRED_WRITE_SCOPE"
            return
        }
    }

    Write-Host "[OK] Graph write scope present ('$REQUIRED_WRITE_SCOPE')" -ForegroundColor Green
}

# =========================================================
# FixBlock helper (used only for the write-scope failure path)
# =========================================================
function Write-FixBlock {
    param([string]$Text)
    Write-Host ""
    Write-Host $Text -ForegroundColor Yellow
    Write-Host ""
}

# =========================================================
# Helpers
# =========================================================
function Get-RoleDefinitionId {
    param([string]$RoleName)
    $def = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $def) { return $null }
    return $def.Id
}

function Test-LastPermanentGlobalAdmin {
    param([string]$PrincipalId)

    $gaDefId = Get-RoleDefinitionId -RoleName "Global Administrator"
    if (-not $gaDefId) { return $false }

    $allGa = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$gaDefId'" -All -ErrorAction SilentlyContinue
    $pimActive = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction SilentlyContinue

    $pimActiveIds = @{}
    foreach ($p in $pimActive) { if ($p.Id) { $pimActiveIds[$p.Id] = $true } }

    $permanentGas = @()
    foreach ($a in $allGa) {
        if ($pimActiveIds.ContainsKey($a.Id)) { continue }
        $permanentGas += $a
    }

    $targetIsGa = $permanentGas | Where-Object { $_.PrincipalId -eq $PrincipalId }
    if ($targetIsGa -and $permanentGas.Count -le 1) {
        return $true
    }
    return $false
}

function Get-PermanentAssignmentId {
    param([string]$PrincipalId, [string]$RoleDefinitionId)

    $all = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction SilentlyContinue
    $pimActive = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction SilentlyContinue
    $pimActiveIds = @{}
    foreach ($p in $pimActive) { if ($p.Id) { $pimActiveIds[$p.Id] = $true } }

    $match = $all | Where-Object {
        $_.PrincipalId      -eq $PrincipalId -and
        $_.RoleDefinitionId -eq $RoleDefinitionId -and
        -not $pimActiveIds.ContainsKey($_.Id)
    } | Select-Object -First 1

    if ($match) { return $match.Id }
    return $null
}

function Get-EligibleAssignmentId {
    param([string]$PrincipalId, [string]$RoleDefinitionId)

    $all = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction SilentlyContinue

    $match = $all | Where-Object {
        $_.PrincipalId      -eq $PrincipalId -and
        $_.RoleDefinitionId -eq $RoleDefinitionId
    } | Select-Object -First 1

    if ($match) { return $match.Id }
    return $null
}

function Get-ActiveAssignmentId {
    param([string]$PrincipalId, [string]$RoleDefinitionId)

    $all = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction SilentlyContinue

    $match = $all | Where-Object {
        $_.PrincipalId      -eq $PrincipalId -and
        $_.RoleDefinitionId -eq $RoleDefinitionId
    } | Select-Object -First 1

    if ($match) { return $match.Id }
    return $null
}

# =========================================================
# Process each change
# =========================================================
$processed = 0
$skipped   = 0
$failed    = 0
$mode      = if ($dryRun) { "DRYRUN" } else { "LIVE" }

foreach ($change in $scenario.Changes) {
    $processed++
    Write-Host ""
    Write-Host "[$processed/$($scenario.Changes.Count)] $($change.Action) - $($change.PrincipalId) / $($change.RoleName)" -ForegroundColor Cyan

    $roleDefId = $null
    if (-not $dryRun) {
        $roleDefId = Get-RoleDefinitionId -RoleName $change.RoleName
        if (-not $roleDefId) {
            Write-Warning "    Role definition '$($change.RoleName)' not found. Skipping."
            Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                        -Result "ROLE_NOT_FOUND" -Mode $mode
            $failed++
            continue
        }
    }

    if ($change.RoleName -eq "Global Administrator" -and -not $dryRun) {
        $isLast = Test-LastPermanentGlobalAdmin -PrincipalId $change.PrincipalId
        if ($isLast) {
            Write-Warning "    BLOCKED: this would remove the last permanent Global Administrator. Skipping."
            Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                        -Result "BLOCKED_LAST_GA" -Mode $mode -Detail "safety guard"
            $skipped++
            continue
        }
    }

    switch ($change.Action) {

        "ConvertPermanentToEligible" {
            if ($dryRun) {
                Write-Host "    [dryrun] Would CREATE eligible PIM assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Host "    [dryrun] Would REMOVE permanent assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                            -Result "SIMULATED" -Mode $mode
            } else {
                try {
                    $params = @{
                        Action           = "adminAssign"
                        Justification    = "Toolkit: convert permanent to eligible"
                        RoleDefinitionId = $roleDefId
                        DirectoryScopeId = "/"
                        PrincipalId      = $change.PrincipalId
                        ScheduleInfo     = @{
                            StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                            Expiration    = @{ Type = "NoExpiration" }
                        }
                    }
                    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                    Write-Host "    [OK] Eligible assignment created" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "ELIGIBLE_CREATED" -Mode $mode
                } catch {
                    Write-Warning "    [FAILED] Could not create eligible: $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED_ELIGIBLE_CREATE" -Mode $mode -Detail ($_.Exception.Message -replace '\s+',' ')
                    $failed++
                    continue
                }

                try {
                    $assignmentId = Get-PermanentAssignmentId -PrincipalId $change.PrincipalId -RoleDefinitionId $roleDefId
                    if (-not $assignmentId) {
                        Write-Host "    [SKIP] No permanent assignment found to remove" -ForegroundColor DarkYellow
                        Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                    -Result "NO_PERMANENT_FOUND" -Mode $mode
                        $skipped++
                        continue
                    }
                    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignmentId -ErrorAction Stop
                    Write-Host "    [OK] Permanent assignment removed" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "PERMANENT_REMOVED" -Mode $mode -Detail "assignmentId=$assignmentId"
                } catch {
                    Write-Warning "    [FAILED] Could not remove permanent: $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED_PERMANENT_REMOVE" -Mode $mode -Detail ($_.Exception.Message -replace '\s+',' ')
                    $failed++
                }
            }
        }

        "RemovePermanent" {
            if ($dryRun) {
                Write-Host "    [dryrun] Would REMOVE permanent assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                            -Result "SIMULATED" -Mode $mode
            } else {
                try {
                    $assignmentId = Get-PermanentAssignmentId -PrincipalId $change.PrincipalId -RoleDefinitionId $roleDefId
                    if (-not $assignmentId) {
                        Write-Host "    [SKIP] No permanent assignment found" -ForegroundColor DarkYellow
                        Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                    -Result "NO_PERMANENT_FOUND" -Mode $mode
                        $skipped++
                        continue
                    }
                    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignmentId -ErrorAction Stop
                    Write-Host "    [OK] Permanent assignment removed" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "PERMANENT_REMOVED" -Mode $mode -Detail "assignmentId=$assignmentId"
                } catch {
                    Write-Warning "    [FAILED] $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED" -Mode $mode -Detail ($_.Exception.Message -replace '\s+',' ')
                    $failed++
                }
            }
        }

        "RemoveEligible" {
            if ($dryRun) {
                Write-Host "    [dryrun] Would REMOVE eligible assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                            -Result "SIMULATED" -Mode $mode
            } else {
                try {
                    $eligibleId = Get-EligibleAssignmentId -PrincipalId $change.PrincipalId -RoleDefinitionId $roleDefId
                    if (-not $eligibleId) {
                        Write-Host "    [SKIP] No eligible assignment found" -ForegroundColor DarkYellow
                        Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                    -Result "NO_ELIGIBLE_FOUND" -Mode $mode
                        $skipped++
                        continue
                    }

                    $params = @{
                        Action           = "adminRemove"
                        Justification    = "Toolkit: remove eligible assignment"
                        RoleDefinitionId = $roleDefId
                        DirectoryScopeId = "/"
                        PrincipalId      = $change.PrincipalId
                    }
                    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                    Write-Host "    [OK] Eligible assignment removed" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "ELIGIBLE_REMOVED" -Mode $mode -Detail "eligibleId=$eligibleId"
                } catch {
                    Write-Warning "    [FAILED] Could not remove eligible: $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED_ELIGIBLE_REMOVE" -Mode $mode -Detail ($_.Exception.Message -replace '\s+',' ')
                    $failed++
                }
            }
        }

        "RemoveActive" {
            if ($dryRun) {
                Write-Host "    [dryrun] Would REMOVE active PIM assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                            -Result "SIMULATED" -Mode $mode
            } else {
                try {
                    $activeId = Get-ActiveAssignmentId -PrincipalId $change.PrincipalId -RoleDefinitionId $roleDefId
                    if (-not $activeId) {
                        Write-Host "    [SKIP] No active assignment found" -ForegroundColor DarkYellow
                        Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                    -Result "NO_ACTIVE_FOUND" -Mode $mode
                        $skipped++
                        continue
                    }

                    $params = @{
                        Action           = "adminRemove"
                        Justification    = "Toolkit: deactivate active PIM assignment"
                        RoleDefinitionId = $roleDefId
                        DirectoryScopeId = "/"
                        PrincipalId      = $change.PrincipalId
                    }
                    New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop | Out-Null
                    Write-Host "    [OK] Active PIM assignment deactivated" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "ACTIVE_REMOVED" -Mode $mode -Detail "activeId=$activeId"
                } catch {
                    Write-Warning "    [FAILED] Could not remove active: $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED_ACTIVE_REMOVE" -Mode $mode -Detail ($_.Exception.Message -replace '\s+',' ')
                    $failed++
                }
            }
        }

        default {
            Write-Warning "    Unsupported action '$($change.Action)' - skipping"
            Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                        -Result "UNSUPPORTED" -Mode $mode
            $skipped++
        }
    }
}

# =========================================================
# Summary
# =========================================================
Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  SUMMARY ($mode)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  Processed : $processed"
Write-Host "  Skipped   : $skipped"
Write-Host "  Failed    : $failed"
Write-Host "  Audit log : $AuditLogPath"
Write-Host ""
if ($dryRun) {
    Write-Host "  [DRY RUN] No changes were applied." -ForegroundColor Yellow
} else {
    if ($failed -eq 0) {
        Write-Host "  [LIVE] Changes have been applied. Audit log written." -ForegroundColor Red
    } else {
        Write-Host "  [LIVE] Completed with $failed failure(s). See audit log for details." -ForegroundColor Red
    }
}