<#
.SYNOPSIS
    Applies remediation actions to Microsoft Entra ID with multi-layer safety guards.

.DESCRIPTION
    Reads a scenario file (same format as Invoke-WhatIfSimulation.ps1) and
    applies the requested remediation actions to Entra ID.

    SAFETY:
      - DryRun is the DEFAULT. No changes are made unless -Apply is passed.
      - Even with -Apply, -Confirm must be explicitly set to $true.
      - Every action (real or simulated) is logged to the audit trail.
      - A hard guard blocks removal of the LAST permanent Global Administrator.

    Supported actions:
      - ConvertPermanentToEligible : create eligible assignment, then remove permanent
      - RemovePermanent            : remove permanent assignment without replacement

.PARAMETER ScenarioPath
    Path to the scenario JSON file. Required.

.PARAMETER AuditLogPath
    Path to the audit log. Defaults to ./output/RemediationAudit.log

.PARAMETER Apply
    Actually perform changes against the tenant. Without this switch, the script
    runs in DryRun mode and only reports what would happen.

.PARAMETER Confirm
    Must be set to $true IN ADDITION to -Apply. Prevents accidental execution.

.EXAMPLE
    # DryRun (default) - shows what would change
    .\Invoke-EntraRemediation.ps1 -ScenarioPath .\scenarios\example-scenario.json

    # Real execution - both switches required
    .\Invoke-EntraRemediation.ps1 -ScenarioPath .\scenarios\example-scenario.json -Apply -Confirm:$true

.NOTES
    Requires Microsoft.Graph module and a connected session with:
      - RoleManagement.ReadWrite.Directory
      - PrivilegedAccess.ReadWrite.AzureADGroup
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
# Graph connection (only required in live mode)
# =========================================================
if (-not $dryRun) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Error "Microsoft.Graph module not found. Install-Module Microsoft.Graph -Scope CurrentUser -Force"
        return
    }
    if (-not (Get-MgContext)) {
        Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","Directory.Read.All"
    }
}

# =========================================================
# Helper : lookup role definition ID by display name
# =========================================================
function Get-RoleDefinitionId {
    param([string]$RoleName)
    $def = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $def) { return $null }
    return $def.Id
}

# =========================================================
# Helper : safety check - is this the last permanent Global Admin?
# =========================================================
function Test-LastPermanentGlobalAdmin {
    param([string]$PrincipalId)

    $gaDefId = Get-RoleDefinitionId -RoleName "Global Administrator"
    if (-not $gaDefId) { return $false }

    # Get all permanent GA assignments (non-PIM)
    $allGa = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$gaDefId'" -All -ErrorAction SilentlyContinue

    # Get PIM-active GA (to exclude)
    $pimActive = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction SilentlyContinue
    $pimActiveIds = @{}
    foreach ($p in $pimActive) { if ($p.Id) { $pimActiveIds[$p.Id] = $true } }

    $permanentGas = @()
    foreach ($a in $allGa) {
        if ($pimActiveIds.ContainsKey($a.Id)) { continue }
        $permanentGas += $a
    }

    # If the target principal is among them and there's only one, block.
    $targetIsGa = $permanentGas | Where-Object { $_.PrincipalId -eq $PrincipalId }
    if ($targetIsGa -and $permanentGas.Count -le 1) {
        return $true
    }
    return $false
}

# =========================================================
# Helper : find a permanent assignment ID for a principal+role
# =========================================================
function Get-PermanentAssignmentId {
    param([string]$PrincipalId, [string]$RoleDefinitionId)

    $all = Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction SilentlyContinue
    $pimActive = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction SilentlyContinue
    $pimActiveIds = @{}
    foreach ($p in $pimActive) { if ($p.Id) { $pimActiveIds[$p.Id] = $true } }

    $match = $all | Where-Object {
        $_.PrincipalId       -eq $PrincipalId -and
        $_.RoleDefinitionId  -eq $RoleDefinitionId -and
        -not $pimActiveIds.ContainsKey($_.Id)
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

    switch ($change.Action) {

        "ConvertPermanentToEligible" {
            # Safety: last GA guard
            if ($change.RoleName -eq "Global Administrator") {
                $isLast = if ($dryRun) {
                    Write-Host "    [dryrun] skipping last-GA safety check (live mode only)" -ForegroundColor DarkGray
                    $false
                } else {
                    Test-LastPermanentGlobalAdmin -PrincipalId $change.PrincipalId
                }
                if ($isLast) {
                    Write-Warning "    BLOCKED: this would remove the last permanent Global Administrator. Skipping."
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "BLOCKED_LAST_GA" -Mode $mode -Detail "safety guard"
                    $skipped++
                    continue
                }
            }

            if ($dryRun) {
                Write-Host "    Would CREATE eligible PIM assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Host "    Would REMOVE permanent assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                            -Result "SIMULATED" -Mode $mode
            } else {
                # LIVE : create eligible PIM assignment
                try {
                    $roleDefId = Get-RoleDefinitionId -RoleName $change.RoleName
                    if (-not $roleDefId) { throw "Role definition '$($change.RoleName)' not found." }

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

                    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params | Out-Null
                    Write-Host "    [OK] Eligible assignment created" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "ELIGIBLE_CREATED" -Mode $mode
                } catch {
                    Write-Warning "    Failed to create eligible assignment: $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED_ELIGIBLE_CREATE" -Mode $mode -Detail $_.Exception.Message
                    $failed++
                    continue
                }

                # LIVE : remove permanent assignment
                try {
                    $assignmentId = Get-PermanentAssignmentId -PrincipalId $change.PrincipalId -RoleDefinitionId $roleDefId
                    if (-not $assignmentId) {
                        Write-Host "    [SKIP] No permanent assignment found to remove" -ForegroundColor DarkYellow
                        Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                    -Result "NO_PERMANENT_FOUND" -Mode $mode
                        $skipped++
                        continue
                    }

                    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignmentId
                    Write-Host "    [OK] Permanent assignment removed ($assignmentId)" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "PERMANENT_REMOVED" -Mode $mode -Detail "assignmentId=$assignmentId"
                } catch {
                    Write-Warning "    Failed to remove permanent assignment: $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED_PERMANENT_REMOVE" -Mode $mode -Detail $_.Exception.Message
                    $failed++
                }
            }
        }

        "RemovePermanent" {
            # Same last-GA safety check
            if ($change.RoleName -eq "Global Administrator") {
                $isLast = if ($dryRun) { $false } else {
                    Test-LastPermanentGlobalAdmin -PrincipalId $change.PrincipalId
                }
                if ($isLast) {
                    Write-Warning "    BLOCKED: this would remove the last permanent Global Administrator. Skipping."
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "BLOCKED_LAST_GA" -Mode $mode -Detail "safety guard"
                    $skipped++
                    continue
                }
            }

            if ($dryRun) {
                Write-Host "    Would REMOVE permanent assignment for $($change.PrincipalId) on $($change.RoleName)" -ForegroundColor Yellow
                Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                            -Result "SIMULATED" -Mode $mode
            } else {
                try {
                    $roleDefId = Get-RoleDefinitionId -RoleName $change.RoleName
                    if (-not $roleDefId) { throw "Role definition '$($change.RoleName)' not found." }

                    $assignmentId = Get-PermanentAssignmentId -PrincipalId $change.PrincipalId -RoleDefinitionId $roleDefId
                    if (-not $assignmentId) {
                        Write-Host "    [SKIP] No permanent assignment found" -ForegroundColor DarkYellow
                        Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                    -Result "NO_PERMANENT_FOUND" -Mode $mode
                        $skipped++
                        continue
                    }

                    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignmentId
                    Write-Host "    [OK] Permanent assignment removed ($assignmentId)" -ForegroundColor Green
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "PERMANENT_REMOVED" -Mode $mode -Detail "assignmentId=$assignmentId"
                } catch {
                    Write-Warning "    Failed: $($_.Exception.Message)"
                    Write-Audit -Action $change.Action -PrincipalId $change.PrincipalId -RoleName $change.RoleName `
                                -Result "FAILED" -Mode $mode -Detail $_.Exception.Message
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
    Write-Host "  [DRY RUN] No changes were applied. Re-run with -Apply -Confirm:`$true to execute." -ForegroundColor Yellow
} else {
    Write-Host "  [LIVE] Changes have been applied. Audit log written." -ForegroundColor Red
}