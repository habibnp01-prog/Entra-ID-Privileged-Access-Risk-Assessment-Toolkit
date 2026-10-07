<#
.SYNOPSIS
    Analyzes PIM eligible and active role assignments in Microsoft Entra ID.

.DESCRIPTION
    Retrieves all eligible and active PIM assignments for Entra directory roles,
    resolves principal and role names, and outputs a structured JSON report.
    Flags potential risks such as assignments with no expiration and
    high-privilege role eligibilities.

.PARAMETER OutputPath
    Path to write the JSON report. Defaults to ./output/PIMEligibilityReport.json

.EXAMPLE
    .\Get-EntraPIMEligibilityReport.ps1

.NOTES
    Requires: Microsoft.Graph.Identity.Governance module
    Scopes:   RoleManagement.Read.Directory, Directory.Read.All
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "./output/PIMEligibilityReport.json"
)

# --- Ensure Graph module is available ---
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.Governance)) {
    Write-Error "Microsoft.Graph.Identity.Governance module not found. Run: Install-Module Microsoft.Graph -Scope CurrentUser -Force"
    return
}

# --- Ensure we're connected to Graph ---
if (-not (Get-MgContext)) {
    Write-Host "[*] Not connected to Microsoft Graph. Connecting..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All"
}

Write-Host "[*] Fetching PIM eligible assignments..." -ForegroundColor Cyan
$eligible = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty '*' -ErrorAction SilentlyContinue

Write-Host "[*] Fetching PIM active assignments..." -ForegroundColor Cyan
$active = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty '*' -ErrorAction SilentlyContinue

# --- Build lookup maps for role names ---
Write-Host "[*] Resolving role definitions..." -ForegroundColor Cyan
$roleMap = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object {
    $roleMap[$_.Id] = $_.DisplayName
}

# --- Process each assignment into a clean object ---
$findings = @()

# Process eligible assignments
foreach ($a in $eligible) {
    $roleName = if ($roleMap.ContainsKey($a.RoleDefinitionId)) { $roleMap[$a.RoleDefinitionId] } else { $a.RoleDefinitionId }
    $principalName = $a.Principal.AdditionalProperties.displayName
    $expirationType = $a.ScheduleInfo.Expiration.Type
    $endDate = $a.ScheduleInfo.Expiration.EndDateTime

    $risk = "Low"
    $reason = "Standard eligible assignment"

    if ($roleName -match "Global Administrator|Privileged Role Administrator|Privileged Authentication Administrator") {
        $risk = "Medium"
        $reason = "Eligible for high-privilege role"
    }

    if ($expirationType -eq "NoExpiration" -or $null -eq $endDate) {
        $risk = "Medium"
        $reason = "Eligible assignment with no expiration (permanent eligibility)"
    }

    $findings += [PSCustomObject]@{
        AssignmentType   = "Eligible"
        PrincipalId      = $a.PrincipalId
        PrincipalName    = $principalName
        RoleName         = $roleName
        RoleDefinitionId = $a.RoleDefinitionId
        ExpirationType   = $expirationType
        EndDateTime      = $endDate
        Risk             = $risk
        Reason           = $reason
        Discovered       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

# Process active assignments
foreach ($a in $active) {
    $roleName = if ($roleMap.ContainsKey($a.RoleDefinitionId)) { $roleMap[$a.RoleDefinitionId] } else { $a.RoleDefinitionId }
    $principalName = $a.Principal.AdditionalProperties.displayName
    $expirationType = $a.ScheduleInfo.Expiration.Type
    $endDate = $a.ScheduleInfo.Expiration.EndDateTime

    $risk = "Medium"
    $reason = "Active PIM assignment"

    if ($expirationType -eq "NoExpiration" -or $null -eq $endDate) {
        $risk = "High"
        $reason = "Active PIM assignment with no expiration (permanent activation)"
    }

    $findings += [PSCustomObject]@{
        AssignmentType   = "Active"
        PrincipalId      = $a.PrincipalId
        PrincipalName    = $principalName
        RoleName         = $roleName
        RoleDefinitionId = $a.RoleDefinitionId
        ExpirationType   = $expirationType
        EndDateTime      = $endDate
        Risk             = $risk
        Reason           = $reason
        Discovered       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

# --- Ensure output folder exists ---
$dir = Split-Path $OutputPath -Parent
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# --- Write JSON report ---
$findings | ConvertTo-Json -Depth 5 | Out-File $OutputPath -Encoding UTF8

# --- Summary ---
$eligibleCount = @($findings | Where-Object { $_.AssignmentType -eq "Eligible" }).Count
$activeCount   = @($findings | Where-Object { $_.AssignmentType -eq "Active" }).Count
$highRiskCount = @($findings | Where-Object { $_.Risk -eq "High" }).Count
$noExpireCount = @($findings | Where-Object { $_.ExpirationType -eq "NoExpiration" -or $null -eq $_.EndDateTime }).Count

Write-Host ""
Write-Host "[OK] Report saved to: $OutputPath" -ForegroundColor Green
Write-Host "[*]  Total assignments: $($findings.Count)" -ForegroundColor Cyan
Write-Host "     Eligible: $eligibleCount" -ForegroundColor Gray
Write-Host "     Active:   $activeCount" -ForegroundColor Gray
Write-Host "[!]  High-risk findings: $highRiskCount" -ForegroundColor Red
Write-Host "[!]  No-expiration assignments: $noExpireCount" -ForegroundColor Yellow