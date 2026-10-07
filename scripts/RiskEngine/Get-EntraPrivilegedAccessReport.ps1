<#
.SYNOPSIS
    Discovers privileged access in Microsoft Entra ID and outputs a risk report.

.DESCRIPTION
    Enumerates directory roles and their members, flags permanent privileged
    assignments (especially Global Administrator) as high-risk findings, and
    writes a timestamped JSON report to the ./output folder.

.PARAMETER OutputPath
    Path to write the JSON report. Defaults to ./output/PrivilegedAccessReport.json

.EXAMPLE
    .\Get-EntraPrivilegedAccessReport.ps1

.NOTES
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement
    Scopes:   RoleManagement.Read.Directory, Directory.Read.All
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "./output/PrivilegedAccessReport.json"
)

# --- Ensure required Graph submodules are available (import if installed) ---
$requiredModules = @(
    "Microsoft.Graph.Authentication",
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

# --- Ensure we're connected to Graph ---
if (-not (Get-MgContext)) {
    Write-Host "[*] Not connected to Microsoft Graph. Connecting..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All"
}

Write-Host "[*] Discovering privileged roles in Entra ID..." -ForegroundColor Cyan

$roles = Get-MgDirectoryRole -All
$findings = @()

foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue

    foreach ($member in $members) {
        $risk   = "Medium"
        $reason = "Standard privileged assignment"

        if ($role.DisplayName -eq "Global Administrator") {
            $risk   = "High"
            $reason = "Permanent Global Administrator assignment"
        }
        elseif ($role.DisplayName -match "Privileged Role Administrator|Privileged Authentication Administrator") {
            $risk   = "High"
            $reason = "Highly privileged role with escalation potential"
        }

        $findings += [PSCustomObject]@{
            RoleName   = $role.DisplayName
            RoleId     = $role.Id
            MemberId   = $member.Id
            Risk       = $risk
            Reason     = $reason
            Discovered = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }
}

# --- Ensure output folder exists ---
$dir = Split-Path $OutputPath -Parent
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# --- Write JSON report ---
$findings | ConvertTo-Json -Depth 5 | Out-File $OutputPath -Encoding UTF8

# --- Summary to console ---
$highCount = @($findings | Where-Object { $_.Risk -eq "High" }).Count

Write-Host ""
Write-Host "[OK] Report saved to: $OutputPath" -ForegroundColor Green
Write-Host "[*]  Total findings: $($findings.Count)" -ForegroundColor Cyan
Write-Host "[!]  High-risk findings: $highCount" -ForegroundColor Red