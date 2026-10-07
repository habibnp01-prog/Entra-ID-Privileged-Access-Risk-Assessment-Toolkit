<#
    Pester 5 tests for Get-EntraRiskScore.ps1.

    Run:
        Invoke-Pester -Path .\tests -Output Detailed
#>

BeforeAll {
    $repoRoot       = Split-Path $PSScriptRoot -Parent
    $scriptUnderTest = Join-Path $repoRoot "scripts\RiskEngine\Get-EntraRiskScore.ps1"
    $fixturePath     = Join-Path $PSScriptRoot "fixtures\scoring-basic.json"

    if (-not (Test-Path $scriptUnderTest)) { throw "Missing script: $scriptUnderTest" }
    if (-not (Test-Path $fixturePath))     { throw "Missing fixture: $fixturePath" }

    # Load fixture and expand into the two JSON files the scorer expects
    $fixture = Get-Content $fixturePath -Raw | ConvertFrom-Json

    $testOutput = Join-Path $PSScriptRoot "output"
    if (-not (Test-Path $testOutput)) { New-Item -ItemType Directory -Path $testOutput -Force | Out-Null }

    $pimPath  = Join-Path $testOutput "PIMEligibilityReport.json"
    $permPath = Join-Path $testOutput "PermanentRoleReport.json"
    $scorePath = Join-Path $testOutput "RiskScoreReport.json"

    $fixture.PIMReport       | ConvertTo-Json -Depth 6 | Out-File $pimPath  -Encoding UTF8
    $fixture.PermanentReport | ConvertTo-Json -Depth 6 | Out-File $permPath -Encoding UTF8

    # Run the scorer once per test session (before tests)
    & $scriptUnderTest -PIMReportPath $pimPath -PermanentReportPath $permPath -OutputPath $scorePath | Out-Null

    $script:scored = Get-Content $scorePath -Raw | ConvertFrom-Json
    if ($scored -isnot [array]) { $scored = @($scored) }
}

Describe "Get-EntraRiskScore" {

    It "produces one score entry per distinct principal" {
        $scored.Count | Should -Be 2
    }

    Context "Principal with mixed PIM + permanent findings" {

        BeforeAll {
            $p = $script:scored | Where-Object { $_.PrincipalId -eq "11111111-1111-1111-1111-111111111111" }
        }

        It "exists in the report" {
            $p | Should -Not -BeNullOrEmpty
        }

        It "has score 70 (50 permanent + 20 active PIM, no blast multiplier)" {
            $p.Score | Should -Be 70
        }

        It "is classified as High tier" {
            $p.Tier | Should -Be "High"
        }

        It "has 2 findings" {
            $p.Findings.Count | Should -Be 2
        }

        It "counts 2 high-privilege roles" {
            $p.HighPrivRoleCount | Should -Be 2
        }
    }

    Context "Principal with only one eligible PIM finding" {

        BeforeAll {
            $p = $script:scored | Where-Object { $_.PrincipalId -eq "22222222-2222-2222-2222-222222222222" }
        }

        It "has score 10 (single eligible + high-priv role)" {
            $p.Score | Should -Be 10
        }

        It "is classified as Low tier" {
            $p.Tier | Should -Be "Low"
        }

        It "has 1 finding" {
            $p.Findings.Count | Should -Be 1
        }
    }

    Context "Edge cases" {

        It "handles empty input arrays gracefully" {
            $emptyPim  = Join-Path $PSScriptRoot "output\empty-pim.json"
            $emptyPerm = Join-Path $PSScriptRoot "output\empty-perm.json"
            $emptyOut  = Join-Path $PSScriptRoot "output\empty-score.json"
            '[]' | Out-File $emptyPim  -Encoding UTF8
            '[]' | Out-File $emptyPerm -Encoding UTF8

            & $scriptUnderTest -PIMReportPath $emptyPim -PermanentReportPath $emptyPerm -OutputPath $emptyOut | Out-Null

            $result = Get-Content $emptyOut -Raw | ConvertFrom-Json
            # Empty array serializes as $null after ConvertFrom-Json on '[]' in some PS versions.
            # Normalize: treat null as empty.
            if ($null -eq $result) { $result = @() }
            $result.Count | Should -Be 0
        }

        It "applies blast-radius multiplier when 3+ high-privilege roles are held" {
            # Build a synthetic principal with 3 permanent high-privilege roles.
            # Raw score = 50*3 = 150. With x1.5 -> 225 -> capped at 100.
            $pim  = @()
            $perm = @(
                @{ RoleName = "Global Administrator";               PrincipalId = "33333333-3333-3333-3333-333333333333"; PrincipalName = "Blast"; Reason = "Permanent"; Source = "PermanentRole" },
                @{ RoleName = "Privileged Role Administrator";      PrincipalId = "33333333-3333-3333-3333-333333333333"; PrincipalName = "Blast"; Reason = "Permanent"; Source = "PermanentRole" },
                @{ RoleName = "Privileged Authentication Administrator"; PrincipalId = "33333333-3333-3333-3333-333333333333"; PrincipalName = "Blast"; Reason = "Permanent"; Source = "PermanentRole" }
            )

            $pimPath2  = Join-Path $PSScriptRoot "output\blast-pim.json"
            $permPath2 = Join-Path $PSScriptRoot "output\blast-perm.json"
            $outPath2  = Join-Path $PSScriptRoot "output\blast-score.json"

            $pim  | ConvertTo-Json -Depth 6 | Out-File $pimPath2  -Encoding UTF8
            $perm | ConvertTo-Json -Depth 6 | Out-File $permPath2 -Encoding UTF8

            & $scriptUnderTest -PIMReportPath $pimPath2 -PermanentReportPath $permPath2 -OutputPath $outPath2 | Out-Null

            $scored2 = Get-Content $outPath2 -Raw | ConvertFrom-Json
            if ($scored2 -isnot [array]) { $scored2 = @($scored2) }
            $p = $scored2 | Where-Object { $_.PrincipalId -eq "33333333-3333-3333-3333-333333333333" }

            $p | Should -Not -BeNullOrEmpty
            $p.Score | Should -Be 100
            $p.Tier  | Should -Be "Critical"
        }
    }
}