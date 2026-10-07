<#
    Pester 5 tests for New-AutoRemediationScenarios.ps1.

    Run:
        Invoke-Pester -Path .\tests -Output Detailed
#>

BeforeAll {
    $repoRoot        = Split-Path $PSScriptRoot -Parent
    $scriptUnderTest = Join-Path $repoRoot "scripts\Remediation\New-AutoRemediationScenarios.ps1"

    if (-not (Test-Path $scriptUnderTest)) { throw "Missing script: $scriptUnderTest" }

    $testOutput = Join-Path $PSScriptRoot "output"
    if (-not (Test-Path $testOutput)) { New-Item -ItemType Directory -Path $testOutput -Force | Out-Null }

    # Build a fixture score report covering all three tiers
    $fixture = @(
        [PSCustomObject]@{
            PrincipalId       = "aaaa-1111"
            PrincipalName     = "Alice Admin"
            Score             = 100
            Tier              = "Critical"
            HighPrivRoleCount = 3
            Findings          = @(
                [PSCustomObject]@{ Source = "PermanentRole"; Role = "Global Administrator"; Weight = 50; Reason = "Permanent high-priv" },
                [PSCustomObject]@{ Source = "PermanentRole"; Role = "Privileged Role Administrator"; Weight = 50; Reason = "Permanent high-priv" },
                [PSCustomObject]@{ Source = "PIM"; Role = "Global Administrator"; Weight = 20; Reason = "Active - permanent activation" }
            )
        },
        [PSCustomObject]@{
            PrincipalId       = "bbbb-2222"
            PrincipalName     = "Bob Operator"
            Score             = 30
            Tier              = "Medium"
            HighPrivRoleCount = 1
            Findings          = @(
                [PSCustomObject]@{ Source = "PIM"; Role = "User Administrator"; Weight = 10; Reason = "Eligible - Standard eligible assignment" }
            )
        },
        [PSCustomObject]@{
            PrincipalId       = "cccc-3333"
            PrincipalName     = "Carol Low"
            Score             = 5
            Tier              = "Low"
            HighPrivRoleCount = 0
            Findings          = @(
                [PSCustomObject]@{ Source = "PIM"; Role = "Reports Reader"; Weight = 2; Reason = "Eligible - Standard" }
            )
        }
    )

    $script:fixturePath = Join-Path $testOutput "scenario-fixture-score.json"
    $fixture | ConvertTo-Json -Depth 6 | Out-File $script:fixturePath -Encoding UTF8

    $script:scenariosFolder = Join-Path $PSScriptRoot "output\scenarios-test"
    if (Test-Path $script:scenariosFolder) { Remove-Item $script:scenariosFolder -Recurse -Force }
    New-Item -ItemType Directory -Path $script:scenariosFolder -Force | Out-Null
}

Describe "New-AutoRemediationScenarios" {

    Context "Tier filter -MinTier Medium" {

        It "generates scenarios only for principals at or above Medium" {
            & $scriptUnderTest -ScoreReportPath $script:fixturePath -ScenariosFolder $script:scenariosFolder -MinTier Medium | Out-Null

            $files = Get-ChildItem $script:scenariosFolder -Filter "*.json"
            # Alice (Critical) and Bob (Medium) should generate scenarios;
            # Carol (Low) should be excluded.
            $files.Count | Should -Be 2
        }

        It "produces a scenario file named after each target principal" {
            $files = Get-ChildItem $script:scenariosFolder -Filter "*.json" | Select-Object -ExpandProperty Name
            $files | Should -Contain "Alice_Admin.scenario.json"
            $files | Should -Contain "Bob_Operator.scenario.json"
        }
    }

    Context "Scenario content" {

        BeforeAll {
            $aliceFile = Join-Path $script:scenariosFolder "Alice_Admin.scenario.json"
            $script:aliceScenario = Get-Content $aliceFile -Raw | ConvertFrom-Json
        }

        It "records the source score report path" {
            $script:aliceScenario.Source | Should -Not -BeNullOrEmpty
        }

        It "contains a change for each actionable finding" {
            # Alice has: 2 permanent high-priv + 1 active PIM with 'permanent activation' reason
            # Expected: both permanents become ConvertPermanentToEligible,
            #           active PIM also becomes ConvertPermanentToEligible (matches 'Active' reason)
            $script:aliceScenario.Changes.Count | Should -Be 3
        }

        It "uses ConvertPermanentToEligible for permanent findings" {
            $permanentChanges = $script:aliceScenario.Changes | Where-Object { $_.Action -eq "ConvertPermanentToEligible" }
            $permanentChanges.Count | Should -BeGreaterOrEqual 2
        }

        It "targets the correct principal ID" {
            $script:aliceScenario.Changes | ForEach-Object {
                $_.PrincipalId | Should -Be "aaaa-1111"
            }
        }
    }

    Context "Tier filter -MinTier Critical" {

        BeforeAll {
            $criticalFolder = Join-Path $PSScriptRoot "output\scenarios-critical"
            if (Test-Path $criticalFolder) { Remove-Item $criticalFolder -Recurse -Force }
            New-Item -ItemType Directory -Path $criticalFolder -Force | Out-Null

            & $scriptUnderTest -ScoreReportPath $script:fixturePath -ScenariosFolder $criticalFolder -MinTier Critical | Out-Null
            $script:criticalFolder = $criticalFolder
        }

        It "generates only one scenario (Alice, Critical)" {
            $files = Get-ChildItem $script:criticalFolder -Filter "*.json"
            $files.Count | Should -Be 1
            $files[0].Name | Should -Be "Alice_Admin.scenario.json"
        }
    }

    Context "Edge cases" {

        It "produces no files when no principals meet the tier threshold" {
            $emptyFolder = Join-Path $PSScriptRoot "output\scenarios-empty"
            if (Test-Path $emptyFolder) { Remove-Item $emptyFolder -Recurse -Force }
            New-Item -ItemType Directory -Path $emptyFolder -Force | Out-Null

            # Filter by Critical, but give it a report with only Low-tier entries
            $lowOnly = @(
                [PSCustomObject]@{
                    PrincipalId = "zzz-9999"; PrincipalName = "Zero Risk"
                    Score = 2; Tier = "Low"; HighPrivRoleCount = 0
                    Findings = @()
                }
            )
            $lowPath = Join-Path $PSScriptRoot "output\low-only-score.json"
            $lowOnly | ConvertTo-Json -Depth 6 | Out-File $lowPath -Encoding UTF8

            & $scriptUnderTest -ScoreReportPath $lowPath -ScenariosFolder $emptyFolder -MinTier Critical | Out-Null

            $files = @(Get-ChildItem $emptyFolder -Filter "*.json")
            $files.Count | Should -Be 0
        }
    }
}