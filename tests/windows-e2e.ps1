#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repository = Split-Path -Parent $PSScriptRoot
$skill = Join-Path $repository '.agents\skills\verifact'
$cli = Join-Path $skill 'scripts\verifact.py'
$assessment = Join-Path $env:RUNNER_TEMP ("verifact-e2e-" + [Guid]::NewGuid().ToString('N'))

function Invoke-Checked {
    param([Parameter(Mandatory=$true)][scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code $LASTEXITCODE"
    }
}

$parseErrors = @()
foreach ($script in Get-ChildItem (Join-Path $skill 'scripts\windows') -Filter '*.ps1') {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors)
    $parseErrors += @($errors | ForEach-Object { "$($script.Name): $($_.Message)" })
}
if ($parseErrors.Count -gt 0) {
    throw "PowerShell parse failures:`n - $($parseErrors -join "`n - ")"
}

& (Join-Path $skill 'scripts\windows\Invoke-VerifactCollection.ps1') `
    -AssessmentPath $assessment `
    -TargetLabel $env:COMPUTERNAME `
    -EventDays 1
if ($LASTEXITCODE -ne 0) { throw "Verifact orchestration failed with exit code $LASTEXITCODE" }

Invoke-Checked { python $cli validate $assessment }
Invoke-Checked { python $cli build $assessment }
Invoke-Checked { python $cli verify-report $assessment }

foreach ($required in @(
    'report\index.html',
    'report\explorer.html',
    'report\build-manifest.json'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $assessment $required) -PathType Leaf)) {
        throw "Expected output is missing: $required"
    }
}

Write-Host "Windows end-to-end assessment passed: $assessment"
