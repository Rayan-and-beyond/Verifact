<#
.SYNOPSIS
Prepares verified Verifact evidence for agent analysis.

.DESCRIPTION
Initializes one assessment, performs read-only event and posture collection,
selects and verifies both runs, and creates normalized analysis views. If the
current process is not elevated, the script requests Windows elevation and
waits for the elevated process to finish.

.EXAMPLE
powershell.exe -NoProfile -File .\Invoke-VerifactCollection.ps1 -AssessmentPath C:\Assessments\case-001
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AssessmentPath,
    [string]$TargetLabel = $env:COMPUTERNAME,
    [ValidateRange(1, 3650)][int]$EventDays = 120,
    [string]$InvokingUser
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PythonInvocation {
    $candidates = New-Object System.Collections.Generic.List[object]
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $candidates.Add([pscustomobject]@{ Executable = $launcher.Source; Prefix = @('-3') })
    }
    foreach ($name in @('python.exe', 'python')) {
        $python = Get-Command $name -ErrorAction SilentlyContinue
        if ($python) {
            $candidates.Add([pscustomobject]@{ Executable = $python.Source; Prefix = @() })
        }
    }
    $seen = @{}
    foreach ($candidate in $candidates) {
        $key = ([string]$candidate.Executable).ToLowerInvariant() + '|' + (@($candidate.Prefix) -join ' ')
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        try {
            $executable = [string]$candidate.Executable
            $prefix = @($candidate.Prefix)
            & $executable @prefix -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        }
        catch { }
    }
    throw 'Python 3.10 or newer was not found.'
}

function Invoke-VerifactPython {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $executable = [string]$script:Python.Executable
    $prefix = @($script:Python.Prefix)
    & $executable @prefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Verifact command failed with exit code $LASTEXITCODE."
    }
}

function Get-RunDirectories {
    param([Parameter(Mandatory = $true)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Root -Directory | ForEach-Object { $_.FullName })
}

function Invoke-Collector {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$ScopePath,
        [hashtable]$AdditionalArguments = @{}
    )
    $before = @{}
    foreach ($path in Get-RunDirectories -Root $RunRoot) { $before[$path] = $true }

    $collectorError = $null
    try {
        & $ScriptPath -OutputRoot $RunRoot -ScopePath $ScopePath @AdditionalArguments | Out-Host
    }
    catch {
        $collectorError = $_
    }

    $created = @(Get-RunDirectories -Root $RunRoot | Where-Object {
        -not $before.ContainsKey($_) -and (Test-Path -LiteralPath (Join-Path $_ 'manifest.json') -PathType Leaf)
    })
    if ($created.Count -ne 1) {
        if ($collectorError) { throw $collectorError }
        throw "Collector created $($created.Count) usable run directories; expected exactly one."
    }
    if ($collectorError) {
        Write-Warning "The collector reported limitations. Verifact will verify the completed manifest before using it."
    }
    return $created[0]
}

$AssessmentPath = [IO.Path]::GetFullPath($AssessmentPath)
$thisScript = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($InvokingUser)) {
    $InvokingUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

if (-not (Test-IsAdministrator)) {
    $powerShell = Join-Path $PSHOME 'powershell.exe'
    $quotedScript = $thisScript.Replace("'", "''")
    $quotedAssessment = $AssessmentPath.Replace("'", "''")
    $quotedTarget = $TargetLabel.Replace("'", "''")
    $quotedInvokingUser = $InvokingUser.Replace("'", "''")
    $command = "& '$quotedScript' -AssessmentPath '$quotedAssessment' -TargetLabel '$quotedTarget' -EventDays $EventDays -InvokingUser '$quotedInvokingUser'"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    try {
        $process = Start-Process -FilePath $powerShell -Verb RunAs -ArgumentList @('-NoProfile', '-EncodedCommand', $encodedCommand) -Wait -PassThru
    }
    catch {
        throw 'Administrator approval was not completed. Collection did not run.'
    }
    if ($process.ExitCode -ne 0) {
        throw "Elevated Verifact collection failed with exit code $($process.ExitCode)."
    }
    [pscustomobject][ordered]@{
        status = 'ready-for-analysis'
        assessmentPath = $AssessmentPath
        elevated = $true
    } | ConvertTo-Json -Compress
    exit 0
}

$skillRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cli = Join-Path $skillRoot 'scripts\verifact.py'
$eventCollector = Join-Path $PSScriptRoot 'Collect-VerifactEvidence.ps1'
$postureCollector = Join-Path $PSScriptRoot 'Collect-VerifactPosture.ps1'
$eventNormalizer = Join-Path $PSScriptRoot 'Export-VerifactTriageData.ps1'
$postureNormalizer = Join-Path $PSScriptRoot 'Export-VerifactPostureInventory.ps1'
$script:Python = Get-PythonInvocation

if (Test-Path -LiteralPath $AssessmentPath) {
    $existing = @(Get-ChildItem -LiteralPath $AssessmentPath -Force -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        throw "Assessment directory is not empty: $AssessmentPath"
    }
}

Invoke-VerifactPython -Arguments @($cli, 'init', $AssessmentPath, '--target', $TargetLabel, '--event-days', [string]$EventDays)

$eventRoot = Join-Path $AssessmentPath 'evidence\events\runs'
$postureRoot = Join-Path $AssessmentPath 'evidence\posture\runs'
$eventRun = Invoke-Collector -ScriptPath $eventCollector -RunRoot $eventRoot -ScopePath (Join-Path $AssessmentPath 'config\event-scope.json')
$postureRun = Invoke-Collector -ScriptPath $postureCollector -RunRoot $postureRoot -ScopePath (Join-Path $AssessmentPath 'config\posture-scope.json') -AdditionalArguments @{ InvokingUser = $InvokingUser }

Invoke-VerifactPython -Arguments @($cli, 'select', $AssessmentPath, '--events-run', $eventRun, '--posture-run', $postureRun)
Invoke-VerifactPython -Arguments @($cli, 'verify', $AssessmentPath)

& $eventNormalizer -RunDirectory $eventRun -AnalysisScopePath (Join-Path $AssessmentPath 'config\analysis-scope.json')
if ($LASTEXITCODE -ne 0) { throw "Event normalization failed with exit code $LASTEXITCODE." }
& $postureNormalizer -RunDirectory $postureRun
if ($LASTEXITCODE -ne 0) { throw "Posture normalization failed with exit code $LASTEXITCODE." }

Invoke-VerifactPython -Arguments @($cli, 'verify', $AssessmentPath)
Invoke-VerifactPython -Arguments @($cli, 'validate', $AssessmentPath, '--draft')

Write-Host "Verifact evidence is ready for agent analysis."
Write-Host "Assessment: $AssessmentPath"
Write-Host "Event run: $eventRun"
Write-Host "Posture run: $postureRun"
[pscustomobject][ordered]@{
    status = 'ready-for-analysis'
    assessmentPath = $AssessmentPath
    eventRun = $eventRun
    postureRun = $postureRun
} | ConvertTo-Json -Compress
