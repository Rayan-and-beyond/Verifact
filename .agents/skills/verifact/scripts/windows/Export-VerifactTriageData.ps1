#requires -Version 5.1

<#
.SYNOPSIS
Extracts focused, normalized event fields from a frozen Verifact run.

.DESCRIPTION
Reads raw EVTX exports using the .NET Event Log reader and writes JSON Lines for
events selected by config/analysis-scope.json. The output is derived evidence:
raw EVTX remains authoritative. Inclusion in this extract does not imply that
an event is suspicious.

Messages are not rendered. XML event-data and user-data values are retained so
later analysis can use the source fields without provider message-rendering
overhead.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunDirectory,
    [Parameter(Mandatory = $true)]
    [string]$AnalysisScopePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$resolvedRun = (Resolve-Path -LiteralPath $RunDirectory).Path
$manifestPath = Join-Path $resolvedRun 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Manifest not found: $manifestPath"
}
if (-not (Test-Path -LiteralPath $AnalysisScopePath -PathType Leaf)) {
    throw "Analysis scope not found: $AnalysisScopePath"
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$analysisScope = Get-Content -LiteralPath $AnalysisScopePath -Raw | ConvertFrom-Json

$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ([string]$manifest.status -notin @('completed', 'completed-degraded', 'completed-with-export-failures')) {
    throw "Run status '$($manifest.status)' is not authorized for normalization."
}
if (-not [bool]$manifest.readOnlyCollection -or -not [bool]$manifest.defenderSpecificCollectionExcluded) {
    throw 'Manifest does not preserve the required Verifact safety declarations.'
}

function Resolve-BoundedRunPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        [System.IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath.StartsWith('\\') -or
        $RelativePath -match '^[A-Za-z]+:' -or
        $RelativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "Unsafe evidence path: $RelativePath"
    }
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $childFull = [System.IO.Path]::GetFullPath((Join-Path $rootFull ($RelativePath -replace '/', '\')))
    if (-not $childFull.StartsWith($rootFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Evidence path escapes the run: $RelativePath"
    }
    return $childFull
}

$integrityFailures = @()
foreach ($channel in @($manifest.channels | Where-Object { $_.exportStatus -eq 'exported' })) {
    try {
        $path = Resolve-BoundedRunPath -Root $resolvedRun -RelativePath ([string]$channel.exportPath)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'referenced EVTX file is missing' }
        $item = Get-Item -LiteralPath $path
        if ([long]$item.Length -ne [long]$channel.exportSizeBytes) { throw 'EVTX byte length mismatch' }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne ([string]$channel.sha256).ToLowerInvariant()) { throw 'EVTX SHA-256 mismatch' }
    }
    catch {
        $integrityFailures += "$($channel.name): $($_.Exception.Message)"
    }
}
if ($integrityFailures.Count -gt 0) {
    throw "Event evidence integrity validation failed before parsing:`n - $($integrityFailures -join "`n - ")"
}

foreach ($excludedPattern in @($analysisScope.excludedProviderPatterns)) {
    foreach ($configuredChannel in @($analysisScope.channels)) {
        if ([string]$configuredChannel.name -match $excludedPattern) {
            throw "Excluded provider pattern '$excludedPattern' matches channel '$($configuredChannel.name)'."
        }
    }
}

$scopeByChannel = @{}
foreach ($channelScope in @($analysisScope.channels)) {
    $scopeByChannel[[string]$channelScope.name] = $channelScope
}

function Test-EventSelected {
    param(
        [Parameter(Mandatory = $true)]
        [object]$EventRecord,

        [Parameter(Mandatory = $true)]
        [object]$ChannelScope,

        [Parameter(Mandatory = $true)]
        [string[]]$ExcludedProviderPatterns
    )

    foreach ($pattern in $ExcludedProviderPatterns) {
        if ([string]$EventRecord.ProviderName -match $pattern) {
            return $false
        }
    }

    $includeAllProperty = $ChannelScope.PSObject.Properties['includeAll']
    if ($null -ne $includeAllProperty -and [bool]$includeAllProperty.Value) {
        return $true
    }

    $includeIdsProperty = $ChannelScope.PSObject.Properties['includeEventIds']
    if ($null -ne $includeIdsProperty -and [int]$EventRecord.Id -in @($includeIdsProperty.Value)) {
        return $true
    }

    $maxLevelProperty = $ChannelScope.PSObject.Properties['maximumNumericLevel']
    if ($null -ne $maxLevelProperty -and $null -ne $EventRecord.Level) {
        if ([int]$EventRecord.Level -le [int]$maxLevelProperty.Value) {
            return $true
        }
    }

    $providerIdsProperty = $ChannelScope.PSObject.Properties['providerEventIds']
    if ($null -ne $providerIdsProperty) {
        foreach ($providerEntry in @($providerIdsProperty.Value)) {
            if (
                [string]$EventRecord.ProviderName -eq [string]$providerEntry.provider -and
                [int]$EventRecord.Id -in @($providerEntry.eventIds)
            ) {
                return $true
            }
        }
    }

    return $false
}

function Add-FieldValue {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Fields,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowEmptyString()]
        [string]$Value
    )

    $candidateName = if ([string]::IsNullOrWhiteSpace($Name)) { 'Data' } else { $Name }
    $suffix = 1
    while ($Fields.ContainsKey($candidateName)) {
        $candidateName = "$Name#$suffix"
        $suffix++
    }
    $Fields[$candidateName] = $Value
}

function Get-EventXmlFields {
    param(
        [Parameter(Mandatory = $true)]
        [string]$XmlText
    )

    $document = New-Object System.Xml.XmlDocument
    $document.PreserveWhitespace = $false
    $document.LoadXml($XmlText)
    $fields = @{}

    $eventDataNodes = $document.SelectNodes(
        '/*[local-name()="Event"]/*[local-name()="EventData"]/*'
    )
    $unnamedIndex = 0
    foreach ($node in @($eventDataNodes)) {
        $nameAttribute = $node.Attributes['Name']
        $fieldName = if ($null -ne $nameAttribute -and -not [string]::IsNullOrWhiteSpace($nameAttribute.Value)) {
            $nameAttribute.Value
        }
        else {
            "Data$unnamedIndex"
        }
        Add-FieldValue -Fields $fields -Name $fieldName -Value $node.InnerText
        $unnamedIndex++
    }

    $userDataLeafNodes = $document.SelectNodes(
        '/*[local-name()="Event"]/*[local-name()="UserData"]//*[not(*)]'
    )
    foreach ($node in @($userDataLeafNodes)) {
        Add-FieldValue -Fields $fields -Name $node.LocalName -Value $node.InnerText
    }

    return $fields
}

$derivedDirectory = Join-Path $resolvedRun 'derived\triage'
if (-not (Test-Path -LiteralPath $derivedDirectory)) {
    $null = New-Item -ItemType Directory -Path $derivedDirectory -Force
}
$generatorSnapshotPath = Join-Path $derivedDirectory 'normalizer.ps1'
Copy-Item -LiteralPath $PSCommandPath -Destination $generatorSnapshotPath -Force

$outputPath = Join-Path $derivedDirectory 'events.jsonl'
$summaryPath = Join-Path $derivedDirectory 'summary.json'
$scopeSnapshotPath = Join-Path $derivedDirectory 'analysis-scope.json'
Copy-Item -LiteralPath $AnalysisScopePath -Destination $scopeSnapshotPath -Force

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$writer = New-Object System.IO.StreamWriter($outputPath, $false, $utf8NoBom)
$channelSummaries = @()
$totalExamined = 0
$totalSelected = 0

try {
    foreach ($channel in @($manifest.channels | Where-Object { $_.exportStatus -eq 'exported' })) {
        $channelName = [string]$channel.name
        if (-not $scopeByChannel.ContainsKey($channelName)) {
            continue
        }

        $relativePath = ([string]$channel.exportPath).Replace(
            [System.IO.Path]::AltDirectorySeparatorChar,
            [System.IO.Path]::DirectorySeparatorChar
        )
        $evtxPath = Resolve-BoundedRunPath -Root $resolvedRun -RelativePath $relativePath
        $channelScope = $scopeByChannel[$channelName]
        $examined = 0
        $selected = 0
        $selectionCounts = @{}

        Write-Host "Extracting $channelName"
        $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
            $evtxPath,
            [System.Diagnostics.Eventing.Reader.PathType]::FilePath
        )
        $query.ReverseDirection = $false
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

        try {
            while ($true) {
                $eventRecord = $reader.ReadEvent()
                if ($null -eq $eventRecord) {
                    break
                }

                try {
                    $examined++
                    if (-not (Test-EventSelected -EventRecord $eventRecord -ChannelScope $channelScope -ExcludedProviderPatterns @($analysisScope.excludedProviderPatterns))) {
                        continue
                    }

                    $selected++
                    $countKey = '{0}|{1}' -f $eventRecord.ProviderName, $eventRecord.Id
                    if (-not $selectionCounts.ContainsKey($countKey)) {
                        $selectionCounts[$countKey] = 0
                    }
                    $selectionCounts[$countKey]++

                    $fields = Get-EventXmlFields -XmlText $eventRecord.ToXml()
                    $normalized = [ordered]@{
                        schemaVersion  = '1.0'
                        runId          = $manifest.runId
                        channel        = $channelName
                        provider       = $eventRecord.ProviderName
                        eventId        = [int]$eventRecord.Id
                        version        = if ($null -ne $eventRecord.Version) { [int]$eventRecord.Version } else { $null }
                        level          = if ($null -ne $eventRecord.Level) { [int]$eventRecord.Level } else { $null }
                        task           = if ($null -ne $eventRecord.Task) { [int]$eventRecord.Task } else { $null }
                        opcode         = if ($null -ne $eventRecord.Opcode) { [int]$eventRecord.Opcode } else { $null }
                        keywords       = if ($null -ne $eventRecord.Keywords) { [long]$eventRecord.Keywords } else { $null }
                        recordId       = if ($null -ne $eventRecord.RecordId) { [long]$eventRecord.RecordId } else { $null }
                        timeCreatedUtc = ([datetime]$eventRecord.TimeCreated).ToUniversalTime().ToString('o')
                        computer       = $eventRecord.MachineName
                        userId         = if ($null -ne $eventRecord.UserId) { $eventRecord.UserId.Value } else { $null }
                        fields         = $fields
                    }
                    $writer.WriteLine(($normalized | ConvertTo-Json -Compress -Depth 8))
                }
                finally {
                    $eventRecord.Dispose()
                }
            }
        }
        finally {
            $reader.Dispose()
        }

        $totalExamined += $examined
        $totalSelected += $selected
        $channelSummaries += [pscustomobject][ordered]@{
            channel         = $channelName
            examined        = $examined
            selected        = $selected
            selectionCounts = @(
                $selectionCounts.GetEnumerator() |
                    ForEach-Object {
                        [pscustomobject]@{
                            providerAndEventId = $_.Key
                            count              = $_.Value
                        }
                    } |
                    Sort-Object -Property @{ Expression = 'count'; Descending = $true }, providerAndEventId
            )
        }
    }
}
finally {
    $writer.Dispose()
}

$outputHash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
$outputItem = Get-Item -LiteralPath $outputPath
$summary = [ordered]@{
    schemaVersion     = '1.0'
    runId             = $manifest.runId
    generatedUtc      = [datetime]::UtcNow.ToString('o')
    rawEvidenceSource = 'manifest.json'
    rawManifestSha256 = $manifestHash
    generator         = 'derived/triage/normalizer.ps1'
    generatorSha256   = (Get-FileHash -LiteralPath $generatorSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
    analysisScopeSha256 = (Get-FileHash -LiteralPath $scopeSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
    analysisScope     = 'derived/triage/analysis-scope.json'
    output            = 'derived/triage/events.jsonl'
    outputSizeBytes   = $outputItem.Length
    outputSha256      = $outputHash
    eventsExamined    = $totalExamined
    eventsSelected    = $totalSelected
    note              = 'Selection means reviewable, not suspicious.'
    channels          = $channelSummaries
}
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host ''
Write-Host "Events examined: $totalExamined"
Write-Host "Events selected: $totalSelected"
Write-Host "Derived data: $outputPath"
Write-Host "SHA-256: $outputHash"
