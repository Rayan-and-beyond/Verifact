#requires -Version 5.1

<#
.SYNOPSIS
Collects read-only Windows event-log evidence for Verifact.

.DESCRIPTION
Discovers the channels defined in config/event-scope.json, records their state
and retained time boundaries, and exports events within the requested UTC
lookback to EVTX files. The script never enables, clears, resizes, or otherwise
changes a Windows event channel.

Every export is hashed with SHA-256 and described in manifest.json. Missing,
disabled, empty, inaccessible, out-of-window, and failed channels remain visible
as explicit dispositions.

.PARAMETER Days
Lookback in days. If omitted, uses defaultWindowDays from the scope file.

.PARAMETER OutputRoot
Parent directory for run folders. Defaults to evidence/runs in the project.

.PARAMETER ScopePath
Path to the event-channel scope JSON.

.PARAMETER InventoryOnly
Discovers channels and writes metadata but does not export EVTX files. This is
useful for validating access and scope before a full collection.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$Days,

    [string]$OutputRoot,

    [string]$ScopePath,

    [switch]$InventoryOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($ScopePath)) {
    $ScopePath = Join-Path $projectRoot 'config\event-scope.json'
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path (Get-Location) 'verifact-assessment\evidence\events\runs'
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$Depth = 12
    )

    $json = $Value | ConvertTo-Json -Depth $Depth
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $safe = $Value -replace '[\\/:*?"<>|\s]+', '_'
    $safe = $safe.Trim('_')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return 'unnamed-channel'
    }
    return $safe
}

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function ConvertTo-UtcIso {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([datetime]$Value).ToUniversalTime().ToString('o')
    }
    catch {
        return $null
    }
}

function Get-ChannelBoundary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [switch]$Oldest
    )

    try {
        if ($Oldest) {
            $eventRecord = Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop
        }
        else {
            $eventRecord = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        }

        return [ordered]@{
            available      = $true
            timeCreatedUtc = ConvertTo-UtcIso -Value $eventRecord.TimeCreated
            recordId       = $eventRecord.RecordId
            eventId        = $eventRecord.Id
            provider       = $eventRecord.ProviderName
            error          = $null
        }
    }
    catch {
        return [ordered]@{
            available      = $false
            timeCreatedUtc = $null
            recordId       = $null
            eventId        = $null
            provider       = $null
            error          = $_.Exception.Message
        }
    }
}

function Invoke-NativeReadOnly {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    $output = @(& $FilePath @ArgumentList 2>&1)
    $exitCode = $LASTEXITCODE

    return [ordered]@{
        exitCode = $exitCode
        output   = @($output | ForEach-Object { $_.ToString() })
    }
}

function Get-HostIdentity {
    $machineGuid = $null
    $systemUuid = $null
    try { $machineGuid = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction Stop) } catch { }
    try { $systemUuid = [string](Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID } catch { }
    $strength = if ($machineGuid -and $systemUuid) { 'strong' } elseif ($machineGuid -or $systemUuid) { 'degraded' } else { 'weak' }
    $material = "$($scope.assessmentId)|$machineGuid|$systemUuid|$([Environment]::MachineName)".ToLowerInvariant()
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($material)
        $digest = $algorithm.ComputeHash($bytes)
        $hash = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
    return [ordered]@{ sha256 = $hash; strength = $strength }
}

if (-not (Test-Path -LiteralPath $ScopePath -PathType Leaf)) {
    throw "Scope configuration not found: $ScopePath"
}

$scope = Get-Content -LiteralPath $ScopePath -Raw | ConvertFrom-Json
if ($null -eq $scope.channels -or @($scope.channels).Count -eq 0) {
    throw 'Scope configuration contains no event channels.'
}

foreach ($excludedFamily in @($scope.excludedFamilies)) {
    foreach ($configuredChannel in @($scope.channels)) {
        if ($configuredChannel.name -like "*$excludedFamily*") {
            throw "Excluded family '$excludedFamily' appears in configured channel '$($configuredChannel.name)'."
        }
    }
}

if (-not $PSBoundParameters.ContainsKey('Days')) {
    $Days = [int]$scope.defaultWindowDays
}

$collectionStartedUtc = [datetime]::UtcNow
$cutoffUtc = $collectionStartedUtc.AddDays(-$Days)
$cutoffText = $cutoffUtc.ToString(
    'yyyy-MM-ddTHH:mm:ss.fffZ',
    [System.Globalization.CultureInfo]::InvariantCulture
)
$randomSuffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$runId = '{0}_{1}_{2}' -f $collectionStartedUtc.ToString('yyyyMMddTHHmmssZ'), (ConvertTo-SafeFileName -Value ([Environment]::MachineName)), $randomSuffix
$runDirectory = Join-Path $OutputRoot $runId
$rawLogDirectory = Join-Path $runDirectory 'raw\event-logs'
$metadataDirectory = Join-Path $runDirectory 'metadata'
$collectionLogDirectory = Join-Path $runDirectory 'logs'

if (Test-Path -LiteralPath $runDirectory) {
    throw "Event run directory already exists: $runDirectory"
}

foreach ($directory in @($OutputRoot, $runDirectory, $rawLogDirectory, $metadataDirectory, $collectionLogDirectory)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
}

$transcriptPath = Join-Path $collectionLogDirectory 'collection-transcript.txt'
$transcriptStarted = $false
$transcriptError = $null
try {
    $null = Start-Transcript -Path $transcriptPath -Force
    $transcriptStarted = $true
}
catch {
    $transcriptError = $_.Exception.Message
}

$channelResults = @()
$collectionErrors = @()
$auditPolicyResult = [ordered]@{
    status   = 'not-attempted'
    path     = $null
    exitCode = $null
    error    = $null
}

try {
    Write-Host "Verifact run: $runId"
    Write-Host "Requested UTC window: $cutoffText through $($collectionStartedUtc.ToString('o'))"
    Write-Host "Mode: $(if ($InventoryOnly) { 'inventory-only' } else { 'full EVTX export' })"

    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($windowsIdentity)
    $isAdministrator = $windowsPrincipal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $hostIdentity = Get-HostIdentity

    $timeZone = $null
    try {
        $timeZoneInfo = Get-TimeZone -ErrorAction Stop
        $timeZone = [ordered]@{
            id          = $timeZoneInfo.Id
            displayName = $timeZoneInfo.DisplayName
            baseUtcOffset = $timeZoneInfo.BaseUtcOffset.ToString()
        }
    }
    catch {
        $timeZoneFallback = Invoke-NativeReadOnly -FilePath 'tzutil.exe' -ArgumentList @('/g')
        $timeZone = [ordered]@{
            id            = if ($timeZoneFallback.exitCode -eq 0) { $timeZoneFallback.output -join '' } else { $null }
            displayName   = $null
            baseUtcOffset = $null
            error         = if ($timeZoneFallback.exitCode -ne 0) { $timeZoneFallback.output -join [Environment]::NewLine } else { $null }
        }
    }

    $operatingSystem = $null
    $operatingSystemError = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $operatingSystem = [ordered]@{
            caption        = $os.Caption
            version        = $os.Version
            buildNumber    = $os.BuildNumber
            architecture   = $os.OSArchitecture
            lastBootUtc    = ConvertTo-UtcIso -Value $os.LastBootUpTime
        }
    }
    catch {
        $operatingSystemError = $_.Exception.Message
    }

    $hostContext = [ordered]@{
        schemaVersion       = '1.0'
        runId               = $runId
        computerName        = [Environment]::MachineName
        hostIdentitySha256  = $hostIdentity.sha256
        hostIdentityStrength = $hostIdentity.strength
        collectionIdentity  = $windowsIdentity.Name
        isAdministrator     = $isAdministrator
        collectionStartedUtc = $collectionStartedUtc.ToString('o')
        requestedCutoffUtc  = $cutoffUtc.ToString('o')
        requestedDays       = $Days
        timeZone            = $timeZone
        operatingSystem     = $operatingSystem
        operatingSystemError = $operatingSystemError
        powerShellVersion   = $PSVersionTable.PSVersion.ToString()
        processArchitecture = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
        machineArchitecture = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
    }
    $hostContextPath = Join-Path $metadataDirectory 'host-context.json'
    Write-JsonFile -Value $hostContext -Path $hostContextPath

    $scopeSnapshotPath = Join-Path $metadataDirectory 'event-scope.json'
    Copy-Item -LiteralPath $ScopePath -Destination $scopeSnapshotPath -Force

    $collectorSnapshotPath = Join-Path $metadataDirectory 'collector.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $collectorSnapshotPath -Force

    try {
        $auditPolicyPath = Join-Path $metadataDirectory 'audit-policy.csv'
        $auditPolicyCommand = Invoke-NativeReadOnly -FilePath 'auditpol.exe' -ArgumentList @('/get', '/category:*', '/r')
        $auditPolicyResult.exitCode = $auditPolicyCommand.exitCode
        if ($auditPolicyCommand.exitCode -eq 0) {
            Set-Content -LiteralPath $auditPolicyPath -Value $auditPolicyCommand.output -Encoding UTF8
            $auditPolicyResult.status = 'collected'
            $auditPolicyResult.path = 'metadata/audit-policy.csv'
        }
        else {
            $auditPolicyResult.status = 'failed'
            $auditPolicyResult.error = $auditPolicyCommand.output -join [Environment]::NewLine
        }
    }
    catch {
        $auditPolicyResult.status = 'failed'
        $auditPolicyResult.error = $_.Exception.Message
    }

    foreach ($configuredChannel in @($scope.channels)) {
        $channelName = [string]$configuredChannel.name
        $channelResult = [ordered]@{
            name                 = $channelName
            tier                 = [string]$configuredChannel.tier
            reason               = [string]$configuredChannel.reason
            discoveryStatus      = $null
            enabled              = $null
            recordCount          = $null
            logMode              = $null
            maximumSizeInBytes   = $null
            fileSize             = $null
            logFilePath          = $null
            oldestRetained       = $null
            newestRetained       = $null
            requestedCutoffUtc   = $cutoffUtc.ToString('o')
            exportStatus         = 'not-attempted'
            exportPath           = $null
            exportSizeBytes      = $null
            sha256               = $null
            exportExitCode       = $null
            error                = $null
        }

        $logInfo = $null
        try {
            $logInfo = Get-WinEvent -ListLog $channelName -ErrorAction Stop
            $channelResult.discoveryStatus = 'present'
            $channelResult.enabled = [bool](Get-OptionalProperty -InputObject $logInfo -Name 'IsEnabled')
            $channelResult.recordCount = Get-OptionalProperty -InputObject $logInfo -Name 'RecordCount'
            $logModeValue = Get-OptionalProperty -InputObject $logInfo -Name 'LogMode'
            $channelResult.logMode = if ($null -ne $logModeValue) { $logModeValue.ToString() } else { $null }
            $channelResult.maximumSizeInBytes = Get-OptionalProperty -InputObject $logInfo -Name 'MaximumSizeInBytes'
            $channelResult.fileSize = Get-OptionalProperty -InputObject $logInfo -Name 'FileSize'
            $channelResult.logFilePath = Get-OptionalProperty -InputObject $logInfo -Name 'LogFilePath'
        }
        catch {
            $channelResult.discoveryStatus = 'missing-or-inaccessible'
            $channelResult.exportStatus = 'not-exported'
            $channelResult.error = $_.Exception.Message
            $channelResults += [pscustomobject]$channelResult
            continue
        }

        if (-not $channelResult.enabled) {
            $channelResult.discoveryStatus = 'disabled'
            $channelResult.exportStatus = 'not-exported'
            $channelResults += [pscustomobject]$channelResult
            continue
        }

        if ($null -eq $channelResult.recordCount -or [long]$channelResult.recordCount -eq 0) {
            $channelResult.discoveryStatus = 'empty'
            $channelResult.exportStatus = 'not-exported'
            $channelResults += [pscustomobject]$channelResult
            continue
        }

        $oldestBoundary = Get-ChannelBoundary -LogName $channelName -Oldest
        $newestBoundary = Get-ChannelBoundary -LogName $channelName
        $channelResult.oldestRetained = $oldestBoundary
        $channelResult.newestRetained = $newestBoundary

        if (-not $oldestBoundary.available -or -not $newestBoundary.available) {
            $channelResult.discoveryStatus = 'present-boundary-read-failed'
            $channelResult.exportStatus = 'not-exported'
            $channelResult.error = @(
                $oldestBoundary.error
                $newestBoundary.error
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            $channelResults += [pscustomobject]$channelResult
            continue
        }

        if ($InventoryOnly) {
            $channelResult.exportStatus = 'inventory-only'
            $channelResults += [pscustomobject]$channelResult
            continue
        }

        if ([datetime]$newestBoundary.timeCreatedUtc -lt $cutoffUtc) {
            $channelResult.exportStatus = 'outside-requested-window'
            $channelResults += [pscustomobject]$channelResult
            continue
        }

        $safeChannelName = ConvertTo-SafeFileName -Value $channelName
        $exportFileName = "$safeChannelName.evtx"
        $exportPath = Join-Path $rawLogDirectory $exportFileName
        $relativeExportPath = "raw/event-logs/$exportFileName"
        $xpath = "*[System[TimeCreated[@SystemTime >= '$cutoffText']]]"

        try {
            $exportCommand = Invoke-NativeReadOnly -FilePath 'wevtutil.exe' -ArgumentList @(
                'epl',
                $channelName,
                $exportPath,
                "/q:$xpath",
                '/ow:true'
            )
            $channelResult.exportExitCode = $exportCommand.exitCode

            if ($exportCommand.exitCode -ne 0) {
                $channelResult.exportStatus = 'export-failed'
                $channelResult.error = $exportCommand.output -join [Environment]::NewLine
            }
            elseif (-not (Test-Path -LiteralPath $exportPath -PathType Leaf)) {
                $channelResult.exportStatus = 'export-failed'
                $channelResult.error = 'wevtutil returned success but did not create an EVTX file.'
            }
            else {
                $exportFile = Get-Item -LiteralPath $exportPath
                $hash = Get-FileHash -LiteralPath $exportPath -Algorithm SHA256
                $channelResult.exportStatus = 'exported'
                $channelResult.exportPath = $relativeExportPath
                $channelResult.exportSizeBytes = $exportFile.Length
                $channelResult.sha256 = $hash.Hash.ToLowerInvariant()
            }
        }
        catch {
            $channelResult.exportStatus = 'export-failed'
            $channelResult.error = $_.Exception.Message
        }

        $channelResults += [pscustomobject]$channelResult
    }

    $channelInventoryPath = Join-Path $metadataDirectory 'channel-inventory.json'
    Write-JsonFile -Value @($channelResults) -Path $channelInventoryPath
}
catch {
    $collectionErrors += $_.Exception.Message
    Write-Error $_
}
finally {
    $collectionCompletedUtc = [datetime]::UtcNow
    $exportFailures = @($channelResults | Where-Object { $_.exportStatus -eq 'export-failed' })
    $discoveryFailures = @($channelResults | Where-Object { $_.discoveryStatus -eq 'missing-or-inaccessible' })
    $coreCoverageFailures = @(
        $channelResults | Where-Object {
            $_.tier -eq 'core' -and (
                $_.discoveryStatus -in @('missing-or-inaccessible', 'disabled', 'present-boundary-read-failed') -or
                (-not $InventoryOnly -and $_.discoveryStatus -ne 'empty' -and $_.exportStatus -in @('export-failed', 'not-exported'))
            )
        }
    )

    $overallStatus = if ($InventoryOnly) {
        if ($collectionErrors.Count -gt 0) { 'inventory-failed' }
        elseif ($coreCoverageFailures.Count -gt 0) { 'inventory-completed-degraded' }
        else { 'inventory-completed' }
    }
    elseif ($collectionErrors.Count -gt 0) {
        'failed'
    }
    elseif ($coreCoverageFailures.Count -gt 0 -or $exportFailures.Count -gt 0) {
        'completed-degraded'
    }
    else {
        'completed'
    }

    if ($transcriptStarted) {
        try {
            $null = Stop-Transcript
        }
        catch {
            $transcriptError = "Unable to stop transcript cleanly: $($_.Exception.Message)"
        }
    }

    function Get-FileReference {
        param(
            [Parameter(Mandatory = $true)][string]$AbsolutePath,
            [Parameter(Mandatory = $true)][string]$RelativePath
        )
        if (-not (Test-Path -LiteralPath $AbsolutePath -PathType Leaf)) { return $null }
        $item = Get-Item -LiteralPath $AbsolutePath
        $hash = Get-FileHash -LiteralPath $AbsolutePath -Algorithm SHA256
        return [ordered]@{
            path = $RelativePath
            sizeBytes = [long]$item.Length
            sha256 = $hash.Hash.ToLowerInvariant()
        }
    }

    $collectorReference = Get-FileReference -AbsolutePath (Join-Path $metadataDirectory 'collector.ps1') -RelativePath 'metadata/collector.ps1'
    $scopeReference = Get-FileReference -AbsolutePath (Join-Path $metadataDirectory 'event-scope.json') -RelativePath 'metadata/event-scope.json'
    $hostReference = Get-FileReference -AbsolutePath (Join-Path $metadataDirectory 'host-context.json') -RelativePath 'metadata/host-context.json'
    $auditReference = Get-FileReference -AbsolutePath (Join-Path $metadataDirectory 'audit-policy.csv') -RelativePath 'metadata/audit-policy.csv'
    $inventoryReference = Get-FileReference -AbsolutePath (Join-Path $metadataDirectory 'channel-inventory.json') -RelativePath 'metadata/channel-inventory.json'
    $transcriptReference = Get-FileReference -AbsolutePath $transcriptPath -RelativePath 'logs/collection-transcript.txt'

    $artifacts = @()
    foreach ($reference in @($collectorReference, $scopeReference, $hostReference, $auditReference, $inventoryReference, $transcriptReference)) {
        if ($null -ne $reference) { $artifacts += [pscustomobject]$reference }
    }
    foreach ($channel in @($channelResults | Where-Object { $_.exportStatus -eq 'exported' })) {
        $artifacts += [pscustomobject][ordered]@{
            path = [string]$channel.exportPath
            sizeBytes = [long]$channel.exportSizeBytes
            sha256 = [string]$channel.sha256
            channel = [string]$channel.name
            tier = [string]$channel.tier
        }
    }

    $manifest = [ordered]@{
        schemaVersion           = '2.0'
        runId                   = $runId
        status                  = $overallStatus
        mode                    = if ($InventoryOnly) { 'inventory-only' } else { 'full-export' }
        assessmentDomain        = 'event-evidence'
        assessmentId            = [string]$scope.assessmentId
        currentHostOnly         = $true
        hostIdentitySha256      = $hostIdentity.sha256
        hostIdentityStrength    = $hostIdentity.strength
        readOnlyCollection      = $true
        defenderSpecificCollectionExcluded = $true
        collectionStartedUtc    = $collectionStartedUtc.ToString('o')
        collectionCompletedUtc  = $collectionCompletedUtc.ToString('o')
        requestedDays           = $Days
        requestedCutoffUtc      = $cutoffUtc.ToString('o')
        scopeConfigSource       = $ScopePath
        scopeConfigSnapshot     = 'metadata/event-scope.json'
        collectionPlanSha256    = if ($scopeReference) { $scopeReference.sha256 } else { $null }
        collectorSnapshot       = 'metadata/collector.ps1'
        collectorSha256         = if ($collectorReference) { $collectorReference.sha256 } else { $null }
        hostContext             = 'metadata/host-context.json'
        auditPolicy             = $auditPolicyResult
        transcript              = [ordered]@{
            status = if ($transcriptReference) { 'collected' } else { 'failed' }
            path = if ($transcriptReference) { $transcriptReference.path } else { $null }
            sizeBytes = if ($transcriptReference) { $transcriptReference.sizeBytes } else { $null }
            sha256 = if ($transcriptReference) { $transcriptReference.sha256 } else { $null }
            error = $transcriptError
        }
        coverage                = [ordered]@{
            status = if ($coreCoverageFailures.Count -gt 0) { 'degraded' } else { 'complete' }
            coreFailures = @($coreCoverageFailures | ForEach-Object {
                [ordered]@{
                    name = $_.name
                    discoveryStatus = $_.discoveryStatus
                    exportStatus = $_.exportStatus
                    error = $_.error
                }
            })
        }
        channelSummary          = [ordered]@{
            configured        = @($scope.channels).Count
            discovered        = @($channelResults | Where-Object { $_.discoveryStatus -notin @('missing-or-inaccessible', $null) }).Count
            missingOrDenied   = $discoveryFailures.Count
            exported          = @($channelResults | Where-Object { $_.exportStatus -eq 'exported' }).Count
            exportFailures    = $exportFailures.Count
            coreCoverageGaps  = $coreCoverageFailures.Count
        }
        channels                = @($channelResults)
        artifacts               = @($artifacts)
        collectionErrors        = @($collectionErrors)
    }

    try {
        $manifestPath = Join-Path $runDirectory 'manifest.json'
        Write-JsonFile -Value $manifest -Path $manifestPath -Depth 18
    }
    catch {
        Write-Error "Unable to write manifest: $($_.Exception.Message)"
    }

    Write-Host "Verifact collection status: $overallStatus"
    Write-Host "Run directory: $runDirectory"
}

if ($collectionErrors.Count -gt 0) {
    exit 1
}
