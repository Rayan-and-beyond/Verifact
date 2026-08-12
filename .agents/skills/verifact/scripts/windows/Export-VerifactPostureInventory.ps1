#requires -Version 5.1

<#
.SYNOPSIS
Builds a bounded factual inventory from one frozen Verifact posture run.

.DESCRIPTION
Verifies every manifest-referenced file before parsing any artifact, then
normalizes only fields needed by Phase 9 analysis. Raw evidence is never
modified. Output is descriptive inventory, not a vulnerability assessment and
not a finding disposition.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunDirectory,

    [ValidateRange(1, 50000)]
    [int]$MaxRowsPerCheck = 5000,

    [ValidateRange(256, 32768)]
    [int]$MaxFieldCharacters = 4096
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$manifestPath = $null

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "JSON file is empty: $Path"
    }
    return $text | ConvertFrom-Json
}

function Resolve-BoundedChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $candidate = $RelativePath.Trim()
    if (
        [string]::IsNullOrWhiteSpace($candidate) -or
        [System.IO.Path]::IsPathRooted($candidate) -or
        $candidate.StartsWith('\\') -or
        $candidate -match '^[A-Za-z]+::' -or
        $candidate -match '^[A-Za-z]+:'
    ) {
        throw "Artifact path is not a bounded relative path: $RelativePath"
    }

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $childFull = [System.IO.Path]::GetFullPath(
        (Join-Path $rootFull ($candidate -replace '/', '\'))
    )
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Artifact path escapes the posture run: $RelativePath"
    }
    return $childFull
}

function Get-PropertyValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Default = $null
    )
    if ($null -eq $Object) {
        return $Default
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }
    return $property.Value
}

function Get-FirstPropertyValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    foreach ($name in $Names) {
        $property = if ($null -ne $Object) { $Object.PSObject.Properties[$name] } else { $null }
        if ($null -ne $property -and $null -ne $property.Value) {
            return $property.Value
        }
    }
    return $null
}

function ConvertTo-NormalizedSid {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim().TrimStart('*')
    if ($text -match '(?i)^S-\d-(?:\d+-){1,14}\d+$') {
        return $text.ToUpperInvariant()
    }
    return $text
}

function ConvertTo-NormalizedPath {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text = $text -replace '/', '\'
    if ($text -match '^[a-zA-Z]:\\') {
        $text = $text.Substring(0, 1).ToUpperInvariant() + $text.Substring(1)
    }
    return $text
}

function Get-ExecutableFromCommand {
    param([AllowNull()][object]$Command)
    if ($null -eq $Command) { return $null }
    $text = ([string]$Command).Trim()
    if ($text -match '^\s*"([^"]+)"') {
        return ConvertTo-NormalizedPath $matches[1]
    }
    if ($text -match '(?i)^\s*(.+?\.(?:exe|com|dll|sys|ps1|bat|cmd|vbs|js|msi))(?=\s|$)') {
        return ConvertTo-NormalizedPath $matches[1]
    }
    return $null
}

function ConvertTo-NormalizedAddress {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim().Trim('[', ']')
    [System.Net.IPAddress]$parsed = $null
    if ([System.Net.IPAddress]::TryParse($text, [ref]$parsed)) {
        return $parsed.ToString()
    }
    return $text
}

function Join-StableValues {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $values = @(
        @($Value) |
            ForEach-Object { if ($null -ne $_) { ([string]$_).Trim() } } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )
    if ($values.Count -eq 0) { return $null }
    return $values -join ' | '
}

function Test-DefenderContent {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    $text = $Value | ConvertTo-Json -Compress -Depth 12
    return $text -match '(?i)\b(?:Microsoft|Windows)\s+Defender\b'
}

function ConvertTo-FlatValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    return ($Value | ConvertTo-Json -Compress -Depth 8)
}

$resolvedRun = (Resolve-Path -LiteralPath $RunDirectory).Path
$runPrefix = $resolvedRun.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if ($null -eq $manifestPath) {
    $manifestPath = Join-Path $resolvedRun 'manifest.json'
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Manifest not found: $manifestPath"
}

$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = Read-JsonFile $manifestPath
if ([string]$manifest.runId -ne (Split-Path -Leaf $resolvedRun)) {
    throw 'Manifest run ID does not match the run directory.'
}
if ([string]$manifest.mode -ne 'full-snapshot') {
    throw "Run mode '$($manifest.mode)' is not full-snapshot."
}
if ([string]$manifest.status -notin @('completed', 'completed-with-limitations')) {
    throw "Run status '$($manifest.status)' is not authorized for normalization."
}
if (
    [string]$manifest.assessmentDomain -ne 'host-posture' -or
    -not [bool]$manifest.currentHostOnly -or
    -not [bool]$manifest.readOnlyCollection -or
    -not [bool]$manifest.defenderSpecificCollectionExcluded
) {
    throw 'Manifest does not preserve the required host-posture safety declarations.'
}

$artifacts = @($manifest.artifacts)
$duplicateIds = @(
    $artifacts |
        Group-Object -Property id |
        Where-Object Count -gt 1 |
        ForEach-Object Name
)
if ($duplicateIds.Count -gt 0) {
    throw "Manifest contains duplicate artifact IDs: $($duplicateIds -join ', ')"
}

# Integrity pass: no artifact content is parsed until all file references pass.
$verifiedPaths = @{}
$integrityFailures = @()
foreach ($artifact in $artifacts) {
    $artifactLabel = "$($artifact.id) $($artifact.description) $($artifact.path)"
    if ($artifactLabel -match '(?i)\b(?:Microsoft|Windows)\s+Defender\b') {
        $integrityFailures += "Excluded Defender artifact is present: $($artifact.id)"
        continue
    }

    $hasPath = -not [string]::IsNullOrWhiteSpace([string]$artifact.path)
    if (-not $hasPath) {
        if ([string]$artifact.status -in @('collected', 'partial', 'empty')) {
            $integrityFailures += "Artifact '$($artifact.id)' has status '$($artifact.status)' but no file path."
        }
        continue
    }

    try {
        $path = Resolve-BoundedChildPath -Root $resolvedRun -RelativePath ([string]$artifact.path)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'referenced file does not exist'
        }
        $item = Get-Item -LiteralPath $path
        if ($null -eq $artifact.sizeBytes -or [long]$artifact.sizeBytes -ne [long]$item.Length) {
            throw "byte length mismatch (manifest $($artifact.sizeBytes), actual $($item.Length))"
        }
        if ([string]::IsNullOrWhiteSpace([string]$artifact.sha256)) {
            throw 'SHA-256 is missing'
        }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne ([string]$artifact.sha256).ToLowerInvariant()) {
            throw 'SHA-256 mismatch'
        }
        $verifiedPaths[[string]$artifact.id] = $path
    }
    catch {
        $integrityFailures += "Artifact '$($artifact.id)': $($_.Exception.Message)"
    }
}

if ([string]$manifest.transcript.status -eq 'collected') {
    try {
        $transcriptPath = Resolve-BoundedChildPath -Root $resolvedRun -RelativePath ([string]$manifest.transcript.path)
        $transcriptItem = Get-Item -LiteralPath $transcriptPath
        $transcriptHash = (Get-FileHash -LiteralPath $transcriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if (
            [long]$transcriptItem.Length -ne [long]$manifest.transcript.sizeBytes -or
            $transcriptHash -ne ([string]$manifest.transcript.sha256).ToLowerInvariant()
        ) {
            throw 'transcript byte length or SHA-256 mismatch'
        }
    }
    catch {
        $integrityFailures += "Transcript: $($_.Exception.Message)"
    }
}

if ($integrityFailures.Count -gt 0) {
    throw "Posture evidence integrity validation failed before parsing:`n - $($integrityFailures -join "`n - ")"
}

$sets = @{
    identity              = @()
    controls              = @()
    persistence           = @()
    'network-exposure'    = @()
    'sharing-permissions' = @()
    'updates-software'    = @()
}
$emittedByCheck = @{}
$omittedByCheck = @{}
$defenderRowsExcluded = 0
$fieldValuesTruncated = 0
$unreliableTargetAclAttributionRows = 0
$normalizationNotes = @{}

function Add-NormalizedRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Set,
        [Parameter(Mandatory = $true)][object]$Artifact,
        [Parameter(Mandatory = $true)][string]$RecordType,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fields
    )

    $checkId = [string]$Artifact.id
    if (-not $emittedByCheck.ContainsKey($checkId)) { $emittedByCheck[$checkId] = 0 }
    if (-not $omittedByCheck.ContainsKey($checkId)) { $omittedByCheck[$checkId] = 0 }
    if ([int]$emittedByCheck[$checkId] -ge $MaxRowsPerCheck) {
        $omittedByCheck[$checkId] = [int]$omittedByCheck[$checkId] + 1
        return
    }

    $row = [ordered]@{
        schemaVersion   = '1.0'
        runId           = [string]$manifest.runId
        checkId         = $checkId
        category        = [string]$Artifact.category
        artifactPath    = [string]$Artifact.path
        artifactSha256  = ([string]$Artifact.sha256).ToLowerInvariant()
        collectedUtc    = [string]$Artifact.completedUtc
        recordType      = $RecordType
        presentation    = 'Observed'
    }
    foreach ($key in $Fields.Keys) {
        $value = $Fields[$key]
        if ($value -is [string] -and $value.Length -gt $MaxFieldCharacters) {
            $value = $value.Substring(0, $MaxFieldCharacters) + '... [truncated]'
            $script:fieldValuesTruncated++
        }
        $row[[string]$key] = $value
    }
    $sets[$Set] += [pscustomobject]$row
    $emittedByCheck[$checkId] = [int]$emittedByCheck[$checkId] + 1
}

function Add-FlatControlObject {
    param(
        [Parameter(Mandatory = $true)][object]$Artifact,
        [Parameter(Mandatory = $true)][string]$Namespace,
        [AllowNull()][object]$Object
    )
    if ($null -eq $Object) { return }
    foreach ($property in $Object.PSObject.Properties) {
        Add-NormalizedRecord -Set 'controls' -Artifact $Artifact -RecordType 'control' -Fields ([ordered]@{
            namespace = $Namespace
            setting   = [string]$property.Name
            present   = $true
            value     = ConvertTo-FlatValue $property.Value
            sourcePath = $null
            error     = $null
        })
    }
}

function Add-AclObject {
    param(
        [Parameter(Mandatory = $true)][object]$Artifact,
        [Parameter(Mandatory = $true)][string]$SourceKind,
        [AllowNull()][object]$SourceName,
        [AllowNull()][object]$TargetPath,
        [Parameter(Mandatory = $true)][string]$AclScope,
        [AllowNull()][object]$Acl,
        [AllowNull()][object]$Signature,
        [bool]$SourceNameAttributionReliable = $true,
        [AllowNull()][string]$AttributionNote = $null
    )
    if ($null -eq $Acl) { return }
    $access = @((Get-PropertyValue $Acl 'access' @()))
    if ($access.Count -eq 0) {
        Add-NormalizedRecord -Set 'sharing-permissions' -Artifact $Artifact -RecordType 'acl' -Fields ([ordered]@{
            sourceKind       = $SourceKind
            sourceName       = $SourceName
            sourceNameAttributionReliable = $SourceNameAttributionReliable
            attributionNote  = $AttributionNote
            targetPath       = ConvertTo-NormalizedPath $TargetPath
            aclScope         = $AclScope
            aclPath          = ConvertTo-NormalizedPath (Get-PropertyValue $Acl 'path')
            exists           = Get-PropertyValue $Acl 'exists'
            owner            = Get-PropertyValue $Acl 'owner'
            protected        = Get-PropertyValue $Acl 'protected'
            identity         = $null
            accessType       = $null
            rights           = $null
            inherited        = $null
            inheritance      = $null
            propagation      = $null
            signatureStatus  = Get-PropertyValue $Signature 'status'
            signerSubject    = Get-PropertyValue $Signature 'signerSubject'
            signerIssuer     = Get-PropertyValue $Signature 'signerIssuer'
            signatureError   = Get-PropertyValue $Signature 'error'
            aclError         = Get-PropertyValue $Acl 'error'
        })
        return
    }
    foreach ($ace in $access) {
        Add-NormalizedRecord -Set 'sharing-permissions' -Artifact $Artifact -RecordType 'acl-entry' -Fields ([ordered]@{
            sourceKind       = $SourceKind
            sourceName       = $SourceName
            sourceNameAttributionReliable = $SourceNameAttributionReliable
            attributionNote  = $AttributionNote
            targetPath       = ConvertTo-NormalizedPath $TargetPath
            aclScope         = $AclScope
            aclPath          = ConvertTo-NormalizedPath (Get-PropertyValue $Acl 'path')
            exists           = Get-PropertyValue $Acl 'exists'
            owner            = Get-PropertyValue $Acl 'owner'
            protected        = Get-PropertyValue $Acl 'protected'
            identity         = Get-PropertyValue $ace 'identity'
            accessType       = Get-PropertyValue $ace 'type'
            rights           = Get-PropertyValue $ace 'rights'
            inherited        = Get-PropertyValue $ace 'inherited'
            inheritance      = Get-PropertyValue $ace 'inheritance'
            propagation      = Get-PropertyValue $ace 'propagation'
            signatureStatus  = Get-PropertyValue $Signature 'status'
            signerSubject    = Get-PropertyValue $Signature 'signerSubject'
            signerIssuer     = Get-PropertyValue $Signature 'signerIssuer'
            signatureError   = Get-PropertyValue $Signature 'error'
            aclError         = Get-PropertyValue $Acl 'error'
        })
    }
}

foreach ($artifact in $artifacts) {
    $checkId = [string]$artifact.id
    if (-not $emittedByCheck.ContainsKey($checkId)) { $emittedByCheck[$checkId] = 0 }
    if (-not $omittedByCheck.ContainsKey($checkId)) { $omittedByCheck[$checkId] = 0 }
    if (-not $verifiedPaths.ContainsKey($checkId) -or [string]$artifact.category -eq 'metadata') {
        continue
    }
    if ([string]$artifact.status -notin @('collected', 'partial', 'empty')) {
        $normalizationNotes[$checkId] = "Artifact status '$($artifact.status)' is not safe for content normalization; disposition remains in the artifact ledger."
        continue
    }

    $path = [string]$verifiedPaths[$checkId]
    $data = $null
    switch ([string]$artifact.format) {
        'json' { $data = Read-JsonFile $path }
        'csv'  {
            $text = Get-Content -LiteralPath $path -Raw -Encoding UTF8
            $data = if ([string]::IsNullOrWhiteSpace($text)) { @() } else { @($text | ConvertFrom-Csv) }
        }
        'text' { $data = @(Get-Content -LiteralPath $path -Encoding UTF8) }
        'inf'  { $data = @(Get-Content -LiteralPath $path -Encoding Unicode) }
        default {
            $normalizationNotes[$checkId] = "Unsupported artifact format '$($artifact.format)'; status retained in artifact ledger."
            continue
        }
    }

    switch ($checkId) {
        'identity-local-users' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                Add-NormalizedRecord -Set 'identity' -Artifact $artifact -RecordType 'local-user' -Fields ([ordered]@{
                    name                  = Get-PropertyValue $item 'name'
                    sid                   = ConvertTo-NormalizedSid (Get-PropertyValue $item 'sid')
                    enabled               = Get-PropertyValue $item 'enabled'
                    principalSource       = Get-PropertyValue $item 'principalSource'
                    description           = Get-PropertyValue $item 'description'
                    lastLogonUtc          = Get-PropertyValue $item 'lastLogon'
                    passwordRequired      = Get-PropertyValue $item 'passwordRequired'
                    passwordExpiresUtc    = Get-PropertyValue $item 'passwordExpires'
                    passwordLastSetUtc    = Get-PropertyValue $item 'passwordLastSet'
                    userMayChangePassword = Get-PropertyValue $item 'userMayChangePassword'
                })
            }
        }
        'identity-local-groups' {
            foreach ($group in @($data)) {
                Add-NormalizedRecord -Set 'identity' -Artifact $artifact -RecordType 'local-group' -Fields ([ordered]@{
                    name        = Get-PropertyValue $group 'name'
                    sid         = ConvertTo-NormalizedSid (Get-PropertyValue $group 'sid')
                    description = Get-PropertyValue $group 'description'
                    memberError = Get-PropertyValue $group 'memberError'
                })
                foreach ($member in @((Get-PropertyValue $group 'members' @()))) {
                    Add-NormalizedRecord -Set 'identity' -Artifact $artifact -RecordType 'local-group-membership' -Fields ([ordered]@{
                        groupName       = Get-PropertyValue $group 'name'
                        groupSid        = ConvertTo-NormalizedSid (Get-PropertyValue $group 'sid')
                        memberName      = Get-PropertyValue $member 'name'
                        memberSid       = ConvertTo-NormalizedSid (Get-PropertyValue $member 'sid')
                        objectClass     = Get-PropertyValue $member 'objectClass'
                        principalSource = Get-PropertyValue $member 'principalSource'
                    })
                }
            }
        }
        'identity-account-policy' {
            $lineNumber = 0
            foreach ($line in @($data)) {
                $lineNumber++
                $text = ([string]$line).Trim()
                if ([string]::IsNullOrWhiteSpace($text) -or $text -match '^-+$') { continue }
                $setting = "line-$lineNumber"
                $value = $text
                if ($text -match '^\s*(.+?)\s{2,}(.+?)\s*$') {
                    $setting = $matches[1].Trim()
                    $value = $matches[2].Trim()
                }
                Add-NormalizedRecord -Set 'identity' -Artifact $artifact -RecordType 'account-policy' -Fields ([ordered]@{
                    setting = $setting
                    value   = $value
                })
            }
        }
        'identity-security-policy' {
            $section = ''
            foreach ($line in @($data)) {
                $text = ([string]$line).Trim()
                if ($text -match '^\[(.+)\]$') { $section = $matches[1]; continue }
                if ($text -notmatch '^([^;][^=]+?)\s*=\s*(.*)$') { continue }
                $name = $matches[1].Trim()
                $value = $matches[2].Trim()
                if ($section -eq 'Privilege Rights') {
                    foreach ($principal in @($value -split ',')) {
                        if ([string]::IsNullOrWhiteSpace($principal)) { continue }
                        Add-NormalizedRecord -Set 'identity' -Artifact $artifact -RecordType 'user-right-assignment' -Fields ([ordered]@{
                            right     = $name
                            principal = ConvertTo-NormalizedSid $principal
                        })
                    }
                }
                elseif ($section -eq 'System Access') {
                    Add-NormalizedRecord -Set 'identity' -Artifact $artifact -RecordType 'security-policy-setting' -Fields ([ordered]@{
                        setting = $name
                        value   = $value
                    })
                }
            }
        }
        'logging-audit-policy' {
            foreach ($item in @($data)) {
                Add-NormalizedRecord -Set 'controls' -Artifact $artifact -RecordType 'audit-policy' -Fields ([ordered]@{
                    machineName      = Get-PropertyValue $item 'machineName'
                    policyTarget     = Get-PropertyValue $item 'policyTarget'
                    subcategoryName  = Get-PropertyValue $item 'subcategoryName'
                    subcategoryGuid  = Get-PropertyValue $item 'subcategoryGuid'
                    inclusionSetting = Get-PropertyValue $item 'inclusionSetting'
                    exclusionSetting = Get-PropertyValue $item 'exclusionSetting'
                    sourceFields     = $item | ConvertTo-Json -Compress -Depth 4
                })
            }
        }
        'logging-event-channels' {
            foreach ($item in @($data)) {
                Add-NormalizedRecord -Set 'controls' -Artifact $artifact -RecordType 'event-channel' -Fields ([ordered]@{
                    name               = Get-PropertyValue $item 'name'
                    status             = Get-PropertyValue $item 'status'
                    enabled            = Get-PropertyValue $item 'isEnabled'
                    logMode            = Get-PropertyValue $item 'logMode'
                    maximumSizeInBytes = Get-PropertyValue $item 'maximumSizeInBytes'
                    recordCount        = Get-PropertyValue $item 'recordCount'
                    fileSizeBytes      = Get-PropertyValue $item 'fileSize'
                    oldestRecordNumber = Get-PropertyValue $item 'oldestRecordNumber'
                    logFilePath        = ConvertTo-NormalizedPath (Get-PropertyValue $item 'logFilePath')
                    error              = Get-PropertyValue $item 'error'
                })
            }
        }
        'persistence-services' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                $command = Get-PropertyValue $item 'pathName'
                Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'service' -Fields ([ordered]@{
                    name           = Get-PropertyValue $item 'name'
                    displayName    = Get-PropertyValue $item 'displayName'
                    state          = Get-PropertyValue $item 'state'
                    startMode      = Get-PropertyValue $item 'startMode'
                    principal      = Get-PropertyValue $item 'startName'
                    command        = $command
                    executablePath = Get-ExecutableFromCommand $command
                    processId      = Get-PropertyValue $item 'processId'
                    serviceType    = Get-PropertyValue $item 'serviceType'
                    desktopInteract = Get-PropertyValue $item 'desktopInteract'
                    description    = Get-PropertyValue $item 'description'
                })
            }
        }
        'persistence-scheduled-tasks' {
            foreach ($task in @($data)) {
                if (Test-DefenderContent $task) { $defenderRowsExcluded++; continue }
                $actions = @((Get-PropertyValue $task 'actions' @()))
                if ($actions.Count -eq 0) { $actions = @($null) }
                $index = 0
                foreach ($action in $actions) {
                    Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'scheduled-task-action' -Fields ([ordered]@{
                        taskPath        = Get-PropertyValue $task 'taskPath'
                        taskName        = Get-PropertyValue $task 'taskName'
                        state           = Get-PropertyValue $task 'state'
                        author          = Get-PropertyValue $task 'author'
                        principalUser   = Get-PropertyValue (Get-PropertyValue $task 'principal') 'userId'
                        principalGroup  = Get-PropertyValue (Get-PropertyValue $task 'principal') 'groupId'
                        logonType       = Get-PropertyValue (Get-PropertyValue $task 'principal') 'logonType'
                        runLevel        = Get-PropertyValue (Get-PropertyValue $task 'principal') 'runLevel'
                        actionIndex     = $index
                        actionType      = Get-PropertyValue $action 'type'
                        executablePath  = ConvertTo-NormalizedPath (Get-PropertyValue $action 'execute')
                        arguments       = Get-PropertyValue $action 'arguments'
                        workingDirectory = ConvertTo-NormalizedPath (Get-PropertyValue $action 'workingDirectory')
                        triggers        = (Get-PropertyValue $task 'triggers' @()) | ConvertTo-Json -Compress -Depth 6
                    })
                    $index++
                }
            }
        }
        'persistence-startup-commands' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                $command = Get-PropertyValue $item 'command'
                Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'startup-command' -Fields ([ordered]@{
                    name           = Get-PropertyValue $item 'name'
                    command        = $command
                    executablePath = Get-ExecutableFromCommand $command
                    location       = Get-PropertyValue $item 'location'
                    principal      = Get-PropertyValue $item 'user'
                    principalSid   = ConvertTo-NormalizedSid (Get-PropertyValue $item 'userSid')
                })
            }
        }
        'persistence-startup-folders' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'startup-folder-entry' -Fields ([ordered]@{
                    scope          = Get-PropertyValue $item 'scope'
                    folderPath     = ConvertTo-NormalizedPath (Get-PropertyValue $item 'folder')
                    name           = Get-PropertyValue $item 'name'
                    executablePath = ConvertTo-NormalizedPath (Get-PropertyValue $item 'fullName')
                    extension      = Get-PropertyValue $item 'extension'
                    sizeBytes      = Get-PropertyValue $item 'length'
                    lastWriteUtc   = Get-PropertyValue $item 'lastWriteUtc'
                    attributes     = Get-PropertyValue $item 'attributes'
                    error          = Get-PropertyValue $item 'error'
                })
            }
        }
        'persistence-run-keys' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                $command = Get-PropertyValue $item 'value'
                Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'run-key' -Fields ([ordered]@{
                    registryPath   = ConvertTo-NormalizedPath (Get-PropertyValue $item 'key')
                    name           = Get-PropertyValue $item 'name'
                    command        = $command
                    executablePath = Get-ExecutableFromCommand $command
                })
            }
        }
        'persistence-wmi-subscriptions' {
            foreach ($item in @((Get-PropertyValue $data 'filters' @()))) {
                Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'wmi-filter' -Fields ([ordered]@{
                    name           = Get-PropertyValue $item 'name'
                    queryLanguage  = Get-PropertyValue $item 'queryLanguage'
                    eventNamespace = Get-PropertyValue $item 'eventNamespace'
                    query          = Get-PropertyValue $item 'query'
                    relativePath   = Get-PropertyValue $item 'relativePath'
                })
            }
            foreach ($item in @((Get-PropertyValue $data 'consumers' @()))) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                $command = Get-PropertyValue $item 'commandLineTemplate'
                Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'wmi-consumer' -Fields ([ordered]@{
                    name           = Get-PropertyValue $item 'name'
                    consumerClass  = Get-PropertyValue $item 'class'
                    executablePath = ConvertTo-NormalizedPath (Get-PropertyValue $item 'executablePath')
                    command        = $command
                    commandImage   = Get-ExecutableFromCommand $command
                    scriptingEngine = Get-PropertyValue $item 'scriptingEngine'
                    relativePath   = Get-PropertyValue $item 'relativePath'
                })
            }
            foreach ($item in @((Get-PropertyValue $data 'bindings' @()))) {
                Add-NormalizedRecord -Set 'persistence' -Artifact $artifact -RecordType 'wmi-binding' -Fields ([ordered]@{
                    filter       = Get-PropertyValue $item 'filter'
                    consumer     = Get-PropertyValue $item 'consumer'
                    relativePath = Get-PropertyValue $item 'relativePath'
                })
            }
        }
        'exposure-firewall-profiles' {
            foreach ($item in @($data)) {
                Add-NormalizedRecord -Set 'network-exposure' -Artifact $artifact -RecordType 'firewall-profile' -Fields ([ordered]@{
                    name                    = Get-PropertyValue $item 'name'
                    enabled                 = Get-PropertyValue $item 'enabled'
                    defaultInboundAction    = Get-PropertyValue $item 'defaultInboundAction'
                    defaultOutboundAction   = Get-PropertyValue $item 'defaultOutboundAction'
                    allowInboundRules       = Get-PropertyValue $item 'allowInboundRules'
                    allowLocalFirewallRules = Get-PropertyValue $item 'allowLocalFirewallRules'
                    notifyOnListen          = Get-PropertyValue $item 'notifyOnListen'
                    logAllowed              = Get-PropertyValue $item 'logAllowed'
                    logBlocked              = Get-PropertyValue $item 'logBlocked'
                    logFilePath             = ConvertTo-NormalizedPath (Get-PropertyValue $item 'logFileName')
                    logMaxSizeKilobytes     = Get-PropertyValue $item 'logMaxSizeKilobytes'
                })
            }
        }
        'exposure-firewall-inbound-allow' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                Add-NormalizedRecord -Set 'network-exposure' -Artifact $artifact -RecordType 'firewall-inbound-allow-rule' -Fields ([ordered]@{
                    name                  = Get-PropertyValue $item 'name'
                    displayName           = Get-PropertyValue $item 'displayName'
                    displayGroup          = Get-PropertyValue $item 'displayGroup'
                    profile               = Get-PropertyValue $item 'profile'
                    policyStoreSourceType = Get-PropertyValue $item 'policyStoreSourceType'
                    edgeTraversalPolicy   = Get-PropertyValue $item 'edgeTraversalPolicy'
                    protocol              = Join-StableValues (Get-PropertyValue $item 'protocol')
                    localPort             = Join-StableValues (Get-PropertyValue $item 'localPort')
                    remotePort            = Join-StableValues (Get-PropertyValue $item 'remotePort')
                    localAddress          = Join-StableValues (Get-PropertyValue $item 'localAddress')
                    remoteAddress         = Join-StableValues (Get-PropertyValue $item 'remoteAddress')
                    programPath           = Join-StableValues @((Get-PropertyValue $item 'program') | ForEach-Object { ConvertTo-NormalizedPath $_ })
                    service               = Join-StableValues (Get-PropertyValue $item 'service')
                    filterError           = Get-PropertyValue $item 'filterError'
                })
            }
        }
        'exposure-tcp-listeners' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                Add-NormalizedRecord -Set 'network-exposure' -Artifact $artifact -RecordType 'tcp-listener' -Fields ([ordered]@{
                    localAddress  = ConvertTo-NormalizedAddress (Get-PropertyValue $item 'localAddress')
                    localPort     = Get-PropertyValue $item 'localPort'
                    state         = Get-PropertyValue $item 'state'
                    owningProcess = Get-PropertyValue $item 'owningProcess'
                    processName   = Get-PropertyValue $item 'processName'
                    processPath   = ConvertTo-NormalizedPath (Get-PropertyValue $item 'processPath')
                    services      = Join-StableValues (Get-PropertyValue $item 'services')
                })
            }
        }
        'exposure-udp-listeners' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                Add-NormalizedRecord -Set 'network-exposure' -Artifact $artifact -RecordType 'udp-listener' -Fields ([ordered]@{
                    localAddress  = ConvertTo-NormalizedAddress (Get-PropertyValue $item 'localAddress')
                    localPort     = Get-PropertyValue $item 'localPort'
                    state         = $null
                    owningProcess = Get-PropertyValue $item 'owningProcess'
                    processName   = Get-PropertyValue $item 'processName'
                    processPath   = ConvertTo-NormalizedPath (Get-PropertyValue $item 'processPath')
                    services      = Join-StableValues (Get-PropertyValue $item 'services')
                })
            }
        }
        'exposure-rdp-configuration' {
            foreach ($name in @('denyConnections', 'userAuthentication', 'securityLayer', 'minEncryptionLevel')) {
                $state = Get-PropertyValue $data $name
                Add-NormalizedRecord -Set 'controls' -Artifact $artifact -RecordType 'rdp-control' -Fields ([ordered]@{
                    namespace  = 'rdp'
                    setting    = $name
                    present    = Get-PropertyValue $state 'present'
                    value      = Get-PropertyValue $state 'value'
                    sourcePath = ConvertTo-NormalizedPath (Get-PropertyValue $state 'path')
                    error      = Get-PropertyValue $state 'error'
                })
            }
            Add-FlatControlObject -Artifact $artifact -Namespace 'rdp-service' -Object (Get-PropertyValue $data 'service')
            foreach ($listener in @((Get-PropertyValue $data 'listeners' @()))) {
                Add-NormalizedRecord -Set 'network-exposure' -Artifact $artifact -RecordType 'rdp-listener' -Fields ([ordered]@{
                    localAddress  = ConvertTo-NormalizedAddress (Get-PropertyValue $listener 'LocalAddress')
                    localPort     = Get-PropertyValue $listener 'LocalPort'
                    owningProcess = Get-PropertyValue $listener 'OwningProcess'
                    processName   = $null
                    processPath   = $null
                    services      = 'TermService'
                })
            }
        }
        'exposure-winrm-configuration' {
            $lineNumber = 0
            foreach ($line in @($data)) {
                $lineNumber++
                $text = ([string]$line).Trim()
                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                $setting = "line-$lineNumber"
                $value = $text
                if ($text -match '^([^=]+?)\s*=\s*(.*?)\s*$') {
                    $setting = $matches[1].Trim()
                    $value = $matches[2].Trim()
                }
                Add-NormalizedRecord -Set 'controls' -Artifact $artifact -RecordType 'winrm-configuration-line' -Fields ([ordered]@{
                    namespace  = 'winrm'
                    setting    = $setting
                    value      = $value
                    lineNumber = $lineNumber
                })
            }
        }
        'sharing-smb-shares' {
            foreach ($share in @($data)) {
                Add-NormalizedRecord -Set 'sharing-permissions' -Artifact $artifact -RecordType 'smb-share' -Fields ([ordered]@{
                    name                  = Get-PropertyValue $share 'name'
                    path                  = ConvertTo-NormalizedPath (Get-PropertyValue $share 'path')
                    description           = Get-PropertyValue $share 'description'
                    special               = Get-PropertyValue $share 'special'
                    temporary             = Get-PropertyValue $share 'temporary'
                    encryptData           = Get-PropertyValue $share 'encryptData'
                    folderEnumerationMode = Get-PropertyValue $share 'folderEnumerationMode'
                    accessError           = Get-PropertyValue $share 'accessError'
                })
                foreach ($entry in @((Get-PropertyValue $share 'access' @()))) {
                    Add-NormalizedRecord -Set 'sharing-permissions' -Artifact $artifact -RecordType 'smb-share-access' -Fields ([ordered]@{
                        shareName        = Get-PropertyValue $share 'name'
                        sharePath        = ConvertTo-NormalizedPath (Get-PropertyValue $share 'path')
                        principal        = Get-PropertyValue $entry 'accountName'
                        accessType       = Get-PropertyValue $entry 'accessControlType'
                        rights           = Get-PropertyValue $entry 'accessRight'
                    })
                }
                Add-AclObject -Artifact $artifact -SourceKind 'smb-share' -SourceName (Get-PropertyValue $share 'name') -TargetPath (Get-PropertyValue $share 'path') -AclScope 'share-root' -Acl (Get-PropertyValue $share 'rootAcl') -Signature $null
            }
        }
        'hardening-security-controls' {
            foreach ($state in @((Get-PropertyValue $data 'registry' @()))) {
                Add-NormalizedRecord -Set 'controls' -Artifact $artifact -RecordType 'security-control' -Fields ([ordered]@{
                    namespace  = 'registry'
                    setting    = Get-PropertyValue $state 'name'
                    present    = Get-PropertyValue $state 'present'
                    value      = Get-PropertyValue $state 'value'
                    sourcePath = ConvertTo-NormalizedPath (Get-PropertyValue $state 'path')
                    error      = Get-PropertyValue $state 'error'
                })
            }
            Add-FlatControlObject -Artifact $artifact -Namespace 'smb-server' -Object (Get-PropertyValue $data 'smbServer')
            Add-FlatControlObject -Artifact $artifact -Namespace 'smb-client' -Object (Get-PropertyValue $data 'smbClient')
        }
        'hardening-optional-features' {
            foreach ($item in @($data)) {
                Add-NormalizedRecord -Set 'controls' -Artifact $artifact -RecordType 'optional-feature' -Fields ([ordered]@{
                    namespace       = 'windows-optional-feature'
                    setting         = Get-PropertyValue $item 'featureName'
                    value           = Get-PropertyValue $item 'state'
                    restartRequired = Get-PropertyValue $item 'restartRequired'
                    error           = Get-PropertyValue $item 'error'
                })
            }
        }
        'system-os-and-updates' {
            $os = Get-PropertyValue $data 'operatingSystem'
            Add-NormalizedRecord -Set 'updates-software' -Artifact $artifact -RecordType 'operating-system' -Fields ([ordered]@{
                name           = Get-PropertyValue $os 'caption'
                version        = Get-PropertyValue $os 'version'
                buildNumber    = Get-PropertyValue $os 'buildNumber'
                architecture   = Get-PropertyValue $os 'architecture'
                displayVersion = Get-PropertyValue $os 'displayVersion'
                releaseId      = Get-PropertyValue $os 'releaseId'
                updateBuildRevision = Get-PropertyValue $os 'ubr'
                editionId      = Get-PropertyValue $os 'editionId'
                productName    = Get-PropertyValue $os 'productName'
                installUtc     = Get-PropertyValue $os 'installUtc'
                lastBootUtc    = Get-PropertyValue $os 'lastBootUtc'
            })
            foreach ($update in @((Get-PropertyValue $data 'updates' @()))) {
                Add-NormalizedRecord -Set 'updates-software' -Artifact $artifact -RecordType 'installed-update' -Fields ([ordered]@{
                    name        = Get-PropertyValue $update 'hotFixId'
                    description = Get-PropertyValue $update 'description'
                    installedBy = Get-PropertyValue $update 'installedBy'
                    installedOn = Get-PropertyValue $update 'installedOn'
                })
            }
        }
        'system-installed-software' {
            foreach ($item in @($data)) {
                if (Test-DefenderContent $item) { $defenderRowsExcluded++; continue }
                Add-NormalizedRecord -Set 'updates-software' -Artifact $artifact -RecordType 'installed-software' -Fields ([ordered]@{
                    name            = Get-PropertyValue $item 'displayName'
                    version         = Get-PropertyValue $item 'displayVersion'
                    publisher       = Get-PropertyValue $item 'publisher'
                    installDate     = Get-PropertyValue $item 'installDate'
                    installLocation = ConvertTo-NormalizedPath (Get-PropertyValue $item 'installLocation')
                    scope           = Get-PropertyValue $item 'scope'
                })
            }
        }
        'system-reboot-status' {
            foreach ($property in $data.PSObject.Properties) {
                Add-NormalizedRecord -Set 'updates-software' -Artifact $artifact -RecordType 'reboot-indicator' -Fields ([ordered]@{
                    name  = [string]$property.Name
                    value = $property.Value
                })
            }
        }
        'permissions-target-acls' {
            $targetRows = @($data)
            $unreliableSourceKinds = @{}
            foreach ($sourceGroup in @($targetRows | Group-Object -Property sourceKind)) {
                $sourceNames = @(
                    $sourceGroup.Group |
                        ForEach-Object { [string](Get-PropertyValue $_ 'sourceName') } |
                        Sort-Object -Unique
                )
                $maximumNameLength = 0
                if ($sourceNames.Count -gt 0) {
                    $maximumNameLength = [int](($sourceNames | ForEach-Object Length | Measure-Object -Maximum).Maximum)
                }
                if (
                    ($sourceGroup.Count -gt 1 -and $sourceNames.Count -eq 1) -or
                    $maximumNameLength -gt 256
                ) {
                    $unreliableSourceKinds[[string]$sourceGroup.Name] = $true
                }
            }

            foreach ($target in $targetRows) {
                $sourceKind = [string](Get-PropertyValue $target 'sourceKind')
                $sourceName = [string](Get-PropertyValue $target 'sourceName')
                $targetPath = [string](Get-PropertyValue $target 'path')
                $sourceNameReliable = -not $unreliableSourceKinds.ContainsKey($sourceKind)
                $defenderTarget = $targetPath -match '(?i)\b(?:Microsoft|Windows)\s+Defender\b'
                if (-not $defenderTarget -and $sourceNameReliable) {
                    $defenderTarget = $sourceName -match '(?i)\b(?:Microsoft|Windows)\s+Defender\b'
                }
                if ($defenderTarget) { $defenderRowsExcluded++; continue }

                $attributionNote = $null
                if (-not $sourceNameReliable) {
                    $script:unreliableTargetAclAttributionRows++
                    $attributionNote = 'Collector sourceName is aggregate/collapsed under Windows PowerShell 5.1; target path and ACL fields remain row-local evidence.'
                }
                $signature = Get-PropertyValue $target 'signature'
                Add-AclObject -Artifact $artifact -SourceKind $sourceKind -SourceName $sourceName -TargetPath $targetPath -AclScope 'file' -Acl (Get-PropertyValue $target 'fileAcl') -Signature $signature -SourceNameAttributionReliable $sourceNameReliable -AttributionNote $attributionNote
                Add-AclObject -Artifact $artifact -SourceKind $sourceKind -SourceName $sourceName -TargetPath $targetPath -AclScope 'parent' -Acl (Get-PropertyValue $target 'parentAcl') -Signature $signature -SourceNameAttributionReliable $sourceNameReliable -AttributionNote $attributionNote
            }
        }
        default {
            $normalizationNotes[$checkId] = 'No content normalizer is defined; manifest disposition remains in the artifact ledger.'
        }
    }
}

$inventoryDirectory = Join-Path $resolvedRun 'derived\inventory'
if (-not (Test-Path -LiteralPath $inventoryDirectory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $inventoryDirectory -Force
}
$generatorSnapshotPath = Join-Path $inventoryDirectory 'normalizer.ps1'
Copy-Item -LiteralPath $PSCommandPath -Destination $generatorSnapshotPath -Force

$generatedUtc = [datetime]::UtcNow.ToString('o')
$outputDefinitions = [ordered]@{
    'identity.json'            = 'identity'
    'controls.json'            = 'controls'
    'persistence.json'         = 'persistence'
    'network-exposure.json'    = 'network-exposure'
    'sharing-permissions.json' = 'sharing-permissions'
    'updates-software.json'    = 'updates-software'
}
$outputSummaries = @()
foreach ($definition in $outputDefinitions.GetEnumerator()) {
    $records = @($sets[$definition.Value])
    $payload = [ordered]@{
        schemaVersion = '1.0'
        runId         = [string]$manifest.runId
        generatedUtc  = $generatedUtc
        dataset       = [string]$definition.Value
        purpose       = 'Bounded factual posture inventory; records are observations and do not infer vulnerability.'
        records       = $records
    }
    $outputPath = Join-Path $inventoryDirectory ([string]$definition.Key)
    $payload | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $outputPath -Encoding UTF8
    $outputSummaries += [pscustomobject][ordered]@{
        path       = "derived/inventory/$($definition.Key)"
        recordCount = $records.Count
        sizeBytes  = (Get-Item -LiteralPath $outputPath).Length
        sha256     = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$artifactRows = @(
    foreach ($artifact in $artifacts) {
        $checkId = [string]$artifact.id
        [pscustomobject][ordered]@{
            runId               = [string]$manifest.runId
            checkId             = $checkId
            category            = [string]$artifact.category
            status              = [string]$artifact.status
            format              = [string]$artifact.format
            artifactPath        = [string]$artifact.path
            artifactSha256      = [string]$artifact.sha256
            collectedUtc        = [string]$artifact.completedUtc
            sourceRecordCount   = $artifact.recordCount
            sizeBytes           = $artifact.sizeBytes
            integrityVerified   = $verifiedPaths.ContainsKey($checkId)
            normalizedRows      = [int]$emittedByCheck[$checkId]
            rowsOmittedByBound  = [int]$omittedByCheck[$checkId]
            normalizationNote   = if ($normalizationNotes.ContainsKey($checkId)) { $normalizationNotes[$checkId] } else { $null }
            collectionLimitation = [string]$artifact.error
        }
    }
)
$artifactLedgerPath = Join-Path $inventoryDirectory 'artifact-status.csv'
$artifactRows | Export-Csv -LiteralPath $artifactLedgerPath -NoTypeInformation -Encoding UTF8
$outputSummaries += [pscustomobject][ordered]@{
    path        = 'derived/inventory/artifact-status.csv'
    recordCount = $artifactRows.Count
    sizeBytes   = (Get-Item -LiteralPath $artifactLedgerPath).Length
    sha256      = (Get-FileHash -LiteralPath $artifactLedgerPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

$summary = [ordered]@{
    schemaVersion           = '1.0'
    runId                   = [string]$manifest.runId
    assessmentDomain        = 'host-posture'
    generatedUtc            = $generatedUtc
    collectionCompletedUtc  = [string]$manifest.collectionCompletedUtc
    manifestPath            = 'manifest.json'
    manifestSha256          = $manifestHash
    generator               = 'derived/inventory/normalizer.ps1'
    generatorSha256         = (Get-FileHash -LiteralPath $generatorSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
    frozenPointerVerified   = $false
    purpose                 = 'Integrity-verified, bounded factual posture inventory for Phase 9 analysis.'
    interpretation          = 'Inventory records are observations. This export does not identify vulnerabilities, validate findings, or infer malicious activity.'
    maxRowsPerCheck         = $MaxRowsPerCheck
    maxFieldCharacters      = $MaxFieldCharacters
    manifestArtifactCount   = $artifacts.Count
    verifiedFileCount       = $verifiedPaths.Count
    defenderRowsExcluded    = $defenderRowsExcluded
    fieldValuesTruncated    = $fieldValuesTruncated
    unreliableTargetAclAttributionRows = $unreliableTargetAclAttributionRows
    rowsEmitted             = [long](($emittedByCheck.Values | Measure-Object -Sum).Sum)
    rowsOmittedByBound      = [long](($omittedByCheck.Values | Measure-Object -Sum).Sum)
    partialOrLimitedChecks  = @(
        $artifacts |
            Where-Object { [string]$_.status -ne 'collected' } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    checkId = [string]$_.id
                    status  = [string]$_.status
                    note    = [string]$_.error
                }
            }
    )
    normalizationLimitations = @(
        if ($unreliableTargetAclAttributionRows -gt 0) {
            [pscustomobject][ordered]@{
                checkId = 'permissions-target-acls'
                affectedSourceRows = $unreliableTargetAclAttributionRows
                note = 'Collector sourceName attribution is aggregate/collapsed for discovered service, task, startup, or Run-key targets under Windows PowerShell 5.1. Derived ACL rows retain row-local target paths and ACLs, flag sourceNameAttributionReliable=false, and must not use aggregate sourceName as a Defender discriminator.'
            }
        }
    )
    outputs                 = $outputSummaries
}
$summaryPath = Join-Path $inventoryDirectory 'summary.json'
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host "Posture run: $($manifest.runId)"
Write-Host "Verified files: $($verifiedPaths.Count)"
Write-Host "Normalized rows: $($summary.rowsEmitted)"
Write-Host "Rows omitted by bound: $($summary.rowsOmittedByBound)"
Write-Host "Defender rows excluded: $defenderRowsExcluded"
Write-Host "Inventory: $inventoryDirectory"
