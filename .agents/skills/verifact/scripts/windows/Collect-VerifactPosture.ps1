#requires -Version 5.1

<#
.SYNOPSIS
Collects one bounded, read-only current-host security posture snapshot.

.DESCRIPTION
Uses only built-in Windows and PowerShell capabilities. The collector does not
change configuration, query a remote host, connect to a listener, inspect
Microsoft Defender, collect credentials, or recursively crawl the filesystem.
Every configured check receives a manifest disposition and every written
artifact is hashed with SHA-256.
#>

[CmdletBinding()]
param(
    [string]$ScopePath,
    [string]$OutputRoot,
    [string]$RunId,
    [string]$InvokingUser,
    [switch]$CapabilityOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$collectorVersion = '1.0.1'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($ScopePath)) {
    $ScopePath = Join-Path $projectRoot 'config\posture-scope.json'
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path (Get-Location) 'verifact-assessment\evidence\posture\runs'
}
$ScopePath = [System.IO.Path]::GetFullPath($ScopePath)
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
if (-not (Test-Path -LiteralPath $ScopePath -PathType Leaf)) {
    throw "Scope configuration not found: $ScopePath"
}
$volumeRoot = [System.IO.Path]::GetPathRoot($OutputRoot).TrimEnd('\')
if ($OutputRoot -eq $volumeRoot) {
    throw "OutputRoot may not be a filesystem volume root: $OutputRoot"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostIdentity {
    $machineGuid = $null
    $systemUuid = $null
    try { $machineGuid = [string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction Stop) } catch { }
    try { $systemUuid = [string](Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID } catch { }
    $strength = if ($machineGuid -and $systemUuid) { 'strong' } elseif ($machineGuid -or $systemUuid) { 'degraded' } else { 'weak' }
    $material = "$($scope.assessmentId)|$machineGuid|$systemUuid|$env:COMPUTERNAME".ToLowerInvariant()
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($material)
        $digest = $algorithm.ComputeHash($bytes)
        $hash = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
    return [pscustomobject][ordered]@{ sha256 = $hash; strength = $strength }
}

function ConvertTo-RelativePath {
    param([string]$Path)
    return $Path.Replace('\', '/')
}

function Resolve-ContainedArtifactPath {
    param(
        [string]$RunDirectory,
        [string]$RelativePath
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        [System.IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath.StartsWith('\\') -or
        $RelativePath -match '::' -or
        $RelativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "Unsafe posture artifact path: $RelativePath"
    }
    $runFull = [System.IO.Path]::GetFullPath($RunDirectory).TrimEnd('\')
    $candidate = [System.IO.Path]::GetFullPath(
        (Join-Path $runFull ($RelativePath -replace '/', '\'))
    )
    if (-not $candidate.StartsWith($runFull + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Artifact path escapes the posture run: $RelativePath"
    }
    return $candidate
}

function Get-SafePropertyValue {
    param(
        [object]$InputObject,
        [string]$Name
    )
    if ($null -eq $InputObject) {
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-SafeTypeName {
    param([object]$InputObject)
    if ($null -eq $InputObject) {
        return $null
    }
    $cimClass = Get-SafePropertyValue $InputObject 'CimClass'
    $cimClassName = Get-SafePropertyValue $cimClass 'CimClassName'
    if ($cimClassName) {
        return [string]$cimClassName
    }
    return $InputObject.GetType().FullName
}

function Get-SafeCimPath {
    param([object]$InputObject)
    $systemProperties = Get-SafePropertyValue $InputObject 'CimSystemProperties'
    $path = Get-SafePropertyValue $systemProperties 'Path'
    if ($null -eq $path) {
        return $null
    }
    return [string]$path
}

function Get-SafeError {
    param([System.Management.Automation.ErrorRecord]$Record)
    $message = [string]$Record.Exception.Message
    return ($message -replace '[\r\n]+', ' ').Trim()
}

function Read-JsonArrayFile {
    <#
    Windows PowerShell 5.1 emits a top-level JSON array from ConvertFrom-Json
    as one pipeline object. Explicitly enumerate that array so callers receive
    one source object at a time and cannot accidentally use member enumeration
    across the entire artifact.
    #>
    param([string]$Path)

    $parsed = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $parsed) {
        return
    }
    if ($parsed -is [System.Array]) {
        foreach ($element in $parsed) {
            Write-Output $element
        }
        return
    }
    Write-Output $parsed
}

function Get-FailureStatus {
    param([System.Management.Automation.ErrorRecord]$Record)
    $text = "$(Get-SafeError $Record) $($Record.FullyQualifiedErrorId)"
    if ($text -match '(?i)commandnotfound|not recognized|could not find.*cmdlet|feature name .* unknown') {
        return 'unsupported'
    }
    if ($text -match '(?i)access is denied|access denied|unauthorized|0x80041003|permission') {
        return 'inaccessible'
    }
    if ($text -match '(?i)not found|does not exist|cannot find|no matching') {
        return 'unavailable'
    }
    return 'failed'
}

function Test-NativeCapability {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Get-RegistryValueState {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return [pscustomobject][ordered]@{
                path    = $Path
                name    = $Name
                present = $false
                value   = $null
                error   = $null
            }
        }
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        $property = $item.PSObject.Properties[$Name]
        if ($null -eq $property) {
            return [pscustomobject][ordered]@{
                path    = $Path
                name    = $Name
                present = $false
                value   = $null
                error   = $null
            }
        }
        return [pscustomobject][ordered]@{
            path    = $Path
            name    = $Name
            present = $true
            value   = $property.Value
            error   = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            path    = $Path
            name    = $Name
            present = $false
            value   = $null
            error   = Get-SafeError $_
        }
    }
}

function Get-ExactAclState {
    param([string]$Path)
    try {
        if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('\\')) {
            return $null
        }
        $expanded = [Environment]::ExpandEnvironmentVariables($Path)
        if (-not (Test-Path -LiteralPath $expanded)) {
            return [pscustomobject][ordered]@{
                path      = $expanded
                exists    = $false
                owner     = $null
                protected = $null
                access    = @()
                error     = $null
            }
        }
        $acl = Get-Acl -LiteralPath $expanded
        $access = @(
            foreach ($entry in @($acl.Access)) {
                [pscustomobject][ordered]@{
                    identity      = [string]$entry.IdentityReference
                    type          = [string]$entry.AccessControlType
                    rights        = [string]$entry.FileSystemRights
                    inherited     = [bool]$entry.IsInherited
                    inheritance   = [string]$entry.InheritanceFlags
                    propagation   = [string]$entry.PropagationFlags
                }
            }
        )
        return [pscustomobject][ordered]@{
            path      = $expanded
            exists    = $true
            owner     = [string]$acl.Owner
            protected = [bool]$acl.AreAccessRulesProtected
            access    = $access
            error     = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            path      = [Environment]::ExpandEnvironmentVariables($Path)
            exists    = $null
            owner     = $null
            protected = $null
            access    = @()
            error     = Get-SafeError $_
        }
    }
}

function Resolve-LocalCommandPath {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) {
        return $null
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($expanded.StartsWith('\\') -or $expanded.StartsWith('\Device\', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    $candidate = $null
    if ($expanded -match '^\s*"([^"]+)"') {
        $candidate = $matches[1]
    }
    elseif ($expanded -match '(?i)^\s*(.+?\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js|msi))(?=\s|$)') {
        $candidate = $matches[1].Trim('"')
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return $null
    }
    if ($candidate -match '(?i)^\\SystemRoot\\(.+)$') {
        $candidate = Join-Path $env:SystemRoot $matches[1]
    }
    elseif ($candidate -match '^\\\?\?\\([A-Za-z]:\\.+)$') {
        $candidate = $matches[1]
    }
    elseif ($candidate.StartsWith('\')) {
        return $null
    }
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        try {
            $resolvedCommand = Get-Command $candidate -CommandType Application -ErrorAction Stop | Select-Object -First 1
            $candidate = if ($resolvedCommand.Path) { $resolvedCommand.Path } else { $resolvedCommand.Source }
        }
        catch {
            return $null
        }
    }
    if ([string]::IsNullOrWhiteSpace($candidate) -or
        $candidate.StartsWith('\\') -or
        $candidate -match '::') {
        return $null
    }
    try {
        return [System.IO.Path]::GetFullPath($candidate)
    }
    catch {
        return $null
    }
}

function New-CollectorResult {
    param(
        [object]$Data,
        [int]$RecordCount,
        [bool]$DirectFile = $false,
        [string]$Status = $null,
        [string]$Note = $null
    )
    return [pscustomobject][ordered]@{
        data        = $Data
        recordCount = $RecordCount
        directFile  = $DirectFile
        status      = $Status
        note        = $Note
    }
}

function Get-ProcessAttribution {
    param(
        [int]$ProcessId,
        [hashtable]$ServicesByPid
    )
    $processName = $null
    $processPath = $null
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $processName = $process.ProcessName
        try { $processPath = $process.Path } catch { $processPath = $null }
    }
    catch {
        $processName = $null
    }
    $serviceNames = @()
    if ($ServicesByPid.ContainsKey([string]$ProcessId)) {
        $serviceNames = @($ServicesByPid[[string]$ProcessId])
    }
    return [pscustomobject][ordered]@{
        processName = $processName
        processPath = $processPath
        services    = $serviceNames
    }
}

function Invoke-PostureSource {
    param(
        [pscustomobject]$Source,
        [string]$ArtifactPath,
        [string]$RunDirectory
    )

    switch ([string]$Source.collector) {
        'LocalUsers' {
            if (-not (Test-NativeCapability 'Get-LocalUser')) {
                throw 'Get-LocalUser is unavailable on this Windows installation.'
            }
            $rows = @(
                Get-LocalUser | ForEach-Object {
                    [pscustomobject][ordered]@{
                        name                  = $_.Name
                        enabled               = [bool]$_.Enabled
                        description           = $_.Description
                        sid                   = [string]$_.SID
                        principalSource       = [string]$_.PrincipalSource
                        lastLogon             = if ($_.LastLogon) { ([datetime]$_.LastLogon).ToUniversalTime().ToString('o') } else { $null }
                        passwordRequired      = [bool]$_.PasswordRequired
                        passwordExpires       = if ($_.PasswordExpires) { ([datetime]$_.PasswordExpires).ToUniversalTime().ToString('o') } else { $null }
                        passwordLastSet       = if ($_.PasswordLastSet) { ([datetime]$_.PasswordLastSet).ToUniversalTime().ToString('o') } else { $null }
                        userMayChangePassword = [bool]$_.UserMayChangePassword
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'LocalGroups' {
            if (-not (Test-NativeCapability 'Get-LocalGroup')) {
                throw 'LocalAccounts group cmdlets are unavailable.'
            }
            $membershipErrors = New-Object System.Collections.Generic.List[string]
            $rows = @(
                foreach ($group in @(Get-LocalGroup)) {
                    $members = @()
                    $memberError = $null
                    try {
                        $members = @(
                            Get-LocalGroupMember -Group $group.Name -ErrorAction Stop |
                                ForEach-Object {
                                    [pscustomobject][ordered]@{
                                        name            = $_.Name
                                        objectClass     = [string]$_.ObjectClass
                                        principalSource = [string]$_.PrincipalSource
                                        sid             = [string]$_.SID
                                    }
                                }
                        )
                    }
                    catch {
                        $memberError = Get-SafeError $_
                        $membershipErrors.Add("$($group.Name): $memberError")
                    }
                    [pscustomobject][ordered]@{
                        name        = $group.Name
                        description = $group.Description
                        sid         = [string]$group.SID
                        members     = $members
                        memberError = $memberError
                    }
                }
            )
            $status = if ($membershipErrors.Count -gt 0) { 'partial' } else { $null }
            $note = if ($membershipErrors.Count -gt 0) { "$($membershipErrors.Count) local-group membership query or resolution errors." } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'AccountPolicy' {
            if (-not (Test-NativeCapability 'net.exe')) {
                throw 'net.exe is unavailable.'
            }
            $lines = @(& net.exe accounts 2>&1 | ForEach-Object { [string]$_ })
            if ($LASTEXITCODE -ne 0) {
                throw "net accounts failed with exit code $LASTEXITCODE."
            }
            return New-CollectorResult $lines $lines.Count
        }
        'SecurityPolicy' {
            if (-not (Test-NativeCapability 'secedit.exe')) {
                throw 'secedit.exe is unavailable.'
            }
            $parent = Split-Path -Parent $ArtifactPath
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
            $output = @(& secedit.exe /export /cfg $ArtifactPath /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1)
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ArtifactPath)) {
                throw "secedit export failed with exit code $LASTEXITCODE. $($output -join ' ')"
            }
            $lineCount = @(Get-Content -LiteralPath $ArtifactPath -Encoding Unicode).Count
            return New-CollectorResult $null $lineCount $true
        }
        'AuditPolicy' {
            if (-not (Test-NativeCapability 'auditpol.exe')) {
                throw 'auditpol.exe is unavailable.'
            }
            $lines = @(& auditpol.exe /get /category:* /r 2>&1 | ForEach-Object { [string]$_ })
            if ($LASTEXITCODE -ne 0) {
                throw "auditpol failed with exit code $LASTEXITCODE."
            }
            $rows = @(
                foreach ($row in @($lines | ConvertFrom-Csv)) {
                    # auditpol localizes its CSV headers, but the /r column order is stable.
                    $values = @($row.PSObject.Properties | ForEach-Object { $_.Value })
                    if ($values.Count -lt 6) { continue }
                    [pscustomobject][ordered]@{
                        machineName      = $values[0]
                        policyTarget     = $values[1]
                        subcategoryName  = $values[2]
                        subcategoryGuid  = $values[3]
                        inclusionSetting = $values[4]
                        exclusionSetting = $values[5]
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'EventLogConfiguration' {
            $rows = @(
                foreach ($channel in @($Source.options.channels)) {
                    try {
                        $log = Get-WinEvent -ListLog ([string]$channel) -ErrorAction Stop
                        [pscustomobject][ordered]@{
                            name               = [string]$channel
                            status             = 'available'
                            isEnabled          = [bool]$log.IsEnabled
                            logMode            = [string]$log.LogMode
                            maximumSizeInBytes = [long]$log.MaximumSizeInBytes
                            recordCount        = if ($null -ne $log.RecordCount) { [long]$log.RecordCount } else { $null }
                            fileSize           = if ($null -ne $log.FileSize) { [long]$log.FileSize } else { $null }
                            oldestRecordNumber = if ($null -ne $log.OldestRecordNumber) { [long]$log.OldestRecordNumber } else { $null }
                            logFilePath        = [string]$log.LogFilePath
                            error              = $null
                        }
                    }
                    catch {
                        [pscustomobject][ordered]@{
                            name               = [string]$channel
                            status             = Get-FailureStatus $_
                            isEnabled          = $null
                            logMode            = $null
                            maximumSizeInBytes = $null
                            recordCount        = $null
                            fileSize           = $null
                            oldestRecordNumber = $null
                            logFilePath        = $null
                            error              = Get-SafeError $_
                        }
                    }
                }
            )
            $limited = @($rows | Where-Object status -ne 'available')
            $status = if ($limited.Count -gt 0) { 'partial' } else { $null }
            $note = if ($limited.Count -gt 0) { "$($limited.Count) configured channels were unavailable or inaccessible." } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'Services' {
            $rows = @(
                Get-CimInstance -ClassName Win32_Service | ForEach-Object {
                    [pscustomobject][ordered]@{
                        name        = $_.Name
                        displayName = $_.DisplayName
                        state       = $_.State
                        startMode   = $_.StartMode
                        startName   = $_.StartName
                        pathName    = $_.PathName
                        processId   = [int]$_.ProcessId
                        serviceType = $_.ServiceType
                        desktopInteract = [bool]$_.DesktopInteract
                        description = $_.Description
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'ScheduledTasks' {
            if (-not (Test-NativeCapability 'Get-ScheduledTask')) {
                throw 'Get-ScheduledTask is unavailable.'
            }
            $rows = @(
                Get-ScheduledTask | ForEach-Object {
                    $task = $_
                    [pscustomobject][ordered]@{
                        taskPath  = $task.TaskPath
                        taskName  = $task.TaskName
                        state     = [string]$task.State
                        author    = $task.Author
                        principal = [pscustomobject][ordered]@{
                            userId    = Get-SafePropertyValue $task.Principal 'UserId'
                            groupId   = Get-SafePropertyValue $task.Principal 'GroupId'
                            logonType = [string](Get-SafePropertyValue $task.Principal 'LogonType')
                            runLevel  = [string](Get-SafePropertyValue $task.Principal 'RunLevel')
                        }
                        actions   = @(
                            foreach ($action in @($task.Actions)) {
                                [pscustomobject][ordered]@{
                                    type             = Get-SafeTypeName $action
                                    execute          = Get-SafePropertyValue $action 'Execute'
                                    arguments        = Get-SafePropertyValue $action 'Arguments'
                                    workingDirectory = Get-SafePropertyValue $action 'WorkingDirectory'
                                }
                            }
                        )
                        triggers  = @(
                            foreach ($trigger in @($task.Triggers)) {
                                [pscustomobject][ordered]@{
                                    type      = Get-SafeTypeName $trigger
                                    enabled   = Get-SafePropertyValue $trigger 'Enabled'
                                    start     = Get-SafePropertyValue $trigger 'StartBoundary'
                                    end       = Get-SafePropertyValue $trigger 'EndBoundary'
                                    delay     = Get-SafePropertyValue $trigger 'Delay'
                                    interval  = Get-SafePropertyValue (Get-SafePropertyValue $trigger 'Repetition') 'Interval'
                                }
                            }
                        )
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'StartupCommands' {
            $rows = @(
                Get-CimInstance -ClassName Win32_StartupCommand | ForEach-Object {
                    [pscustomobject][ordered]@{
                        name       = $_.Name
                        command    = $_.Command
                        location   = $_.Location
                        user       = $_.User
                        userSid    = $_.UserSID
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'StartupFolders' {
            $startupFolders = @(
                [pscustomobject]@{
                    scope = 'machine'
                    path  = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
                },
                [pscustomobject]@{
                    scope = 'current-user'
                    path  = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
                }
            )
            $folderLimitations = New-Object System.Collections.Generic.List[string]
            $rows = @(
                foreach ($folder in $startupFolders) {
                    try {
                        if (-not (Test-Path -LiteralPath $folder.path -PathType Container -ErrorAction Stop)) {
                            $folderLimitations.Add("$($folder.scope): startup folder is unavailable.")
                            continue
                        }
                        $folderItems = @(Get-ChildItem -LiteralPath $folder.path -Force -File -ErrorAction Stop)
                    }
                    catch {
                        $folderLimitations.Add("$($folder.scope): $(Get-SafeError $_)")
                        continue
                    }
                    foreach ($item in $folderItems) {
                        [pscustomobject][ordered]@{
                            scope        = $folder.scope
                            folder       = $folder.path
                            name         = $item.Name
                            fullName     = $item.FullName
                            extension    = $item.Extension
                            length       = [long]$item.Length
                            lastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
                            attributes   = [string]$item.Attributes
                        }
                    }
                }
            )
            $status = if ($folderLimitations.Count -gt 0) { 'partial' } else { $null }
            $note = if ($folderLimitations.Count -gt 0) {
                "$($folderLimitations.Count) configured startup folders were unavailable or inaccessible."
            } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'RunKeys' {
            $registryPaths = @(
                'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
            )
            $loadedUserError = $null
            try {
                $loadedSids = @(
                    Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
                        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
                        ForEach-Object { $_.PSChildName }
                )
                foreach ($sid in $loadedSids) {
                    $registryPaths += "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                    $registryPaths += "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                }
            }
            catch {
                $loadedUserError = Get-SafeError $_
            }
            $rows = @(
                foreach ($path in $registryPaths | Select-Object -Unique) {
                    if (-not (Test-Path -LiteralPath $path)) {
                        continue
                    }
                    $item = Get-ItemProperty -LiteralPath $path
                    foreach ($property in @($item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        [pscustomobject][ordered]@{
                            key   = $path
                            name  = $property.Name
                            value = [string]$property.Value
                        }
                    }
                }
            )
            $status = if ($loadedUserError) { 'partial' } else { $null }
            $note = if ($loadedUserError) { "Loaded-user Run-key enumeration was incomplete: $loadedUserError" } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'WmiSubscriptions' {
            $filters = @(
                Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' |
                    ForEach-Object {
                        [pscustomobject][ordered]@{
                            name            = $_.Name
                            queryLanguage   = $_.QueryLanguage
                            eventNamespace  = $_.EventNamespace
                            query           = $_.Query
                            relativePath    = Get-SafeCimPath $_
                        }
                    }
            )
            $consumerErrors = New-Object System.Collections.Generic.List[string]
            $consumerClasses = @(
                'CommandLineEventConsumer',
                'ActiveScriptEventConsumer',
                'LogFileEventConsumer',
                'NTEventLogEventConsumer',
                'SMTPEventConsumer'
            )
            $consumers = @()
            foreach ($className in $consumerClasses) {
                try {
                    $consumers += @(
                        Get-CimInstance -Namespace 'root\subscription' -ClassName $className -ErrorAction Stop |
                            ForEach-Object {
                                [pscustomobject][ordered]@{
                                    name                = $_.Name
                                    class               = Get-SafeTypeName $_
                                    executablePath      = Get-SafePropertyValue $_ 'ExecutablePath'
                                    commandLineTemplate = Get-SafePropertyValue $_ 'CommandLineTemplate'
                                    scriptingEngine     = Get-SafePropertyValue $_ 'ScriptingEngine'
                                    relativePath        = Get-SafeCimPath $_
                                }
                            }
                    )
                }
                catch {
                    $message = Get-SafeError $_
                    if ("$message $($_.FullyQualifiedErrorId)" -notmatch '(?i)invalid class|0x80041010') {
                        $consumerErrors.Add("${className}: $message")
                    }
                }
            }
            $bindings = @(
                Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' |
                    ForEach-Object {
                        [pscustomobject][ordered]@{
                            filter       = [string]$_.Filter
                            consumer     = [string]$_.Consumer
                            relativePath = Get-SafeCimPath $_
                        }
                    }
            )
            $data = [pscustomobject][ordered]@{
                filters   = $filters
                consumers = $consumers
                bindings  = $bindings
            }
            $status = if ($consumerErrors.Count -gt 0) { 'partial' } else { $null }
            $note = if ($consumerErrors.Count -gt 0) { "$($consumerErrors.Count) WMI consumer subclass queries failed." } else { $null }
            return New-CollectorResult $data ($filters.Count + $consumers.Count + $bindings.Count) $false $status $note
        }
        'FirewallProfiles' {
            $rows = @(
                Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
                    [pscustomobject][ordered]@{
                        name                  = $_.Name
                        enabled               = [bool]$_.Enabled
                        defaultInboundAction  = [string]$_.DefaultInboundAction
                        defaultOutboundAction = [string]$_.DefaultOutboundAction
                        allowInboundRules     = [string]$_.AllowInboundRules
                        allowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
                        notifyOnListen        = [bool]$_.NotifyOnListen
                        logAllowed            = [bool]$_.LogAllowed
                        logBlocked            = [bool]$_.LogBlocked
                        logFileName           = $_.LogFileName
                        logMaxSizeKilobytes   = $_.LogMaxSizeKilobytes
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'FirewallInboundAllowRules' {
            $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow)
            $filterErrors = 0
            $rows = @(
                foreach ($rule in $rules) {
                    $ports = @()
                    $addresses = @()
                    $applications = @()
                    $services = @()
                    try { $ports = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop) } catch { $filterErrors++ }
                    try { $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop) } catch { $filterErrors++ }
                    try { $applications = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop) } catch { $filterErrors++ }
                    try { $services = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop) } catch { $filterErrors++ }
                    [pscustomobject][ordered]@{
                        name        = $rule.Name
                        displayName = $rule.DisplayName
                        displayGroup = $rule.DisplayGroup
                        profile     = [string]$rule.Profile
                        policyStoreSourceType = [string]$rule.PolicyStoreSourceType
                        edgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy
                        protocol    = @($ports | ForEach-Object { [string]$_.Protocol } | Select-Object -Unique)
                        localPort   = @($ports | ForEach-Object { [string]$_.LocalPort } | Select-Object -Unique)
                        remotePort  = @($ports | ForEach-Object { [string]$_.RemotePort } | Select-Object -Unique)
                        localAddress = @($addresses | ForEach-Object { [string]$_.LocalAddress } | Select-Object -Unique)
                        remoteAddress = @($addresses | ForEach-Object { [string]$_.RemoteAddress } | Select-Object -Unique)
                        program     = @($applications | ForEach-Object { [string]$_.Program } | Select-Object -Unique)
                        service     = @($services | ForEach-Object { [string]$_.Service } | Select-Object -Unique)
                    }
                }
            )
            $status = if ($filterErrors -gt 0) { 'partial' } else { $null }
            $note = if ($filterErrors -gt 0) { "$filterErrors associated firewall-filter lookups failed." } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'TcpListeners' {
            $servicesByPid = @{}
            foreach ($service in @(Get-CimInstance -ClassName Win32_Service | Where-Object ProcessId -gt 0)) {
                $key = [string][int]$service.ProcessId
                if (-not $servicesByPid.ContainsKey($key)) { $servicesByPid[$key] = @() }
                $servicesByPid[$key] += $service.Name
            }
            $rows = @(
                Get-NetTCPConnection -State Listen | ForEach-Object {
                    $owner = Get-ProcessAttribution -ProcessId ([int]$_.OwningProcess) -ServicesByPid $servicesByPid
                    [pscustomobject][ordered]@{
                        localAddress  = $_.LocalAddress
                        localPort     = [int]$_.LocalPort
                        state         = [string]$_.State
                        owningProcess = [int]$_.OwningProcess
                        processName   = $owner.processName
                        processPath   = $owner.processPath
                        services      = $owner.services
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'UdpListeners' {
            $servicesByPid = @{}
            foreach ($service in @(Get-CimInstance -ClassName Win32_Service | Where-Object ProcessId -gt 0)) {
                $key = [string][int]$service.ProcessId
                if (-not $servicesByPid.ContainsKey($key)) { $servicesByPid[$key] = @() }
                $servicesByPid[$key] += $service.Name
            }
            $rows = @(
                Get-NetUDPEndpoint | ForEach-Object {
                    $owner = Get-ProcessAttribution -ProcessId ([int]$_.OwningProcess) -ServicesByPid $servicesByPid
                    [pscustomobject][ordered]@{
                        localAddress  = $_.LocalAddress
                        localPort     = [int]$_.LocalPort
                        owningProcess = [int]$_.OwningProcess
                        processName   = $owner.processName
                        processPath   = $owner.processPath
                        services      = $owner.services
                    }
                }
            )
            return New-CollectorResult $rows $rows.Count
        }
        'RdpConfiguration' {
            $terminalPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            $service = Get-Service -Name TermService -ErrorAction SilentlyContinue
            $listener = @()
            $listenerError = $null
            try {
                $listener = @(
                    Get-NetTCPConnection -State Listen -ErrorAction Stop |
                        Where-Object LocalPort -eq 3389 |
                        Select-Object LocalAddress,LocalPort,OwningProcess
                )
            }
            catch {
                $listener = @()
                $listenerError = Get-SafeError $_
            }
            $data = [pscustomobject][ordered]@{
                denyConnections   = Get-RegistryValueState $terminalPath 'fDenyTSConnections'
                userAuthentication = Get-RegistryValueState $rdpTcpPath 'UserAuthentication'
                securityLayer     = Get-RegistryValueState $rdpTcpPath 'SecurityLayer'
                minEncryptionLevel = Get-RegistryValueState $rdpTcpPath 'MinEncryptionLevel'
                service           = if ($service) {
                    [pscustomobject][ordered]@{
                        name      = $service.Name
                        status    = [string]$service.Status
                        startType = [string]$service.StartType
                    }
                } else { $null }
                listeners         = $listener
                listenerError     = $listenerError
            }
            $status = if ($listenerError) { 'partial' } else { $null }
            $note = if ($listenerError) { "RDP listener query was incomplete: $listenerError" } else { $null }
            return New-CollectorResult $data 1 $false $status $note
        }
        'WinRmConfiguration' {
            if (-not (Test-NativeCapability 'winrm.cmd')) {
                throw 'winrm.cmd is unavailable.'
            }
            $lines = @()
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $lines += '### winrm get winrm/config'
                $lines += @(& winrm.cmd get winrm/config 2>&1 | ForEach-Object { [string]$_ })
                $configExit = $LASTEXITCODE
                $lines += '### winrm enumerate winrm/config/listener'
                $lines += @(& winrm.cmd enumerate winrm/config/listener 2>&1 | ForEach-Object { [string]$_ })
                $listenerExit = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            $status = if ($configExit -ne 0 -or $listenerExit -ne 0) { 'partial' } else { $null }
            $note = if ($status) { "WinRM configuration queries returned exit codes $configExit and $listenerExit." } else { $null }
            return New-CollectorResult $lines $lines.Count $false $status $note
        }
        'SmbShares' {
            $shareErrors = 0
            $rows = @(
                foreach ($share in @(Get-SmbShare)) {
                    $access = @()
                    $accessError = $null
                    try {
                        $access = @(
                            Get-SmbShareAccess -Name $share.Name -ErrorAction Stop |
                                ForEach-Object {
                                    [pscustomobject][ordered]@{
                                        accountName       = $_.AccountName
                                        accessControlType = [string]$_.AccessControlType
                                        accessRight       = [string]$_.AccessRight
                                    }
                                }
                        )
                    }
                    catch {
                        $accessError = Get-SafeError $_
                        $shareErrors++
                    }
                    $rootAcl = $null
                    if (-not [string]::IsNullOrWhiteSpace([string]$share.Path)) {
                        $rootAcl = Get-ExactAclState -Path ([string]$share.Path)
                        if ($rootAcl -and $rootAcl.error) { $shareErrors++ }
                    }
                    [pscustomobject][ordered]@{
                        name        = $share.Name
                        path        = $share.Path
                        description = $share.Description
                        special     = [bool]$share.Special
                        temporary   = [bool]$share.Temporary
                        encryptData = [bool]$share.EncryptData
                        folderEnumerationMode = [string]$share.FolderEnumerationMode
                        access      = $access
                        accessError = $accessError
                        rootAcl     = $rootAcl
                    }
                }
            )
            $status = if ($shareErrors -gt 0) { 'partial' } else { $null }
            $note = if ($shareErrors -gt 0) { "$shareErrors SMB access or exact-root ACL queries failed." } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'SecurityControls' {
            $registry = @(
                Get-RegistryValueState 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
                Get-RegistryValueState 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
                Get-RegistryValueState 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'EnableSecuritySignature'
                Get-RegistryValueState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
            )
            $server = $null
            $client = $null
            try {
                $serverConfig = Get-SmbServerConfiguration
                $server = [pscustomobject][ordered]@{
                    enableSMB1Protocol       = [bool]$serverConfig.EnableSMB1Protocol
                    enableSMB2Protocol       = [bool]$serverConfig.EnableSMB2Protocol
                    enableSecuritySignature  = [bool]$serverConfig.EnableSecuritySignature
                    requireSecuritySignature = [bool]$serverConfig.RequireSecuritySignature
                    rejectUnencryptedAccess  = [bool]$serverConfig.RejectUnencryptedAccess
                    encryptData              = [bool]$serverConfig.EncryptData
                }
            }
            catch {
                $server = [pscustomobject][ordered]@{ error = Get-SafeError $_ }
            }
            try {
                $clientConfig = Get-SmbClientConfiguration
                $client = [pscustomobject][ordered]@{
                    enableSecuritySignature  = [bool]$clientConfig.EnableSecuritySignature
                    requireSecuritySignature = [bool]$clientConfig.RequireSecuritySignature
                    enableInsecureGuestLogons = [bool]$clientConfig.EnableInsecureGuestLogons
                }
            }
            catch {
                $client = [pscustomobject][ordered]@{ error = Get-SafeError $_ }
            }
            $controlErrors = @($registry | Where-Object error).Count
            if ($server.PSObject.Properties['error'] -and $server.error) { $controlErrors++ }
            if ($client.PSObject.Properties['error'] -and $client.error) { $controlErrors++ }
            $data = [pscustomobject][ordered]@{
                registry  = $registry
                smbServer = $server
                smbClient = $client
            }
            $status = if ($controlErrors -gt 0) { 'partial' } else { $null }
            $note = if ($controlErrors -gt 0) { "$controlErrors hardening-control queries failed." } else { $null }
            return New-CollectorResult $data ($registry.Count + 2) $false $status $note
        }
        'OptionalFeatures' {
            if (-not (Test-NativeCapability 'Get-WindowsOptionalFeature')) {
                throw 'Get-WindowsOptionalFeature is unavailable.'
            }
            $rows = @(
                foreach ($featureName in @($Source.options.featureNames)) {
                    try {
                        $feature = Get-WindowsOptionalFeature -Online -FeatureName ([string]$featureName) -ErrorAction Stop
                        [pscustomobject][ordered]@{
                            featureName = [string]$featureName
                            state       = [string]$feature.State
                            restartRequired = [string]$feature.RestartRequired
                            error       = $null
                        }
                    }
                    catch {
                        [pscustomobject][ordered]@{
                            featureName = [string]$featureName
                            state       = 'Unavailable'
                            restartRequired = $null
                            error       = Get-SafeError $_
                        }
                    }
                }
            )
            $featureErrors = @($rows | Where-Object error).Count
            $status = if ($featureErrors -gt 0) { 'partial' } else { $null }
            $note = if ($featureErrors -gt 0) { "$featureErrors optional-feature queries failed." } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'OsAndUpdates' {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $updates = @(
                Get-HotFix | Sort-Object InstalledOn -Descending | ForEach-Object {
                    [pscustomobject][ordered]@{
                        hotFixId    = $_.HotFixID
                        description = $_.Description
                        installedBy = $_.InstalledBy
                        installedOn = if ($_.InstalledOn) { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } else { $null }
                    }
                }
            )
            $data = [pscustomobject][ordered]@{
                operatingSystem = [pscustomobject][ordered]@{
                    caption       = $os.Caption
                    version       = $os.Version
                    buildNumber   = $os.BuildNumber
                    architecture  = $os.OSArchitecture
                    installUtc    = if ($os.InstallDate) { ([datetime]$os.InstallDate).ToUniversalTime().ToString('o') } else { $null }
                    lastBootUtc   = if ($os.LastBootUpTime) { ([datetime]$os.LastBootUpTime).ToUniversalTime().ToString('o') } else { $null }
                    displayVersion = Get-SafePropertyValue $currentVersion 'DisplayVersion'
                    releaseId     = Get-SafePropertyValue $currentVersion 'ReleaseId'
                    ubr           = Get-SafePropertyValue $currentVersion 'UBR'
                    editionId     = Get-SafePropertyValue $currentVersion 'EditionID'
                    productName   = Get-SafePropertyValue $currentVersion 'ProductName'
                }
                updates = $updates
            }
            return New-CollectorResult $data (1 + $updates.Count)
        }
        'InstalledSoftware' {
            $patterns = @($Source.options.namePatterns)
            $uninstallRoots = @(
                'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            )
            $softwareErrors = 0
            $rows = @(
                foreach ($root in $uninstallRoots) {
                    try {
                        if (-not (Test-Path -LiteralPath $root -ErrorAction Stop)) { continue }
                        $uninstallKeys = @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)
                    }
                    catch {
                        $softwareErrors++
                        continue
                    }
                    foreach ($key in $uninstallKeys) {
                        try {
                            $item = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                            $displayName = [string](Get-SafePropertyValue $item 'DisplayName')
                            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
                            if ($displayName -match '(?i)Microsoft Defender') { continue }
                            $matched = $false
                            foreach ($pattern in $patterns) {
                                if ($displayName -like "*$pattern*") { $matched = $true; break }
                            }
                            if (-not $matched) { continue }
                            [pscustomobject][ordered]@{
                                displayName     = $displayName
                                displayVersion  = [string](Get-SafePropertyValue $item 'DisplayVersion')
                                publisher       = [string](Get-SafePropertyValue $item 'Publisher')
                                installDate     = [string](Get-SafePropertyValue $item 'InstallDate')
                                installLocation = [string](Get-SafePropertyValue $item 'InstallLocation')
                                scope            = if ($root -match 'HKEY_CURRENT_USER') { 'current-user' } else { 'machine' }
                            }
                        }
                        catch {
                            $softwareErrors++
                            continue
                        }
                    }
                }
            ) | Sort-Object displayName,displayVersion -Unique
            $status = if ($softwareErrors -gt 0) { 'partial' } else { $null }
            $note = if ($softwareErrors -gt 0) { "$softwareErrors uninstall-registry subkeys could not be read." } else { $null }
            return New-CollectorResult $rows $rows.Count $false $status $note
        }
        'RebootStatus' {
            $rebootErrors = New-Object System.Collections.Generic.List[string]
            $data = [pscustomobject][ordered]@{
                componentBasedServicing = $null
                windowsUpdate           = $null
                pendingFileRename       = $null
                pendingComputerRename   = $null
            }
            try { $data.componentBasedServicing = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop }
            catch { $rebootErrors.Add("CBS reboot state: $(Get-SafeError $_)") }
            try { $data.windowsUpdate = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop }
            catch { $rebootErrors.Add("Windows Update reboot state: $(Get-SafeError $_)") }
            try {
                $pending = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop
                $data.pendingFileRename = $null -ne $pending
            }
            catch {
                if ($_.FullyQualifiedErrorId -match 'PropertyNotFound|ItemNotFound') { $data.pendingFileRename = $false }
                else { $rebootErrors.Add("Pending file rename state: $(Get-SafeError $_)") }
            }
            try {
                $activeName = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name ComputerName -ErrorAction Stop
                $configuredName = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name ComputerName -ErrorAction Stop
                $data.pendingComputerRename = $activeName -ne $configuredName
            }
            catch { $rebootErrors.Add("Computer rename state: $(Get-SafeError $_)") }
            $status = if ($rebootErrors.Count -gt 0) { 'partial' } else { $null }
            $note = if ($rebootErrors.Count -gt 0) { $rebootErrors -join ' | ' } else { $null }
            return New-CollectorResult $data 1 $false $status $note
        }
        'TargetAcls' {
            $targetRows = @()
            $candidateTargets = @()
            $targetLimitations = New-Object System.Collections.Generic.List[string]
            foreach ($staticPath in @($Source.options.staticPaths)) {
                try {
                    $expandedStaticPath = [Environment]::ExpandEnvironmentVariables([string]$staticPath)
                    if ([System.IO.Path]::IsPathRooted($expandedStaticPath) -and
                        -not $expandedStaticPath.StartsWith('\\')) {
                        $candidateTargets += [pscustomobject]@{
                            sourceKind = 'static-approved-path'
                            sourceName = [string]$staticPath
                            path       = [System.IO.Path]::GetFullPath($expandedStaticPath)
                        }
                    }
                }
                catch {
                    $targetLimitations.Add("Static target '$staticPath': $(Get-SafeError $_)")
                }
            }
            $sourceFiles = @(
                @{ Path = 'raw/persistence/services.json'; Kind = 'service'; Property = 'pathName' },
                @{ Path = 'raw/persistence/startup-commands.json'; Kind = 'startup'; Property = 'command' }
            )
            foreach ($definition in $sourceFiles) {
                $path = Join-Path $RunDirectory ($definition.Path -replace '/', '\')
                if (-not (Test-Path -LiteralPath $path)) { continue }
                $items = @(Read-JsonArrayFile -Path $path)
                foreach ($item in $items) {
                    $command = [string]$item.($definition.Property)
                    $resolved = Resolve-LocalCommandPath $command
                    if ($resolved) {
                        $candidateTargets += [pscustomobject]@{
                            sourceKind = $definition.Kind
                            sourceName = if ($definition.Kind -eq 'service') { $item.name } else { $item.name }
                            path       = $resolved
                        }
                    }
                }
            }
            $taskPath = Join-Path $RunDirectory 'raw\persistence\scheduled-tasks.json'
            if (Test-Path -LiteralPath $taskPath) {
                foreach ($task in @(Read-JsonArrayFile -Path $taskPath)) {
                    foreach ($action in @($task.actions)) {
                        $resolved = Resolve-LocalCommandPath ([string]$action.execute)
                        if ($resolved) {
                            $candidateTargets += [pscustomobject]@{
                                sourceKind = 'scheduled-task'
                                sourceName = "$($task.taskPath)$($task.taskName)"
                                path       = $resolved
                            }
                        }
                    }
                }
            }
            $runKeyPath = Join-Path $RunDirectory 'raw\persistence\run-keys.json'
            if (Test-Path -LiteralPath $runKeyPath) {
                foreach ($entry in @(Read-JsonArrayFile -Path $runKeyPath)) {
                    $resolved = Resolve-LocalCommandPath ([string]$entry.value)
                    if ($resolved) {
                        $candidateTargets += [pscustomobject]@{
                            sourceKind = 'run-key'
                            sourceName = "$($entry.key)::$($entry.name)"
                            path       = $resolved
                        }
                    }
                }
            }
            $startupFolderPath = Join-Path $RunDirectory 'raw\persistence\startup-folders.json'
            if (Test-Path -LiteralPath $startupFolderPath) {
                foreach ($entry in @(Read-JsonArrayFile -Path $startupFolderPath)) {
                    try {
                        if ([System.IO.Path]::IsPathRooted([string]$entry.fullName)) {
                            $candidateTargets += [pscustomobject]@{
                                sourceKind = 'startup-folder-entry'
                                sourceName = "$($entry.scope):$($entry.name)"
                                path       = [System.IO.Path]::GetFullPath([string]$entry.fullName)
                            }
                        }
                    }
                    catch {
                        $targetLimitations.Add("Startup entry '$($entry.name)': $(Get-SafeError $_)")
                    }
                }
            }
            $wmiPath = Join-Path $RunDirectory 'raw\persistence\wmi-subscriptions.json'
            if (Test-Path -LiteralPath $wmiPath) {
                $wmiData = Get-Content -LiteralPath $wmiPath -Raw -Encoding UTF8 | ConvertFrom-Json
                foreach ($consumer in @($wmiData.consumers)) {
                    $resolved = Resolve-LocalCommandPath ([string]$consumer.executablePath)
                    if (-not $resolved) {
                        $resolved = Resolve-LocalCommandPath ([string]$consumer.commandLineTemplate)
                    }
                    if ($resolved) {
                        $candidateTargets += [pscustomobject]@{
                            sourceKind = 'wmi-consumer'
                            sourceName = "$($consumer.class):$($consumer.name)"
                            path       = $resolved
                        }
                    }
                }
            }
            foreach ($target in @($candidateTargets | Sort-Object path,sourceKind,sourceName -Unique)) {
                try {
                    if ($target.path -match '(?i)Microsoft Defender') { continue }
                    $expandedPath = [Environment]::ExpandEnvironmentVariables([string]$target.path)
                    $signature = $null
                    if (Test-Path -LiteralPath $expandedPath -PathType Leaf) {
                        $auth = Get-AuthenticodeSignature -LiteralPath $expandedPath
                        $signature = [pscustomobject][ordered]@{
                            status      = [string]$auth.Status
                            statusMessage = $auth.StatusMessage
                            signerSubject = if ($auth.SignerCertificate) { $auth.SignerCertificate.Subject } else { $null }
                            signerIssuer  = if ($auth.SignerCertificate) { $auth.SignerCertificate.Issuer } else { $null }
                            thumbprint    = if ($auth.SignerCertificate) { $auth.SignerCertificate.Thumbprint } else { $null }
                        }
                    }
                    $parentPath = Split-Path -Parent $expandedPath
                    $targetRows += [pscustomobject][ordered]@{
                        sourceKind = $target.sourceKind
                        sourceName = $target.sourceName
                        path       = $expandedPath
                        fileAcl    = Get-ExactAclState $expandedPath
                        parentAcl  = if ($parentPath) { Get-ExactAclState $parentPath } else { $null }
                        signature  = $signature
                    }
                }
                catch {
                    $targetLimitations.Add("$($target.sourceKind) '$($target.sourceName)': $(Get-SafeError $_)")
                }
            }
            $status = if ($targetLimitations.Count -gt 0) { 'partial' } else { $null }
            $note = if ($targetLimitations.Count -gt 0) { "$($targetLimitations.Count) targeted ACL/signature paths could not be normalized or inspected." } else { $null }
            return New-CollectorResult $targetRows $targetRows.Count $false $status $note
        }
        default {
            throw "Unsupported collector '$($Source.collector)'."
        }
    }
}

$scope = Get-Content -LiteralPath $ScopePath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not [bool]$scope.currentHostOnly -or -not [bool]$scope.readOnlyCollection -or -not [bool]$scope.defenderSpecificCollectionExcluded) {
    throw 'Posture scope must require current-host-only, read-only, Defender-specific-collection-excluded collection.'
}

if ($CapabilityOnly) {
    $capabilities = @(
        foreach ($source in @($scope.sources)) {
            $required = switch ([string]$source.collector) {
                'LocalUsers' { 'Get-LocalUser' }
                'LocalGroups' { 'Get-LocalGroup' }
                'AccountPolicy' { 'net.exe' }
                'SecurityPolicy' { 'secedit.exe' }
                'AuditPolicy' { 'auditpol.exe' }
                'ScheduledTasks' { 'Get-ScheduledTask' }
                'FirewallProfiles' { 'Get-NetFirewallProfile' }
                'FirewallInboundAllowRules' { 'Get-NetFirewallRule' }
                'TcpListeners' { 'Get-NetTCPConnection' }
                'UdpListeners' { 'Get-NetUDPEndpoint' }
                'WinRmConfiguration' { 'winrm.cmd' }
                'SmbShares' { 'Get-SmbShare' }
                'OptionalFeatures' { 'Get-WindowsOptionalFeature' }
                default { 'built-in PowerShell/.NET/CIM' }
            }
            [pscustomobject][ordered]@{
                id        = $source.id
                collector = $source.collector
                required  = $required
                available = if ($required -eq 'built-in PowerShell/.NET/CIM') { $true } else { Test-NativeCapability $required }
            }
        }
    )
    [pscustomobject][ordered]@{
        schemaVersion   = '1.0'
        computerName    = $env:COMPUTERNAME
        currentHostOnly = $true
        isAdministrator = Test-IsAdministrator
        sourceCount     = $capabilities.Count
        capabilities    = $capabilities
    } | ConvertTo-Json -Depth 5
    return
}

if (-not (Test-IsAdministrator)) {
    throw 'A full posture snapshot requires an approved administrator PowerShell context.'
}

$collectionStarted = [datetime]::UtcNow
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $hostToken = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]', '_')
    $RunId = "POSTURE_$($collectionStarted.ToString('yyyyMMddTHHmmssZ'))_$hostToken"
}
if ($RunId -notmatch '^POSTURE_[A-Za-z0-9._-]+$') {
    throw "Invalid posture run ID '$RunId'."
}

$runDirectory = Join-Path $OutputRoot $RunId
$runDirectory = [System.IO.Path]::GetFullPath($runDirectory).TrimEnd('\')
if (-not $runDirectory.StartsWith($OutputRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Resolved posture run escapes the approved output root: $runDirectory"
}
if (Test-Path -LiteralPath $runDirectory) {
    throw "Posture run directory already exists: $runDirectory"
}
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
foreach ($relativeDirectory in @('raw','metadata','logs')) {
    New-Item -ItemType Directory -Path (Join-Path $runDirectory $relativeDirectory) -Force | Out-Null
}

$transcriptPath = Resolve-ContainedArtifactPath $runDirectory 'logs/collection-transcript.txt'
$transcriptStarted = $false
try {
    Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null
    $transcriptStarted = $true
}
catch {
    Write-Warning "Transcript could not start: $(Get-SafeError $_)"
}

Write-Host "Verifact posture run: $RunId"
Write-Host 'Mode: local-only, read-only, native Windows, Defender excluded'

$artifacts = New-Object System.Collections.Generic.List[object]
$collectionErrors = New-Object System.Collections.Generic.List[string]
$collectionIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$alternateElevationIdentity = -not [string]::IsNullOrWhiteSpace($InvokingUser) -and $InvokingUser -ne $collectionIdentity
if ($alternateElevationIdentity) {
    $collectionErrors.Add("Current-user profile coverage is degraded because collection ran as '$collectionIdentity' after invocation by '$InvokingUser'. HKCU and APPDATA observations describe the elevated identity, not necessarily the invoking user.")
}

$hostContextPath = Resolve-ContainedArtifactPath $runDirectory 'metadata/host-context.json'
$scopeSnapshotPath = Resolve-ContainedArtifactPath $runDirectory 'metadata/posture-scope.json'
$collectorSnapshotPath = Resolve-ContainedArtifactPath $runDirectory 'metadata/collector.ps1'
$osContext = $null
try {
    $osContext = Get-CimInstance -ClassName Win32_OperatingSystem
}
catch {
    $collectionErrors.Add("Host operating-system context: $(Get-SafeError $_)")
}
$timeZone = [TimeZoneInfo]::Local
$hostIdentity = Get-HostIdentity
$hostContext = [pscustomobject][ordered]@{
    schemaVersion       = '1.0'
    runId               = $RunId
    computerName        = $env:COMPUTERNAME
    hostIdentitySha256  = $hostIdentity.sha256
    hostIdentityStrength = $hostIdentity.strength
    collectionIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    isAdministrator     = Test-IsAdministrator
    collectionStartedUtc = $collectionStarted.ToString('o')
    collectionStartedLocal = $collectionStarted.ToLocalTime().ToString('o')
    timeZone            = [pscustomobject][ordered]@{
        id            = $timeZone.Id
        displayName   = $timeZone.DisplayName
        baseUtcOffset = $timeZone.BaseUtcOffset.ToString()
    }
    operatingSystem     = if ($osContext) {
        [pscustomobject][ordered]@{
            caption      = $osContext.Caption
            version      = $osContext.Version
            buildNumber  = $osContext.BuildNumber
            architecture = $osContext.OSArchitecture
        }
    } else { $null }
    powerShellVersion   = $PSVersionTable.PSVersion.ToString()
}
$hostContext | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $hostContextPath -Encoding UTF8
Copy-Item -LiteralPath $ScopePath -Destination $scopeSnapshotPath
Copy-Item -LiteralPath $PSCommandPath -Destination $collectorSnapshotPath

foreach ($metadataDefinition in @(
    @{ Id='metadata-host-context'; Description='Host and collection context.'; Path=$hostContextPath; Format='json'; Count=1 },
    @{ Id='metadata-posture-scope'; Description='Frozen posture scope configuration.'; Path=$scopeSnapshotPath; Format='json'; Count=@($scope.sources).Count },
    @{ Id='metadata-collector'; Description='Frozen collector implementation used for this run.'; Path=$collectorSnapshotPath; Format='text'; Count=1 }
)) {
    $file = Get-Item -LiteralPath $metadataDefinition.Path
    $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
    $artifacts.Add([pscustomobject][ordered]@{
        id           = $metadataDefinition.Id
        category     = 'metadata'
        description  = $metadataDefinition.Description
        status       = 'collected'
        path         = ConvertTo-RelativePath ($file.FullName.Substring($runDirectory.Length + 1))
        format       = $metadataDefinition.Format
        startedUtc   = $collectionStarted.ToString('o')
        completedUtc = [datetime]::UtcNow.ToString('o')
        recordCount  = [int]$metadataDefinition.Count
        sizeBytes    = [long]$file.Length
        sha256       = $hash.Hash.ToLowerInvariant()
        error        = $null
    })
}

foreach ($source in @($scope.sources)) {
    $started = [datetime]::UtcNow
    $relativePath = ConvertTo-RelativePath ([string]$source.outputPath)
    $artifactPath = Resolve-ContainedArtifactPath $runDirectory $relativePath
    $artifactDirectory = Split-Path -Parent $artifactPath
    New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
    $status = 'failed'
    $recordCount = $null
    $errorText = $null
    $sizeBytes = $null
    $sha256 = $null

    Write-Host "Collecting $($source.id)"
    try {
        $result = Invoke-PostureSource -Source $source -ArtifactPath $artifactPath -RunDirectory $runDirectory
        $recordCount = [int]$result.recordCount
        if (-not [bool]$result.directFile) {
            switch ([string]$source.format) {
                'json' {
                    ConvertTo-Json -InputObject $result.data -Depth 14 |
                        Set-Content -LiteralPath $artifactPath -Encoding UTF8
                }
                'csv' {
                    @($result.data) | Set-Content -LiteralPath $artifactPath -Encoding UTF8
                }
                'text' {
                    @($result.data) | Set-Content -LiteralPath $artifactPath -Encoding UTF8
                }
                default {
                    @($result.data) | Set-Content -LiteralPath $artifactPath -Encoding UTF8
                }
            }
        }
        if (-not (Test-Path -LiteralPath $artifactPath)) {
            throw "Collector '$($source.collector)' did not produce its configured artifact."
        }
        $status = if ($result.status) { [string]$result.status } elseif ($recordCount -eq 0) { 'empty' } else { 'collected' }
        if ($result.note) { $errorText = [string]$result.note }
        $file = Get-Item -LiteralPath $artifactPath
        $hash = Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
        $sizeBytes = [long]$file.Length
        $sha256 = $hash.Hash.ToLowerInvariant()
    }
    catch {
        $status = Get-FailureStatus $_
        $errorText = Get-SafeError $_
        $collectionErrors.Add("$($source.id): $errorText")
        if (Test-Path -LiteralPath $artifactPath) {
            $file = Get-Item -LiteralPath $artifactPath
            $hash = Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
            $sizeBytes = [long]$file.Length
            $sha256 = $hash.Hash.ToLowerInvariant()
        }
    }

    $artifacts.Add([pscustomobject][ordered]@{
        id           = [string]$source.id
        category     = [string]$source.category
        description  = [string]$source.description
        status       = $status
        path         = if (Test-Path -LiteralPath $artifactPath) { $relativePath } else { $null }
        format       = [string]$source.format
        startedUtc   = $started.ToString('o')
        completedUtc = [datetime]::UtcNow.ToString('o')
        recordCount  = $recordCount
        sizeBytes    = $sizeBytes
        sha256       = $sha256
        error        = $errorText
    })
}

$collectionCompleted = [datetime]::UtcNow
if ($transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
}

$transcriptReference = [pscustomobject][ordered]@{
    status    = 'failed'
    path      = $null
    sizeBytes = $null
    sha256    = $null
    error     = if ($transcriptStarted) { 'Transcript file was not finalized.' } else { 'Transcript could not be started.' }
}
if (Test-Path -LiteralPath $transcriptPath) {
    $transcriptFile = Get-Item -LiteralPath $transcriptPath
    $transcriptHash = Get-FileHash -LiteralPath $transcriptPath -Algorithm SHA256
    $transcriptReference = [pscustomobject][ordered]@{
        status    = 'collected'
        path      = 'logs/collection-transcript.txt'
        sizeBytes = [long]$transcriptFile.Length
        sha256    = $transcriptHash.Hash.ToLowerInvariant()
        error     = $null
    }
}
if ($transcriptReference.status -ne 'collected') {
    $collectionErrors.Add("Transcript: $($transcriptReference.error)")
}

$summary = [ordered]@{
    configuredSources = @($scope.sources).Count
    totalArtifacts    = $artifacts.Count
    collected         = @($artifacts | Where-Object status -eq 'collected').Count
    partial           = @($artifacts | Where-Object status -eq 'partial').Count
    empty             = @($artifacts | Where-Object status -eq 'empty').Count
    unavailable       = @($artifacts | Where-Object status -eq 'unavailable').Count
    unsupported       = @($artifacts | Where-Object status -eq 'unsupported').Count
    inaccessible      = @($artifacts | Where-Object status -eq 'inaccessible').Count
    failed            = @($artifacts | Where-Object status -eq 'failed').Count
}
$limitationCount = $summary.partial + $summary.unavailable + $summary.unsupported + $summary.inaccessible + $summary.failed
if ($alternateElevationIdentity) {
    $limitationCount++
}
if ($transcriptReference.status -ne 'collected') {
    $limitationCount++
}
$manifestStatus = if ($summary.failed -ge $summary.configuredSources) { 'failed' } elseif ($limitationCount -gt 0) { 'completed-with-limitations' } else { 'completed' }

$collectorHash = (Get-FileHash -LiteralPath $collectorSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [pscustomobject][ordered]@{
    schemaVersion          = '1.0'
    runId                  = $RunId
    status                 = $manifestStatus
    mode                   = 'full-snapshot'
    assessmentDomain       = 'host-posture'
    assessmentId           = [string]$scope.assessmentId
    currentHostOnly        = $true
    hostIdentitySha256     = $hostIdentity.sha256
    hostIdentityStrength   = $hostIdentity.strength
    readOnlyCollection     = $true
    defenderSpecificCollectionExcluded = $true
    computerName          = $env:COMPUTERNAME
    collectionIdentity    = $collectionIdentity
    invokingIdentity      = if ([string]::IsNullOrWhiteSpace($InvokingUser)) { $collectionIdentity } else { $InvokingUser }
    currentUserProfileCoverage = if ($alternateElevationIdentity) { 'degraded-elevated-identity' } else { 'complete' }
    isAdministrator       = Test-IsAdministrator
    powerShellVersion     = $PSVersionTable.PSVersion.ToString()
    collectorVersion      = $collectorVersion
    collectorSnapshot     = 'metadata/collector.ps1'
    collectorSha256       = $collectorHash
    scopeSchemaVersion    = [string]$scope.schemaVersion
    collectionStartedUtc  = $collectionStarted.ToString('o')
    collectionCompletedUtc = $collectionCompleted.ToString('o')
    collectionStartedLocal = $collectionStarted.ToLocalTime().ToString('o')
    collectionCompletedLocal = $collectionCompleted.ToLocalTime().ToString('o')
    timeZone               = [pscustomobject][ordered]@{
        id            = $timeZone.Id
        displayName   = $timeZone.DisplayName
        baseUtcOffset = $timeZone.BaseUtcOffset.ToString()
    }
    scopeConfigSource      = 'provided-scope'
    scopeConfigSnapshot    = 'metadata/posture-scope.json'
    collectionPlanSha256   = (Get-FileHash -LiteralPath $scopeSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
    hostContext            = 'metadata/host-context.json'
    transcript             = $transcriptReference
    summary                = [pscustomobject]$summary
    artifacts              = @($artifacts | ForEach-Object { $_ })
    collectionErrors       = @($collectionErrors | ForEach-Object { $_ })
}
$manifestPath = Resolve-ContainedArtifactPath $runDirectory 'manifest.json'
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Posture run status: $manifestStatus"
Write-Host "Artifacts: $($artifacts.Count)"
Write-Host "Collected: $($summary.collected); empty: $($summary.empty); unavailable: $($summary.unavailable); unsupported: $($summary.unsupported); inaccessible: $($summary.inaccessible); failed: $($summary.failed)"
Write-Host "Run directory: $runDirectory"
