[CmdletBinding()]
param(
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [string]$IntegrationRoot,
    [string]$ServerPath,
    [string]$FixtureName = 'mcp-debuggee-fixture.exe'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($IntegrationRoot)) {
    $IntegrationRoot = Join-Path $PSScriptRoot '..\artifacts\integration'
}
if ([string]::IsNullOrWhiteSpace($ServerPath)) {
    $ServerPath = Join-Path $PSScriptRoot '..\target\debug\x64dbg-mcp-server.exe'
}
if ([string]::IsNullOrWhiteSpace($FixtureName) -or
    $FixtureName -ne [System.IO.Path]::GetFileName($FixtureName) -or
    [System.IO.Path]::GetExtension($FixtureName) -ine '.exe') {
    throw 'FixtureName must be an .exe leaf filename.'
}
$backendRoot = (Resolve-Path -LiteralPath (Join-Path $IntegrationRoot $Backend)).Path
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$debuggerName = if ($Backend -eq 'x32') { 'x32dbg-unsigned.exe' } else { 'x64dbg.exe' }
$debugger = Join-Path $backendRoot $debuggerName
$fixture = Join-Path $backendRoot $FixtureName
$argumentObservation = Join-Path $backendRoot 'mcp-argv-observed.bin'
if (!(Test-Path -LiteralPath $debugger) -or !(Test-Path -LiteralPath $fixture)) {
    throw 'The isolated debugger tree or fixture is missing. Run prepare-integration.ps1 first.'
}
$plugins = Get-ChildItem -LiteralPath (Join-Path $backendRoot 'plugins') -File
$expectedExtension = if ($Backend -eq 'x32') { '.dp32' } else { '.dp64' }
if ($plugins.Count -ne 1 -or $plugins[0].Name -ine "x64dbg-mcp-backend$expectedExtension") {
    throw 'Isolation invariant failed: the debugger plugins directory must contain only this project plugin.'
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$tokenBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tokenBytes)
$token = [Convert]::ToBase64String($tokenBytes)
$baseUri = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }

function Invoke-Mcp([string]$Method, $Params, [int]$Id) {
    if ($Method -eq 'tools/call' -and $null -ne $Params.arguments.operation_id -and
        $null -eq $Params.arguments.instance_id) {
        if ([string]::IsNullOrWhiteSpace($script:InstanceId)) {
            throw 'Mutation attempted before backend instance identity was observed.'
        }
        $Params.arguments.instance_id = $script:InstanceId
    }
    $request = @{ jsonrpc = '2.0'; id = $Id; method = $Method; params = $Params } |
        ConvertTo-Json -Depth 12 -Compress
    $requestBytes = [System.Text.Encoding]::UTF8.GetBytes($request)
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$baseUri/mcp" `
        -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $requestBytes -TimeoutSec 40
    if ($response.error) {
        throw "JSON-RPC error from $Method`: $($response.error | ConvertTo-Json -Compress)"
    }
    return $response.result
}

function Invoke-Tool([string]$Name, $Arguments, [int]$Id) {
    Write-Verbose "Calling $Name"
    $result = Invoke-Mcp 'tools/call' @{ name = $Name; arguments = $Arguments } $Id
    if ($result.isError) {
        throw "Tool error from $Name`: $($result.structuredContent | ConvertTo-Json -Compress -Depth 8)"
    }
    return $result.structuredContent
}

function Assert-ExactStringSequence($Actual, [string[]]$Expected, [string]$Context) {
    $actualItems = @($Actual)
    if ($actualItems.Count -ne $Expected.Count) {
        $actualJson = $actualItems | ConvertTo-Json -Compress
        throw "$Context count mismatch: expected=$($Expected.Count), actual=$($actualItems.Count), values=$actualJson"
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if (![string]::Equals([string]$actualItems[$index], $Expected[$index],
                [StringComparison]::Ordinal)) {
            throw "$Context mismatch at index $index."
        }
    }
}

function Read-ObservedArguments([string]$Path) {
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        $expectedMagic = [System.Text.Encoding]::ASCII.GetBytes("MARGV1`r`n")
        $magic = $reader.ReadBytes($expectedMagic.Length)
        if ($magic.Length -ne $expectedMagic.Length -or
            [BitConverter]::ToString($magic) -ne [BitConverter]::ToString($expectedMagic)) {
            throw 'Fixture argument observation has an invalid format marker.'
        }
        $count = $reader.ReadUInt32()
        if ($count -lt 1 -or $count -gt 64) {
            throw "Fixture argument observation count is invalid: $count"
        }
        $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $items = [System.Collections.Generic.List[string]]::new()
        for ($index = 0; $index -lt $count; $index++) {
            $length = $reader.ReadUInt32()
            if ($length -gt 32768) {
                throw "Fixture argument observation item is too large: $length"
            }
            $bytes = $reader.ReadBytes([int]$length)
            if ($bytes.Length -ne $length) {
                throw 'Fixture argument observation was truncated.'
            }
            $items.Add($strictUtf8.GetString($bytes))
        }
        if ($stream.Position -ne $stream.Length) {
            throw 'Fixture argument observation contains trailing data.'
        }
        return $items.ToArray()
    } finally {
        $stream.Dispose()
    }
}

$previous = @{
    Port = $env:X64DBG_MCP_PORT
    Token = $env:X64DBG_MCP_TOKEN
    Server = $env:X64DBG_MCP_SERVER_PATH
    Rate = $env:X64DBG_MCP_MAX_REQUESTS_PER_SECOND
}
$debuggerProcess = $null
try {
    Write-Verbose "Launching isolated debugger: $debugger"
    Remove-Item -LiteralPath $argumentObservation -Force -ErrorAction SilentlyContinue
    $env:X64DBG_MCP_PORT = [string]$port
    $env:X64DBG_MCP_TOKEN = $token
    $env:X64DBG_MCP_SERVER_PATH = $server
    # This qualification intentionally performs more than 100 calls in a
    # second on fast hosts. Keep the production default unchanged while using
    # the documented hard-bounded test ceiling for this isolated instance.
    $env:X64DBG_MCP_MAX_REQUESTS_PER_SECOND = '1000'
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $debugger
    $startInfo.Arguments = ''
    $startInfo.WorkingDirectory = $backendRoot
    $startInfo.UseShellExecute = $false
    $debuggerProcess = [System.Diagnostics.Process]::Start($startInfo)
    Write-Verbose "Started $Backend debugger process $($debuggerProcess.Id)"

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch {
            $ready = $null
        }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $deadline -or $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready') {
        throw 'Sidecar did not become ready through the isolated debugger plugin.'
    }
    $script:InstanceId = ([Guid]::Parse([string]$ready.instance_id)).ToString()
    if ($ready.debugger_state -ne 'absent' -or $ready.diagnostic_code -ne 'NO_DEBUGGEE' -or
        @($ready.next_actions).Count -ne 2 -or
        $ready.next_actions[0].code -ne 'CALL_DEBUGGEE_LAUNCH' -or
        $ready.next_actions[0].tool -ne 'debuggee.launch' -or
        $ready.next_actions[1].tool -ne 'debuggee.attach') {
        throw 'Readiness did not advertise bounded launch and attach actions.'
    }
    Write-Verbose 'Sidecar is ready'

    $null = Invoke-Mcp 'initialize' @{
        protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'real-integration'; version = '1' }
    } 1
    $beforeLaunch = Invoke-Tool 'debugger.state' @{} 2
    if ($beforeLaunch.instance_id -ne $script:InstanceId) {
        throw 'Readiness and debugger.state reported different backend instances.'
    }
    if ($beforeLaunch.debuggee_state -ne 'absent') {
        throw "Isolated debugger did not start without a debuggee; actual=$($beforeLaunch.debuggee_state)"
    }
    if ($beforeLaunch.diagnostic_code -ne 'NO_DEBUGGEE' -or
        @($beforeLaunch.next_actions).Count -ne 2 -or
        $beforeLaunch.next_actions[0].tool -ne 'debuggee.launch' -or
        $beforeLaunch.next_actions[1].tool -ne 'debuggee.attach') {
        throw 'debugger.state did not advertise absent-debuggee launch and attach actions.'
    }
    $invalidLaunch = Invoke-Mcp 'tools/call' @{
        name = 'debuggee.launch'
        arguments = @{
            operation_id = [Guid]::NewGuid().ToString()
            path = '.\relative-fixture.exe'
        }
    } 3
    if (!$invalidLaunch.isError -or
        $invalidLaunch.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'debuggee.launch did not reject a relative path before queuing InitDebug.'
    }
    # Keep this Windows PowerShell 5.1 script ASCII-only: UTF-8 without a BOM is
    # otherwise decoded through the active ANSI code page before JSON encoding.
    $unicodeArgument = -join @([char]0x5169, [char]0x500b, [char]0x5b57)
    [string[]]$launchArgumentValues = @(
        '', 'plain', 'with space', 'quote"inside', 'trail\', 'comma,value', $unicodeArgument
    )
    $launchArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        path = $fixture
        working_directory = $backendRoot
        arguments = $launchArgumentValues
    }
    $launch = Invoke-Tool 'debuggee.launch' $launchArguments 4
    $launchReplay = Invoke-Tool 'debuggee.launch' $launchArguments 204
    Assert-ExactStringSequence $launch.arguments $launchArgumentValues 'Launch result arguments'
    if (($launch | ConvertTo-Json -Compress -Depth 10) -ne
        ($launchReplay | ConvertTo-Json -Compress -Depth 10)) {
        throw 'debuggee.launch did not replay the admitted operation exactly.'
    }
    $launchConflict = Invoke-Mcp 'tools/call' @{
        name = 'debuggee.launch'; arguments = @{
            operation_id = $launchArguments.operation_id
            path = $fixture
            working_directory = $backendRoot
            arguments = @('different')
        }
    } 205
    if (!$launchConflict.isError -or
        $launchConflict.structuredContent.error.code -ne 'OPERATION_ID_CONFLICT') {
        throw 'debuggee.launch did not reject changed arguments under a reused operation_id.'
    }
    $state = Invoke-Tool 'debugger.state' @{} 5
    if ($state.debuggee_state -ne 'paused') {
        throw "Fixture did not reach paused state; actual=$($state.debuggee_state)"
    }
    if ($null -ne $state.diagnostic_code -or @($state.next_actions).Count -ne 0) {
        throw 'Paused debugger.state retained a stale bootstrap diagnostic.'
    }
    Write-Verbose 'Debuggee is paused'

    $registers = Invoke-Tool 'registers.read' @{} 3
    $callstack = Invoke-Tool 'callstack.read' @{ limit = 50 } 201
    if (!$callstack.thread_id -or @($callstack.frames).Count -gt 50 -or
        $callstack.native_frame_count -lt @($callstack.frames).Count -or
        $callstack.completeness -notin @('native_bounded', 'inconclusive') -or
        $callstack.state_generation -ne $state.state_generation) {
        throw 'Native call-stack read was not bounded and generation-consistent.'
    }
    $specificCallstack = Invoke-Tool 'callstack.read' @{
        thread_id = $callstack.thread_id; limit = 1
    } 202
    if ($specificCallstack.thread_id -ne $callstack.thread_id -or
        @($specificCallstack.frames).Count -gt 1) {
        throw 'Exact-thread call-stack selection did not honor its bound.'
    }
    $expression = Invoke-Tool 'expression.evaluate' @{ expression = 'cip' } 4
    $memory = Invoke-Tool 'memory.read' @{ address = $expression.value; length = 16 } 5
    $disassembly = Invoke-Tool 'disassembly.read' @{ address = $expression.value; count = 4 } 6
    $modules = Invoke-Tool 'modules.list' @{ limit = 256 } 7
    $fixtureName = [System.IO.Path]::GetFileName($fixture)
    $fixtureModule = @($modules.items | Where-Object { $_.name -ieq $fixtureName })[0]
    if (!$fixtureModule) {
        $actualModuleNames = @($modules.items | ForEach-Object { $_.name }) -join ', '
        throw "The launched fixture '$fixtureName' was not present in modules.list; actual: $actualModuleNames"
    }
    $importPageOne = Invoke-Tool 'imports.list' @{
        module = $fixtureModule.name; limit = 1
    } 206
    if ($importPageOne.native_count -lt 1 -or $importPageOne.matched_count -lt 1 -or
        @($importPageOne.items).Count -ne 1 -or !$importPageOne.next_cursor -or
        $importPageOne.state_generation -ne $state.state_generation) {
        throw 'Bounded import pagination did not return one generation-consistent item.'
    }
    $importPageTwo = Invoke-Tool 'imports.list' @{
        module = $fixtureModule.name; limit = 1; cursor = $importPageOne.next_cursor
    } 207
    if (@($importPageTwo.items).Count -gt 1 -or
        $importPageTwo.native_count -ne $importPageOne.native_count) {
        throw 'Import cursor did not preserve its native snapshot shape.'
    }
    $importCursorMismatch = Invoke-Mcp 'tools/call' @{
        name = 'imports.list'; arguments = @{
            module = $fixtureModule.name; query = 'Sleep'; limit = 1
            cursor = $importPageOne.next_cursor
        }
    } 208
    if (!$importCursorMismatch.isError -or
        $importCursorMismatch.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Import cursor was not bound to its literal filter.'
    }
    $sleepImports = Invoke-Tool 'imports.list' @{
        module = $fixtureModule.name; query = 'Sleep'; limit = 16
    } 209
    $sleepImport = @($sleepImports.items | Where-Object {
        $_.name -and $_.name.IndexOf('Sleep', [StringComparison]::OrdinalIgnoreCase) -ge 0
    })[0]
    if (!$sleepImport -or !$sleepImport.iat.address -or
        $sleepImport.resolution -notin @('resolved', 'unresolved', 'unreadable')) {
        throw 'Module import metadata did not expose the fixture Sleep IAT record.'
    }
    $fixtureExports = Invoke-Tool 'exports.list' @{
        module = $fixtureModule.name; query = 'mcp_fixture'; limit = 16
    } 210
    if ($fixtureExports.matched_count -lt 3 -or @($fixtureExports.items).Count -lt 3 -or
        @($fixtureExports.items | Where-Object { !$_.location.address }).Count -ne 0) {
        throw 'Module export metadata did not expose the fixture exports.'
    }
    $kernelModule = @($modules.items | Where-Object { $_.name -ieq 'kernel32.dll' })[0]
    if (!$kernelModule) {
        throw 'The loaded kernel32 module was unavailable for forwarder qualification.'
    }
    $forwardedExports = Invoke-Tool 'exports.list' @{
        module = $kernelModule.name; query = 'AcquireSRWLockExclusive'; limit = 16
    } 211
    $forwardedExport = @($forwardedExports.items | Where-Object {
        $_.forwarded -and $_.forward_name
    })[0]
    if (!$forwardedExport) {
        throw 'Forwarded export metadata was not preserved by exports.list.'
    }
    $moduleBase = [Convert]::ToUInt64($fixtureModule.base.Substring(2), 16)
    $moduleEntry = [Convert]::ToUInt64($fixtureModule.entry.Substring(2), 16)
    $entryRva = '0x{0:x}' -f ($moduleEntry - $moduleBase)
    $moduleEntryRef = @{
        module = $fixtureModule.name.ToUpperInvariant()
        rva = $entryRva
    }
    $resolvedEntry = Invoke-Tool 'address.resolve' @{ address = $moduleEntryRef } 41
    if ($resolvedEntry.address -ne $fixtureModule.entry -or
        $resolvedEntry.module -ine $fixtureModule.name -or
        $resolvedEntry.rva -ne $entryRva) {
        throw 'Module-relative address resolution did not return the fixture entry.'
    }
    $resolvedAbsolute = Invoke-Tool 'address.resolve' @{
        address = @{ absolute = $fixtureModule.entry }
    } 44
    if ($resolvedAbsolute.address -ne $resolvedEntry.address -or
        $resolvedAbsolute.module -ine $resolvedEntry.module -or
        $resolvedAbsolute.rva -ne $resolvedEntry.rva) {
        throw 'Structured absolute and module-relative references did not resolve equally.'
    }
    $missingModule = Invoke-Mcp 'tools/call' @{
        name = 'address.resolve'
        arguments = @{ address = @{ module = 'definitely-missing.exe'; rva = '0x0' } }
    } 45
    if (!$missingModule.isError -or
        $missingModule.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'address.resolve did not reject a missing module.'
    }
    $outsideModule = Invoke-Mcp 'tools/call' @{
        name = 'address.resolve'
        arguments = @{ address = @{ module = $fixtureModule.name; rva = $fixtureModule.size } }
    } 46
    if (!$outsideModule.isError -or
        $outsideModule.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'address.resolve did not reject an RVA at the module size boundary.'
    }
    $tooWideAddress = if ($Backend -eq 'x32') { '0x100000000' } else { '0x10000000000000000' }
    $pointerWidth = Invoke-Mcp 'tools/call' @{
        name = 'address.resolve'
        arguments = @{ address = $tooWideAddress }
    } 47
    if (!$pointerWidth.isError -or
        $pointerWidth.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'address.resolve did not reject an address wider than the debugger pointer.'
    }
    $afterWidthError = Invoke-Tool 'debugger.state' @{} 48
    if ($afterWidthError.plugin_state -ne 'ready' -or
        $afterWidthError.debuggee_state -ne 'paused') {
        throw 'A pointer-width validation error damaged the plugin connection.'
    }
    $moduleMemory = Invoke-Tool 'memory.read' @{ address = $moduleEntryRef; length = 16 } 42
    $moduleDisassembly = Invoke-Tool 'disassembly.read' @{ address = $moduleEntryRef; count = 4 } 43
    $patchInstructionSize = [int]$moduleDisassembly.items[0].size
    if ($patchInstructionSize -lt 1 -or $patchInstructionSize -gt 16) {
        throw 'Fixture entry did not begin with a bounded patchable instruction.'
    }
    $patchOriginalHex = $moduleMemory.data_hex.Substring(0, $patchInstructionSize * 2)
    $patchPreview = Invoke-Tool 'assembly.preview' @{
        address = $moduleEntryRef; instruction = 'int3'
    } 120
    if ($patchPreview.bytes_hex -ne 'cc' -or $patchPreview.byte_count -ne 1 -or
        $patchPreview.state_generation -ne $state.state_generation) {
        throw 'Assembly preview was not exact and generation-consistent.'
    }
    $stalePatch = Invoke-Mcp 'tools/call' @{
        name = 'assembly.patch'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString(); address = $moduleEntryRef
            instruction = 'int3'; expected_bytes_hex = ('00' * $patchInstructionSize)
            fill_nop = $true
        }
    } 121
    if (!$stalePatch.isError -or $stalePatch.structuredContent.error.code -ne 'CONFLICT') {
        throw 'Assembly patch did not reject stale expected bytes.'
    }
    $patchArguments = @{
        operation_id = [Guid]::NewGuid().ToString(); address = $moduleEntryRef
        instruction = 'int3'; expected_bytes_hex = $patchOriginalHex; fill_nop = $true
    }
    $trackedPatch = Invoke-Tool 'assembly.patch' $patchArguments 122
    $trackedPatchReplay = Invoke-Tool 'assembly.patch' $patchArguments 123
    if (!$trackedPatch.patch_tracked -or $trackedPatch.patched_bytes_hex.Length -ne
        $patchOriginalHex.Length -or $trackedPatch.nop_padding -ne ($patchInstructionSize - 1) -or
        ($trackedPatch | ConvertTo-Json -Compress -Depth 12) -ne
        ($trackedPatchReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Tracked assembly patch was not bounded, padded, or replay-safe.'
    }
    $secondPatchInstruction = $moduleDisassembly.items[2]
    $secondPatchMemory = Invoke-Tool 'memory.read' @{
        address = @{ absolute = $secondPatchInstruction.address }
        length = [int]$secondPatchInstruction.size
    } 209
    $secondPatchAssembly = if ($secondPatchMemory.data_hex.StartsWith('cc')) { 'nop' } else { 'int3' }
    $secondPatch = Invoke-Tool 'assembly.patch' @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $secondPatchInstruction.address }
        instruction = $secondPatchAssembly
        expected_bytes_hex = $secondPatchMemory.data_hex; fill_nop = $true
    } 210
    $patchPageOne = Invoke-Tool 'patches.list' @{
        module = $fixtureModule.name; limit = 1
    } 211
    if (@($patchPageOne.items).Count -ne 1 -or !$patchPageOne.next_cursor -or
        !$patchPageOne.next_cursor.StartsWith('v3:')) {
        throw 'Disjoint patch ranges did not produce a bounded v3 cursor.'
    }
    $patchPageTwo = Invoke-Tool 'patches.list' @{
        module = $fixtureModule.name; limit = 1; cursor = $patchPageOne.next_cursor
    } 212
    if (@($patchPageTwo.items).Count -ne 1 -or $patchPageTwo.next_cursor -or
        $patchPageTwo.snapshot_fingerprint -ne $patchPageOne.snapshot_fingerprint) {
        throw 'Patch pagination mixed snapshots or returned an invalid second page.'
    }
    $null = Invoke-Tool 'patches.restore' @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $secondPatchInstruction.address }
        expected_patched_bytes_hex = $secondPatch.patched_bytes_hex
        expected_original_bytes_hex = $secondPatchMemory.data_hex
    } 213
    $stalePatchCursor = Invoke-Mcp 'tools/call' @{
        name = 'patches.list'; arguments = @{
            module = $fixtureModule.name; limit = 1; cursor = $patchPageOne.next_cursor
        }
    } 214
    if (!$stalePatchCursor.isError -or
        $stalePatchCursor.structuredContent.error.code -ne 'STALE_CURSOR') {
        throw 'Patch pagination did not reject database churn without a generation change.'
    }
    $listedPatches = Invoke-Tool 'patches.list' @{
        module = $fixtureModule.name.ToUpperInvariant(); limit = 256
    } 203
    $listedEntryPatch = @($listedPatches.items | Where-Object {
        $_.start.address -eq $trackedPatch.address
    })[0]
    if (!$listedEntryPatch -or !$listedEntryPatch.current_matches_patch -or
        $listedEntryPatch.original_bytes_hex -ne $patchOriginalHex -or
        $listedEntryPatch.patched_bytes_hex -ne $trackedPatch.patched_bytes_hex -or
        $listedPatches.completeness -ne 'tracked_only' -or
        !$listedPatches.snapshot_fingerprint) {
        throw 'Tracked patch listing did not return the verified adjacent range.'
    }
    $overlappingPatch = Invoke-Mcp 'tools/call' @{
        name = 'assembly.patch'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString(); address = $moduleEntryRef
            instruction = 'int3'; expected_bytes_hex = $trackedPatch.patched_bytes_hex
            fill_nop = $true
        }
    } 124
    if (!$overlappingPatch.isError -or
        $overlappingPatch.structuredContent.error.code -ne 'CONFLICT') {
        throw 'Assembly patch did not reject an already tracked span.'
    }
    $restoreArguments = @{
        operation_id = [Guid]::NewGuid().ToString(); address = $moduleEntryRef
        expected_patched_bytes_hex = $trackedPatch.patched_bytes_hex
        expected_original_bytes_hex = $patchOriginalHex
    }
    $restoredPatch = Invoke-Tool 'patches.restore' $restoreArguments 125
    $restoredPatchReplay = Invoke-Tool 'patches.restore' $restoreArguments 126
    $memoryAfterRestore = Invoke-Tool 'memory.read' @{
        address = $moduleEntryRef; length = $patchInstructionSize
    } 127
    if ($restoredPatch.patch_tracked -or $memoryAfterRestore.data_hex -ne $patchOriginalHex -or
        ($restoredPatch | ConvertTo-Json -Compress -Depth 12) -ne
        ($restoredPatchReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Tracked patch restore did not exactly recover the fixture bytes.'
    }
    $patchesAfterRestore = Invoke-Tool 'patches.list' @{
        module = $fixtureModule.name; limit = 256
    } 204
    if (@($patchesAfterRestore.items).Count -ne 0 -or
        $patchesAfterRestore.completeness -ne 'tracked_only') {
        throw 'Patch listing retained restored patch records.'
    }
    $compactSnapshot = Invoke-Tool 'debugger.snapshot' @{} 54
    if ($compactSnapshot.state_generation -ne $state.state_generation -or
        $compactSnapshot.instruction_pointer.address -ne $expression.value -or
        $compactSnapshot.instruction_pointer.state_generation -ne $compactSnapshot.state_generation -or
        @($compactSnapshot.registers.PSObject.Properties).Count -ne 4 -or
        @($compactSnapshot.disassembly).Count -ne 8) {
        throw 'Compact debugger snapshot mixed generations or omitted its bounded default fields.'
    }
    $symbols = Invoke-Tool 'symbols.search' @{
        module = $fixtureModule.name.ToUpperInvariant(); query = 'mcp_fixture'; limit = 32
    } 60
    $functions = Invoke-Tool 'functions.list' @{
        module = $fixtureModule.name.ToUpperInvariant(); limit = 32
    } 61
    $analysisSymbol = @($symbols.items | Where-Object {
        $_.name -ieq 'mcp_fixture_analysis_target'
    })[0]
    $markerSymbol = @($symbols.items | Where-Object {
        $_.name -ieq 'mcp_fixture_marker'
    })[0]
    if (!$analysisSymbol -or !$analysisSymbol.location.rva -or
        !$markerSymbol -or !$markerSymbol.location.rva) {
        throw 'Fixture analysis and marker exports were not available as structured symbols.'
    }
    $resolvedSymbolByName = Invoke-Tool 'symbols.resolve' @{
        module = $fixtureModule.name.ToUpperInvariant(); name = $analysisSymbol.name
    } 205
    $resolvedSymbolByAddress = Invoke-Tool 'symbols.resolve' @{
        address = @{ absolute = $analysisSymbol.location.address }
    } 206
    if ($resolvedSymbolByName.resolution -ne 'found' -or
        $resolvedSymbolByName.total_matches -ne 1 -or
        $resolvedSymbolByName.matches[0].location.address -ne $analysisSymbol.location.address -or
        $resolvedSymbolByAddress.resolution -eq 'missing' -or
        @($resolvedSymbolByAddress.matches | Where-Object {
            $_.name -ceq $analysisSymbol.name
        }).Count -eq 0) {
        throw 'Exact symbol resolution did not agree by name and runtime address.'
    }
    $missingSymbol = Invoke-Tool 'symbols.resolve' @{
        module = $fixtureModule.name; name = '__mcp_definitely_missing_symbol__'
    } 207
    if ($missingSymbol.resolution -ne 'missing' -or $missingSymbol.total_matches -ne 0) {
        throw 'Missing exact symbol resolution was not an explicit successful result.'
    }
    $analysisRef = @{
        module = $fixtureModule.name.ToUpperInvariant()
        rva = $analysisSymbol.location.rva
    }
    $markerRef = @{
        module = $fixtureModule.name.ToUpperInvariant()
        rva = $markerSymbol.location.rva
    }
    $analysisOperation = [Guid]::NewGuid().ToString()
    $analysis = Invoke-Tool 'analysis.function' @{
        operation_id = $analysisOperation; address = $analysisRef
    } 72
    if ($analysis.state_generation -ne $state.state_generation -or
        $analysis.requested_location.address -ne $analysisSymbol.location.address -or
        !$analysis.function.start.module -or !$analysis.function.end.module) {
        throw 'Explicit function analysis omitted generation-consistent structured results.'
    }
    $knownFunction = Invoke-Tool 'functions.at' @{ address = $analysisRef } 208
    if (!$knownFunction.found -or !$knownFunction.function.contains_query -or
        $knownFunction.function.start.address -ne $analysis.function.start.address -or
        $knownFunction.function.end_inclusive.address -ne $analysis.function.end.address -or
        $knownFunction.completeness -ne 'known_only') {
        throw 'Known-function lookup did not return the analyzed containing function.'
    }
    $analysisReplay = Invoke-Tool 'analysis.function' @{
        operation_id = $analysisOperation; address = $analysisRef
    } 73
    if (($analysisReplay | ConvertTo-Json -Compress -Depth 12) -ne
        ($analysis | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Explicit function analysis did not replay its recorded operation result.'
    }
    $analysisFunctionFound = $false
    $analysisCursor = $null
    for ($analysisPage = 0; $analysisPage -lt 8; $analysisPage++) {
        $analysisListArguments = @{
            module = $fixtureModule.name.ToUpperInvariant(); limit = 256
        }
        if ($analysisCursor) { $analysisListArguments.cursor = $analysisCursor }
        $analyzedFunctions = Invoke-Tool 'functions.list' $analysisListArguments (74 + $analysisPage)
        if ($analyzedFunctions.state_generation -ne $state.state_generation) {
            throw 'Function discovery changed generation after explicit analysis.'
        }
        if (@($analyzedFunctions.items | Where-Object {
            $_.start.address -eq $analysis.function.start.address
        }).Count -ne 0) {
            $analysisFunctionFound = $true
            break
        }
        $analysisCursor = $analyzedFunctions.next_cursor
        if (!$analysisCursor) { break }
    }
    if (!$analysisFunctionFound) {
        throw 'Explicit analysis was not visible through known-only function discovery.'
    }
    $asciiStrings = Invoke-Tool 'strings.search' @{
        module = $fixtureModule.name.ToUpperInvariant(); query = 'MCP_DISCOVERY_ASCII_SENTINEL'
        encoding = 'ascii_utf8'; context_bytes = 0; min_length = 4; limit = 8
    } 62
    $wideStrings = Invoke-Tool 'strings.search' @{
        module = $fixtureModule.name.ToUpperInvariant(); query = 'MCP_DISCOVERY_UTF16_SENTINEL'
        encoding = 'utf16le'; context_bytes = 0; min_length = 4; limit = 8
    } 63
    $references = Invoke-Tool 'references.to' @{ address = $moduleEntryRef; limit = 32 } 64
    if (@($asciiStrings.items | Where-Object { $_.text -eq 'MCP_DISCOVERY_ASCII_SENTINEL' }).Count -eq 0 -or
        @($wideStrings.items | Where-Object { $_.text -eq 'MCP_DISCOVERY_UTF16_SENTINEL' }).Count -eq 0) {
        throw 'Bounded string discovery did not find both fixture sentinels.'
    }
    foreach ($item in @($asciiStrings.items) + @($wideStrings.items)) {
        if ($null -eq $item.match_offset -or $null -eq $item.text_offset -or
            $item.match_offset -lt $item.text_offset -or $item.before -ne '' -or
            $item.after -ne '' -or $item.text -ne $item.match -or
            $item.text -ne ($item.before + $item.match + $item.after)) {
            throw 'A compact string result omitted its exact reconstructable match context.'
        }
    }
    foreach ($discovery in @($symbols, $functions, $asciiStrings, $wideStrings, $references)) {
        if ($discovery.completeness -ne 'known_only' -or
            $discovery.state_generation -ne $state.state_generation) {
            throw 'Discovery result omitted known-only or generation metadata.'
        }
    }
    $discoveryCursorProbe = Invoke-Tool 'strings.search' @{
        module = $fixtureModule.name; min_length = 4; encoding = 'both'; limit = 1
    } 65
    if (!$discoveryCursorProbe.next_cursor -or
        !$discoveryCursorProbe.next_cursor.StartsWith('v2:')) {
        throw 'String discovery did not return a v2 cursor for binding tests.'
    }
    $mismatchedDiscoveryCursor = Invoke-Mcp 'tools/call' @{
        name = 'strings.search'; arguments = @{
            module = $fixtureModule.name; query = 'different-filter'; min_length = 4
            encoding = 'both'; limit = 1; cursor = $discoveryCursorProbe.next_cursor
        }
    } 66
    if (!$mismatchedDiscoveryCursor.isError -or
        $mismatchedDiscoveryCursor.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Discovery cursor was not bound to its exact filters.'
    }
    $contextCursorProbe = Invoke-Tool 'strings.search' @{
        module = $fixtureModule.name; query = 'MCP'; context_bytes = 0
        min_length = 4; encoding = 'both'; limit = 1
    } 70
    if (!$contextCursorProbe.next_cursor) {
        throw 'String discovery did not return a cursor for context binding.'
    }
    $mismatchedContextCursor = Invoke-Mcp 'tools/call' @{
        name = 'strings.search'; arguments = @{
            module = $fixtureModule.name; query = 'MCP'; context_bytes = 1
            min_length = 4; encoding = 'both'; limit = 1
            cursor = $contextCursorProbe.next_cursor
        }
    } 71
    if (!$mismatchedContextCursor.isError -or
        $mismatchedContextCursor.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Discovery cursor was not bound to context_bytes.'
    }
    $afterDiscoveryCursorError = Invoke-Tool 'debugger.state' @{} 67
    if ($afterDiscoveryCursorError.plugin_state -ne 'ready') {
        throw 'A mismatched discovery cursor damaged the plugin connection.'
    }
    $threads = Invoke-Tool 'threads.list' @{ limit = 2 } 8
    $memoryMap = Invoke-Tool 'memory.map' @{ limit = 2 } 9
    $cursorProbe = Invoke-Tool 'memory.map' @{ limit = 1 } 52
    $filteredMap = Invoke-Tool 'memory.map' @{
        module = $fixtureModule.name.ToUpperInvariant(); committed_only = $true
        executable_only = $true; compact = $true; limit = 1
    } 69
    if (@($filteredMap.items).Count -ne 1 -or !$filteredMap.next_cursor -or
        !$filteredMap.next_cursor.StartsWith('v2:')) {
        throw 'Filtered memory.map did not return one bounded item and a v2 cursor.'
    }
    $moduleEnd = $moduleBase + [Convert]::ToUInt64($fixtureModule.size.Substring(2), 16)
    foreach ($region in @($filteredMap.items)) {
        $regionBase = [Convert]::ToUInt64($region.base.Substring(2), 16)
        $regionSize = [Convert]::ToUInt64($region.size.Substring(2), 16)
        if ($region.state -ne '0x1000' -or $regionBase -ge $moduleEnd -or
            ($regionBase + $regionSize) -le $moduleBase) {
            throw 'Filtered memory.map returned a non-committed region outside the fixture module.'
        }
        if ($region.PSObject.Properties.Name -contains 'allocation_base' -and
            $region.allocation_base -eq $region.base) {
            throw 'Compact memory.map retained a redundant allocation_base.'
        }
        if ($region.PSObject.Properties.Name -contains 'info' -and
            [string]::IsNullOrEmpty($region.info)) {
            throw 'Compact memory.map retained an empty info field.'
        }
    }
    $mismatchedMapCursor = Invoke-Mcp 'tools/call' @{
        name = 'memory.map'; arguments = @{
            module = $fixtureModule.name.ToUpperInvariant(); committed_only = $true
            executable_only = $true; compact = $false; limit = 1
            cursor = $filteredMap.next_cursor
        }
    } 70
    if (!$mismatchedMapCursor.isError -or
        $mismatchedMapCursor.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Memory-map cursor was not bound to its exact filters.'
    }
    $afterMapCursorError = Invoke-Tool 'debugger.state' @{} 71
    if ($afterMapCursorError.plugin_state -ne 'ready') {
        throw 'A mismatched memory-map cursor damaged the plugin connection.'
    }
    $breakpoints = Invoke-Tool 'breakpoints.list' @{ limit = 2 } 10
    if (!$state.state_generation -or !$registers.state_generation -or
        !$expression.state_generation -or !$memory.state_generation -or
        !$disassembly.state_generation -or !$modules.state_generation -or
        !$threads.state_generation -or !$memoryMap.state_generation -or
        !$breakpoints.state_generation) {
        throw 'A read snapshot omitted its state_generation.'
    }
    if ($memory.state_generation -ne $memory.location.state_generation -or
        $disassembly.state_generation -ne $disassembly.location.state_generation) {
        throw 'Address-consuming read returned mixed snapshot generations.'
    }
    if (!$cursorProbe.next_cursor) {
        throw 'memory.map did not return a cursor for stale-generation testing.'
    }
    $cursorParts = $cursorProbe.next_cursor.Split(':')
    if ($cursorParts.Count -ne 4 -or $cursorParts[0] -ne 'v2' -or
        [uint64]$cursorParts[1] -ne $cursorProbe.state_generation) {
        throw 'Pagination cursor generation does not match its snapshot.'
    }

    $writableRegister = if ($Backend -eq 'x32') { 'edi' } else { 'rdi' }
    $originalRegisterValue = $registers.registers.$writableRegister
    $testRegisterValue = if ($originalRegisterValue -eq '0x11223344') {
        '0x55667788'
    } else {
        '0x11223344'
    }
    $registerWriteArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        name = $writableRegister
        value = $testRegisterValue
    }
    $registerWrite = Invoke-Tool 'registers.write' $registerWriteArguments 80
    $registerWriteReplay = Invoke-Tool 'registers.write' $registerWriteArguments 81
    $registerAfterWrite = Invoke-Tool 'registers.read' @{ names = @($writableRegister) } 82
    if (!$registerWrite.changed -or $registerWrite.previous_value -ne $originalRegisterValue -or
        $registerWrite.value -ne $testRegisterValue -or
        $registerAfterWrite.registers.$writableRegister -ne $testRegisterValue -or
        ($registerWrite | ConvertTo-Json -Compress -Depth 8) -ne
        ($registerWriteReplay | ConvertTo-Json -Compress -Depth 8)) {
        throw 'Typed register write was not verified, observable, or replay-safe.'
    }
    $registerRestore = Invoke-Tool 'registers.write' @{
        operation_id = [Guid]::NewGuid().ToString()
        name = $writableRegister
        value = $originalRegisterValue
    } 83
    $registerAfterRestore = Invoke-Tool 'registers.read' @{ names = @($writableRegister) } 84
    if ($registerRestore.value -ne $originalRegisterValue -or
        $registerAfterRestore.registers.$writableRegister -ne $originalRegisterValue) {
        throw 'Typed register write did not restore the fixture context.'
    }
    $tooWideRegister = Invoke-Mcp 'tools/call' @{
        name = 'registers.write'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString()
            name = 'eflags'; value = '0x100000000'
        }
    } 85
    if (!$tooWideRegister.isError -or
        $tooWideRegister.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Register write did not reject a value wider than eflags.'
    }

    $writeOperation = [Guid]::NewGuid().ToString()
    $write = Invoke-Tool 'memory.write' @{
        operation_id = $writeOperation; address = $moduleEntryRef; data_hex = $moduleMemory.data_hex.Substring(0, 2)
    } 11
    $writeReplay = Invoke-Tool 'memory.write' @{
        operation_id = $writeOperation; address = $moduleEntryRef; data_hex = $moduleMemory.data_hex.Substring(0, 2)
    } 12
    if (($write | ConvertTo-Json -Compress) -ne ($writeReplay | ConvertTo-Json -Compress)) {
        throw 'Mutation replay did not return the recorded memory.write result.'
    }
    $earlyHardwareRejected = $null
    if ($state.pause_reason.kind -in @('process_created', 'system_breakpoint')) {
        $earlyHardware = Invoke-Mcp 'tools/call' @{
            name = 'breakpoints.hardware.set'; arguments = @{
                operation_id = [Guid]::NewGuid().ToString()
                address = $analysisRef; access = 'execute'; size = 1
            }
        } 76
        if (!$earlyHardware.isError -or
            $earlyHardware.structuredContent.error.code -ne 'INVALID_DEBUGGER_STATE') {
            throw 'Hardware setup did not reject a transient startup pause.'
        }
        $earlyHardwareRejected = $true
    }
    # Hardware debug registers are applied to the actionable debug thread. Move
    # past x64dbg's startup pause before installing the slot.
    $hardwareReadyResume = Invoke-Tool 'debugger.resume' @{
        operation_id = [Guid]::NewGuid().ToString()
    } 78
    $hardwareReadyPause = Invoke-Tool 'debugger.wait_for_pause' @{
        after_generation = $hardwareReadyResume.state_generation; timeout_ms = 9000
    } 79
    if ($hardwareReadyPause.debuggee_state -ne 'paused' -or
        $hardwareReadyPause.state_generation -le $hardwareReadyResume.state_generation) {
        throw 'Fixture did not reach an actionable pause before hardware breakpoint setup.'
    }
    $analysisAddressValue = [Convert]::ToUInt64($analysis.requested_location.address.Substring(2), 16)
    $unalignedHardware = Invoke-Mcp 'tools/call' @{
        name = 'breakpoints.hardware.set'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString()
            address = @{ absolute = ('0x{0:x}' -f ($analysisAddressValue + 1)) }
            access = 'write'; size = 4
        }
    } 77
    if (!$unalignedHardware.isError -or
        $unalignedHardware.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Hardware setup did not reject a misaligned data breakpoint.'
    }
    if ($Backend -eq 'x32') {
        $x86WideHardware = Invoke-Mcp 'tools/call' @{
            name = 'breakpoints.hardware.set'; arguments = @{
                operation_id = [Guid]::NewGuid().ToString()
                address = $analysisRef; access = 'write'; size = 8
            }
        } 75
        if (!$x86WideHardware.isError -or
            $x86WideHardware.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
            throw 'x32 hardware setup did not reject an 8-byte debug-register request.'
        }
    }
    $hardwareArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = $analysisRef; access = 'execute'; size = 1
    }
    $hardwareSet = Invoke-Tool 'breakpoints.hardware.set' $hardwareArguments 86
    $hardwareSetReplay = Invoke-Tool 'breakpoints.hardware.set' $hardwareArguments 87
    $hardwareList = Invoke-Tool 'breakpoints.list' @{ limit = 256 } 88
    $listedHardware = @($hardwareList.items | Where-Object {
        $_.address -eq $analysis.requested_location.address -and $_.type -eq 'hardware'
    })[0]
    if (!$hardwareSet.present -or $hardwareSet.access -ne 'execute' -or
        $hardwareSet.size -ne 1 -or $hardwareSet.slot -lt 0 -or $hardwareSet.slot -gt 3 -or
        !$listedHardware -or $listedHardware.access -ne 'execute' -or
        $listedHardware.size -ne 1 -or
        ($hardwareSet | ConvertTo-Json -Compress -Depth 10) -ne
        ($hardwareSetReplay | ConvertTo-Json -Compress -Depth 10)) {
        throw 'Typed hardware breakpoint was not exactly listed or replay-safe.'
    }
    $hardwareMismatch = Invoke-Mcp 'tools/call' @{
        name = 'breakpoints.hardware.remove'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString()
            address = $analysisRef; access = 'write'; size = 1
        }
    } 89
    if (!$hardwareMismatch.isError -or
        $hardwareMismatch.structuredContent.error.code -ne 'CONFLICT') {
        throw "Hardware removal did not reject a mismatched access shape: $($hardwareMismatch | ConvertTo-Json -Compress -Depth 10)"
    }
    $stepOutEntryPause = $null
    for ($stepOutAttempt = 0; $stepOutAttempt -lt 6; $stepOutAttempt++) {
        $stepOutResume = Invoke-Tool 'debugger.resume' @{
            operation_id = [Guid]::NewGuid().ToString()
        } (87 + $stepOutAttempt * 2)
        $stepOutWait = Invoke-Tool 'debugger.wait_for_pause' @{
            after_generation = $stepOutResume.state_generation; timeout_ms = 9000
        } (88 + $stepOutAttempt * 2)
        if ($stepOutWait.pause_reason.kind -eq 'breakpoint' -and
            $stepOutWait.pause_reason.address -eq $analysis.requested_location.address) {
            $stepOutEntryPause = $stepOutWait
            break
        }
    }
    if (!$stepOutEntryPause) {
        throw 'Fixture analysis target was not reached for step-out qualification.'
    }
    if ($stepOutEntryPause.pause_reason.breakpoint_type -ne 'hardware') {
        throw 'Fixture function entry did not report a hardware breakpoint hit.'
    }
    $hardwareRemoveArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = $analysisRef; access = 'execute'; size = 1
    }
    $hardwareRemove = Invoke-Tool 'breakpoints.hardware.remove' $hardwareRemoveArguments 100
    $hardwareRemoveReplay = Invoke-Tool 'breakpoints.hardware.remove' $hardwareRemoveArguments 101
    if ($hardwareRemove.present -or
        ($hardwareRemove | ConvertTo-Json -Compress -Depth 10) -ne
        ($hardwareRemoveReplay | ConvertTo-Json -Compress -Depth 10)) {
        throw 'Typed hardware breakpoint removal was not exactly replay-safe.'
    }
    $stepOutDisassembly = Invoke-Tool 'disassembly.read' @{
        address = $analysisRef; count = 6
    } 102
    $stepOutInterruptInstruction = @($stepOutDisassembly.items | Select-Object -Skip 1 |
        Where-Object { !$_.text.StartsWith('ret', [StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1)[0]
    if (!$stepOutInterruptInstruction) {
        throw 'Fixture function has no deterministic inner instruction for interruption testing.'
    }
    $null = Invoke-Tool 'breakpoints.set' @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $stepOutInterruptInstruction.address }
    } 102
    $interruptedStepOutArguments = @{ operation_id = [Guid]::NewGuid().ToString() }
    $interruptedStepOut = Invoke-Tool 'debugger.step_out' $interruptedStepOutArguments 103
    $interruptedStepOutReplay = Invoke-Tool 'debugger.step_out' $interruptedStepOutArguments 104
    if ($interruptedStepOut.completed -or
        $interruptedStepOut.pause_reason.kind -ne 'breakpoint' -or
        $interruptedStepOut.instruction_pointer -ne $stepOutInterruptInstruction.address -or
        ($interruptedStepOut | ConvertTo-Json -Compress -Depth 8) -ne
        ($interruptedStepOutReplay | ConvertTo-Json -Compress -Depth 8)) {
        throw 'Step-out did not expose and replay its deterministic breakpoint interruption.'
    }
    $null = Invoke-Tool 'breakpoints.remove' @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $stepOutInterruptInstruction.address }
    } 105
    $stepOutArguments = @{ operation_id = [Guid]::NewGuid().ToString() }
    $stepOut = Invoke-Tool 'debugger.step_out' $stepOutArguments 106
    $stepOutReplay = Invoke-Tool 'debugger.step_out' $stepOutArguments 107
    if (!$stepOut.completed -or $stepOut.debuggee_state -ne 'paused' -or
        !($stepOut.instruction.text.StartsWith('ret', [StringComparison]::OrdinalIgnoreCase)) -or
        [Convert]::ToUInt64($stepOut.stack_pointer.Substring(2), 16) -lt
        [Convert]::ToUInt64($stepOut.initial_stack_pointer.Substring(2), 16) -or
        ($stepOut | ConvertTo-Json -Compress -Depth 8) -ne
        ($stepOutReplay | ConvertTo-Json -Compress -Depth 8)) {
        throw 'Step-out was not callback-confirmed at the fixture return or replay-safe.'
    }

    $argumentDeadline = [DateTime]::UtcNow.AddSeconds(5)
    while (!(Test-Path -LiteralPath $argumentObservation) -and
           [DateTime]::UtcNow -lt $argumentDeadline) {
        Start-Sleep -Milliseconds 50
    }
    if (!(Test-Path -LiteralPath $argumentObservation)) {
        throw 'Fixture did not record its received launch arguments.'
    }
    $observedArguments = Read-ObservedArguments $argumentObservation
    if (![string]::Equals([System.IO.Path]::GetFullPath($observedArguments[0]),
            [System.IO.Path]::GetFullPath($fixture), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture observed an unexpected argv[0] executable path.'
    }
    Assert-ExactStringSequence @($observedArguments | Select-Object -Skip 1) `
        $launchArgumentValues 'Fixture-observed launch arguments'

    $markerAddressValue = [Convert]::ToUInt64($markerSymbol.location.address.Substring(2), 16)
    $markerMap = Invoke-Tool 'memory.map' @{
        module = $fixtureModule.name.ToUpperInvariant(); committed_only = $true
        executable_only = $false; compact = $true; limit = 256
    } 116
    $markerRegion = @($markerMap.items | Where-Object {
        $base = [Convert]::ToUInt64($_.base.Substring(2), 16)
        $size = [Convert]::ToUInt64($_.size.Substring(2), 16)
        $markerAddressValue -ge $base -and $markerAddressValue -lt ($base + $size)
    })[0]
    if (!$markerRegion) {
        throw 'Fixture marker memory region was unavailable for range-bound testing.'
    }
    $markerRegionBase = [Convert]::ToUInt64($markerRegion.base.Substring(2), 16)
    $markerRegionSize = [Convert]::ToUInt64($markerRegion.size.Substring(2), 16)
    $crossRegionMemory = Invoke-Mcp 'tools/call' @{
        name = 'breakpoints.memory.set'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString()
            address = @{ absolute = ('0x{0:x}' -f ($markerRegionBase + $markerRegionSize - 1)) }
            access = 'read'; size = 2
        }
    } 117
    if (!$crossRegionMemory.isError -or
        $crossRegionMemory.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Memory breakpoint setup did not reject a cross-region range.'
    }
    $memoryBreakpointArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = $markerRef; access = 'read'; size = 4
    }
    $memoryBreakpoint = Invoke-Tool 'breakpoints.memory.set' $memoryBreakpointArguments 108
    $memoryBreakpointReplay = Invoke-Tool 'breakpoints.memory.set' $memoryBreakpointArguments 109
    $memoryBreakpointList = Invoke-Tool 'breakpoints.list' @{ limit = 256 } 110
    $listedMemory = @($memoryBreakpointList.items | Where-Object {
        $_.address -eq $markerSymbol.location.address -and $_.type -eq 'memory'
    })[0]
    if (!$memoryBreakpoint.present -or $memoryBreakpoint.access -ne 'read' -or
        $memoryBreakpoint.size -ne 4 -or !$listedMemory -or
        $listedMemory.access -ne 'read' -or $listedMemory.size -ne 4 -or
        ($memoryBreakpoint | ConvertTo-Json -Compress -Depth 10) -ne
        ($memoryBreakpointReplay | ConvertTo-Json -Compress -Depth 10)) {
        throw 'Typed memory breakpoint was not exactly listed or replay-safe.'
    }
    $memoryMismatch = Invoke-Mcp 'tools/call' @{
        name = 'breakpoints.memory.remove'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString()
            address = $markerRef; access = 'write'; size = 4
        }
    } 111
    if (!$memoryMismatch.isError -or
        $memoryMismatch.structuredContent.error.code -ne 'CONFLICT') {
        throw "Memory removal did not reject a mismatched access shape: $($memoryMismatch | ConvertTo-Json -Compress -Depth 10)"
    }
    $memoryResume = Invoke-Tool 'debugger.resume' @{
        operation_id = [Guid]::NewGuid().ToString()
    } 112
    $memoryPause = Invoke-Tool 'debugger.wait_for_pause' @{
        after_generation = $memoryResume.state_generation; timeout_ms = 9000
    } 113
    if ($memoryPause.pause_reason.kind -ne 'breakpoint' -or
        $memoryPause.pause_reason.breakpoint_type -ne 'memory') {
        throw 'Fixture marker read did not report a memory breakpoint hit.'
    }
    $memoryRemoveArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = $markerRef; access = 'read'; size = 4
    }
    $memoryRemove = Invoke-Tool 'breakpoints.memory.remove' $memoryRemoveArguments 114
    $memoryRemoveReplay = Invoke-Tool 'breakpoints.memory.remove' $memoryRemoveArguments 115
    if ($memoryRemove.present -or
        ($memoryRemove | ConvertTo-Json -Compress -Depth 10) -ne
        ($memoryRemoveReplay | ConvertTo-Json -Compress -Depth 10)) {
        throw 'Typed memory breakpoint removal was not exactly replay-safe.'
    }
    $resume = $null
    $startupPause = $null
    $stableRunning = $false
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $resume = Invoke-Tool 'debugger.resume' @{
            operation_id = [Guid]::NewGuid().ToString()
        } (14 + $attempt * 2)
        if (!$resume.state_generation) {
            throw 'debugger.resume omitted its callback-confirmed state_generation.'
        }
        $wait = Invoke-Mcp 'tools/call' @{
            name = 'debugger.wait_for_pause'
            arguments = @{ after_generation = $resume.state_generation; timeout_ms = 1500 }
        } (15 + $attempt * 2)
        if ($wait.isError) {
            if ($wait.structuredContent.error.code -ne 'TIMEOUT' -or
                !$wait.structuredContent.error.retryable) {
                throw "Unexpected wait_for_pause failure: $($wait.structuredContent | ConvertTo-Json -Compress -Depth 8)"
            }
            $stableRunning = $true
            break
        }
        $startupPause = $wait.structuredContent
        if ($startupPause.debuggee_state -ne 'paused' -or
            $startupPause.state_generation -le $resume.state_generation -or
            !$startupPause.pause_reason.kind) {
            throw 'Callback wait did not return a newer structured pause observation.'
        }
        if ($startupPause.pause_reason.kind -eq 'breakpoint' -and
            (!$startupPause.pause_reason.address -or
             !$startupPause.pause_reason.breakpoint_type -or
             $null -eq $startupPause.pause_reason.hit_count -or
             !$startupPause.instruction_pointer -or
             !$startupPause.active_thread_id)) {
            throw 'Breakpoint pause observation omitted required address, type, hit, IP, or thread metadata.'
        }
    }
    if (!$stableRunning) {
        throw 'Fixture never reached a stable running window after callback-observed startup pauses.'
    }
    $pause = Invoke-Tool 'debugger.pause' @{ operation_id = [Guid]::NewGuid().ToString() } 40
    $pauseObservation = Invoke-Tool 'debugger.wait_for_pause' @{
        after_generation = $resume.state_generation; timeout_ms = 1500
    } 49
    if ($pauseObservation.state_generation -ne $pause.state_generation -or
        $pauseObservation.pause_reason.kind -ne 'user_pause') {
        throw 'Explicit pause was not retained as a generation-consistent user_pause observation.'
    }
    $stepInto = Invoke-Tool 'debugger.step_into' @{ operation_id = [Guid]::NewGuid().ToString() } 17
    $stepIntoObservation = Invoke-Tool 'debugger.wait_for_pause' @{
        after_generation = $pause.state_generation; timeout_ms = 1500
    } 50
    if ($stepIntoObservation.state_generation -ne $stepInto.state_generation -or
        $stepIntoObservation.pause_reason.kind -ne 'step') {
        throw 'Step-into callback reason or generation was not retained.'
    }
    $staleCursor = Invoke-Mcp 'tools/call' @{
        name = 'memory.map'; arguments = @{ limit = 1; cursor = $cursorProbe.next_cursor }
    } 53
    if (!$staleCursor.isError -or
        $staleCursor.structuredContent.error.code -ne 'STALE_CURSOR') {
        throw 'A cursor from an older debugger generation was not rejected.'
    }
    $staleDiscoveryCursor = Invoke-Mcp 'tools/call' @{
        name = 'strings.search'; arguments = @{
            module = $fixtureModule.name; min_length = 4; encoding = 'both'; limit = 1
            cursor = $discoveryCursorProbe.next_cursor
        }
    } 68
    if (!$staleDiscoveryCursor.isError -or
        $staleDiscoveryCursor.structuredContent.error.code -ne 'STALE_CURSOR') {
        throw "A discovery cursor from an older debugger generation was not rejected: $($staleDiscoveryCursor | ConvertTo-Json -Compress -Depth 8)"
    }
    $stepOver = Invoke-Tool 'debugger.step_over' @{ operation_id = [Guid]::NewGuid().ToString() } 18
    $stepOverObservation = Invoke-Tool 'debugger.wait_for_pause' @{
        after_generation = $stepInto.state_generation; timeout_ms = 1500
    } 51
    if ($stepOverObservation.state_generation -ne $stepOver.state_generation -or
        $stepOverObservation.pause_reason.kind -ne 'step') {
        throw 'Step-over callback reason or generation was not retained.'
    }
    $breakpointSet = Invoke-Tool 'breakpoints.set' @{
        operation_id = [Guid]::NewGuid().ToString(); address = $moduleEntryRef
    } 19
    $breakpointRemove = Invoke-Tool 'breakpoints.remove' @{
        operation_id = [Guid]::NewGuid().ToString(); address = $moduleEntryRef
    } 20
    $stop = Invoke-Tool 'debugger.stop' @{ operation_id = [Guid]::NewGuid().ToString() } 21

    $report = [ordered]@{
        backend = $Backend
        instance_id = $script:InstanceId
        debugger_host_process_id = $debuggerProcess.Id
        sidecar_port = $port
        architecture = $state.architecture
        launched_path = $launch.path
        launch_arguments_exact = $true
        launch_replay_equal = $true
        launch_conflict_rejected = $true
        process_id = $state.process_id
        registers = @($registers.registers.PSObject.Properties).Count
        memory_bytes = $memory.bytes_read
        instructions = $disassembly.items.Count
        modules = $modules.items.Count
        imports = $importPageOne.native_count
        import_pagination_verified = $true
        import_cursor_filter_bound = $true
        sleep_import_resolution = $sleepImport.resolution
        fixture_exports = $fixtureExports.matched_count
        forwarded_export = $forwardedExport.forward_name
        threads = $threads.items.Count
        memory_regions = $memoryMap.items.Count
        compact_snapshot_instructions = @($compactSnapshot.disassembly).Count
        filtered_executable_regions = @($filteredMap.items).Count
        snapshot_generations_present = $true
        bootstrap_launch_action_advertised = $true
        paused_diagnostic_cleared = $true
        address_snapshot_generations_equal = $true
        cursor_generation_matches = $true
        stale_cursor_rejected = $true
        breakpoints = $breakpoints.items.Count
        resolved_entry = $resolvedEntry.address
        resolved_module = $resolvedEntry.module
        resolved_rva = $resolvedEntry.rva
        absolute_resolution_equal = $true
        missing_module_rejected = $true
        out_of_range_rva_rejected = $true
        pointer_width_rejected = $true
        connection_survived_width_error = $true
        module_memory_bytes = $moduleMemory.bytes_read
        module_instructions = $moduleDisassembly.items.Count
        symbols = $symbols.items.Count
        functions = $functions.items.Count
        callstack_frames = @($callstack.frames).Count
        callstack_completeness = $callstack.completeness
        patches_verified = $true
        patch_cursor_snapshot_bound = $true
        exact_symbol_resolution = $true
        known_function_lookup = $true
        analysis_function_start = $analysis.function.start.address
        analysis_function_end = $analysis.function.end.address
        analysis_already_known = $analysis.already_known
        analysis_generation_unchanged = $true
        analysis_replay_equal = $true
        analysis_visible_in_discovery = $analysisFunctionFound
        ascii_strings = $asciiStrings.items.Count
        utf16_strings = $wideStrings.items.Count
        inbound_references = $references.items.Count
        discovery_cursor_filter_bound = $true
        stale_discovery_cursor_rejected = $true
        write_verified = $write.verified
        write_replay_equal = $true
        register_written = $writableRegister
        register_write_verified = $true
        register_write_replay_equal = $true
        register_restored = $true
        register_width_rejected = $true
        step_out_completed = $stepOut.completed
        step_out_interruption_reported = $true
        step_out_instruction = $stepOut.instruction.text
        step_out_replay_equal = $true
        hardware_breakpoint_hit = $true
        initial_pause_reason = $state.pause_reason.kind
        hardware_startup_pause_rejected = $earlyHardwareRejected
        hardware_alignment_rejected = $true
        hardware_x86_size_rejected = $Backend -eq 'x32'
        hardware_breakpoint_slot = $hardwareSet.slot
        hardware_breakpoint_replay_equal = $true
        hardware_breakpoint_mismatch_rejected = $true
        memory_breakpoint_hit = $true
        memory_cross_region_rejected = $true
        memory_breakpoint_size = $memoryBreakpoint.size
        memory_breakpoint_replay_equal = $true
        memory_breakpoint_mismatch_rejected = $true
        resume_state = $resume.debuggee_state
        resume_generation = $resume.state_generation
        startup_pause_reason = if ($startupPause) { $startupPause.pause_reason.kind } else { $null }
        wait_timeout_retryable = $true
        pause_reason = $pauseObservation.pause_reason.kind
        pause_generation = $pauseObservation.state_generation
        step_into_state = $stepInto.debuggee_state
        step_into_reason = $stepIntoObservation.pause_reason.kind
        step_over_state = $stepOver.debuggee_state
        step_over_reason = $stepOverObservation.pause_reason.kind
        breakpoint_set = $breakpointSet.present
        breakpoint_removed = !$breakpointRemove.present
        pause_state = $pause.debuggee_state
        stop_state = $stop.debuggee_state
    }
    $report | ConvertTo-Json -Depth 5
} finally {
    Write-Verbose 'Entering integration cleanup'
    if ($debuggerProcess -and !$debuggerProcess.HasExited) {
        $null = $debuggerProcess.CloseMainWindow()
        if (!$debuggerProcess.WaitForExit(7000)) {
            Stop-Process -Id $debuggerProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $env:X64DBG_MCP_PORT = $previous.Port
    $env:X64DBG_MCP_TOKEN = $previous.Token
    $env:X64DBG_MCP_SERVER_PATH = $previous.Server
    $env:X64DBG_MCP_MAX_REQUESTS_PER_SECOND = $previous.Rate
    Remove-Item -LiteralPath $argumentObservation -Force -ErrorAction SilentlyContinue
    Write-Verbose 'Integration cleanup finished'
}
