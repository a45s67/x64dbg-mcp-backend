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

$previous = @{
    Port = $env:X64DBG_MCP_PORT
    Token = $env:X64DBG_MCP_TOKEN
    Server = $env:X64DBG_MCP_SERVER_PATH
}
$debuggerProcess = $null
try {
    Write-Verbose "Launching isolated debugger: $debugger"
    $env:X64DBG_MCP_PORT = [string]$port
    $env:X64DBG_MCP_TOKEN = $token
    $env:X64DBG_MCP_SERVER_PATH = $server
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
    Write-Verbose 'Sidecar is ready'

    $null = Invoke-Mcp 'initialize' @{
        protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'real-integration'; version = '1' }
    } 1
    $beforeLaunch = Invoke-Tool 'debugger.state' @{} 2
    if ($beforeLaunch.debuggee_state -ne 'absent') {
        throw "Isolated debugger did not start without a debuggee; actual=$($beforeLaunch.debuggee_state)"
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
    $launch = Invoke-Tool 'debuggee.launch' @{
        operation_id = [Guid]::NewGuid().ToString()
        path = $fixture
        working_directory = $backendRoot
    } 4
    $state = Invoke-Tool 'debugger.state' @{} 5
    if ($state.debuggee_state -ne 'paused') {
        throw "Fixture did not reach paused state; actual=$($state.debuggee_state)"
    }
    Write-Verbose 'Debuggee is paused'

    $registers = Invoke-Tool 'registers.read' @{} 3
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
    $asciiStrings = Invoke-Tool 'strings.search' @{
        module = $fixtureModule.name.ToUpperInvariant(); query = 'MCP_DISCOVERY_ASCII_SENTINEL'
        encoding = 'ascii_utf8'; min_length = 4; limit = 8
    } 62
    $wideStrings = Invoke-Tool 'strings.search' @{
        module = $fixtureModule.name.ToUpperInvariant(); query = 'MCP_DISCOVERY_UTF16_SENTINEL'
        encoding = 'utf16le'; min_length = 4; limit = 8
    } 63
    $references = Invoke-Tool 'references.to' @{ address = $moduleEntryRef; limit = 32 } 64
    if (@($asciiStrings.items | Where-Object { $_.text -eq 'MCP_DISCOVERY_ASCII_SENTINEL' }).Count -eq 0 -or
        @($wideStrings.items | Where-Object { $_.text -eq 'MCP_DISCOVERY_UTF16_SENTINEL' }).Count -eq 0) {
        throw 'Bounded string discovery did not find both fixture sentinels.'
    }
    foreach ($item in @($asciiStrings.items) + @($wideStrings.items)) {
        if ($null -eq $item.match_offset -or $null -eq $item.text_offset -or
            $item.match_offset -lt $item.text_offset) {
            throw 'A string result omitted valid match-context offsets.'
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
        architecture = $state.architecture
        launched_path = $launch.path
        process_id = $state.process_id
        registers = @($registers.registers.PSObject.Properties).Count
        memory_bytes = $memory.bytes_read
        instructions = $disassembly.items.Count
        modules = $modules.items.Count
        threads = $threads.items.Count
        memory_regions = $memoryMap.items.Count
        compact_snapshot_instructions = @($compactSnapshot.disassembly).Count
        filtered_executable_regions = @($filteredMap.items).Count
        snapshot_generations_present = $true
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
        ascii_strings = $asciiStrings.items.Count
        utf16_strings = $wideStrings.items.Count
        inbound_references = $references.items.Count
        discovery_cursor_filter_bound = $true
        stale_discovery_cursor_rejected = $true
        write_verified = $write.verified
        write_replay_equal = $true
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
    Write-Verbose 'Integration cleanup finished'
}
