[CmdletBinding()]
param(
    [string]$X64dbgRoot = 'C:\tools\x64dbg',
    [string]$SamplePath = 'C:\Users\fish\Downloads\Flare-On11_Challenges\checksum.exe',
    [string]$MainRva = '0xa78a0'
)

$ErrorActionPreference = 'Stop'
$releaseRoot = Join-Path (Resolve-Path -LiteralPath $X64dbgRoot).Path 'release'
$debugger = Join-Path $releaseRoot 'x64\x64dbg.exe'
$configPath = Join-Path $releaseRoot 'server\x64dbg-mcp-server-x64.toml'
$sample = (Resolve-Path -LiteralPath $SamplePath).Path
foreach ($required in @($debugger, $configPath, $sample)) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required file is missing: $required"
    }
}

$config = Get-Content -LiteralPath $configPath -Raw
$portMatch = [regex]::Match($config, '(?m)^port = ([0-9]+)$')
$tokenMatch = [regex]::Match($config, '(?m)^bearer_token = "([^"]+)"$')
if (!$portMatch.Success -or !$tokenMatch.Success) {
    throw 'Installed x64 configuration is missing port or bearer_token.'
}
$port = [int]$portMatch.Groups[1].Value
$token = $tokenMatch.Groups[1].Value
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
    $result = Invoke-Mcp 'tools/call' @{ name = $Name; arguments = $Arguments } $Id
    if ($result.isError) {
        throw "Tool error from $Name`: $($result.structuredContent | ConvertTo-Json -Compress -Depth 8)"
    }
    return $result.structuredContent
}

function Find-InstalledString([string]$Module, [string]$Query, [int]$IdBase) {
    $cursor = $null
    for ($page = 0; $page -lt 8; $page++) {
        $arguments = @{
            module = $Module; query = $Query; encoding = 'ascii_utf8'
            context_bytes = 32; min_length = 4; limit = 16
        }
        if ($cursor) { $arguments.cursor = $cursor }
        $result = Invoke-Tool 'strings.search' $arguments ($IdBase + $page)
        $match = @($result.items | Where-Object {
            $_.text.IndexOf($Query, [StringComparison]::OrdinalIgnoreCase) -ge 0
        } | Select-Object -First 1)
        if ($match.Count -eq 1) {
            return [pscustomobject]@{ Item = $match[0]; Page = $page + 1; Result = $result }
        }
        $cursor = $result.next_cursor
        if (!$cursor) { break }
    }
    throw "Installed strings.search did not find '$Query' within eight bounded pages."
}

$debuggerProcess = $null
$stopSubmitted = $false
try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $debugger
    $startInfo.WorkingDirectory = Split-Path -Parent $debugger
    $startInfo.UseShellExecute = $false
    $debuggerProcess = [System.Diagnostics.Process]::Start($startInfo)

    $ready = $null
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch {
            $ready = $null
        }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $readyDeadline -or
        $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready') {
        throw 'Installed x64 backend did not become ready.'
    }
    if ($ready.debugger_state -ne 'absent' -or $ready.diagnostic_code -ne 'NO_DEBUGGEE' -or
        @($ready.next_actions).Count -ne 2 -or
        $ready.next_actions[0].tool -ne 'debuggee.launch' -or
        $ready.next_actions[1].tool -ne 'debuggee.attach') {
        throw 'Installed readiness did not advertise explicit launch and attach actions.'
    }

    $null = Invoke-Mcp 'initialize' @{
        protocolVersion = '2025-06-18'
        capabilities = @{}
        clientInfo = @{ name = 'flare-checksum-smoke'; version = '1' }
    } 1
    $initial = Invoke-Tool 'debugger.state' @{} 2
    if ($initial.debuggee_state -ne 'absent') {
        throw 'Installed debugger did not start without a debuggee.'
    }
    if ($initial.diagnostic_code -ne 'NO_DEBUGGEE' -or
        @($initial.next_actions).Count -ne 2 -or
        $initial.next_actions[0].tool -ne 'debuggee.launch' -or
        $initial.next_actions[1].tool -ne 'debuggee.attach') {
        throw 'Installed debugger.state did not advertise launch and attach actions.'
    }
    $launch = Invoke-Tool 'debuggee.launch' @{
        operation_id = [Guid]::NewGuid().ToString()
        path = $sample
        working_directory = Split-Path -Parent $sample
    } 3
    $moduleRef = @{
        module = [System.IO.Path]::GetFileName($sample).ToUpperInvariant()
        rva = $MainRva
    }
    $resolved = Invoke-Tool 'address.resolve' @{ address = $moduleRef } 4
    $breakpoint = Invoke-Tool 'breakpoints.set' @{
        operation_id = [Guid]::NewGuid().ToString()
        address = $moduleRef
    } 5
    if (!$breakpoint.present) {
        throw 'The module-relative main breakpoint was not confirmed.'
    }

    $mainPause = $null
    for ($attempt = 0; $attempt -lt 8 -and !$mainPause; $attempt++) {
        $resume = Invoke-Tool 'debugger.resume' @{
            operation_id = [Guid]::NewGuid().ToString()
        } (10 + $attempt * 2)
        $wait = Invoke-Mcp 'tools/call' @{
            name = 'debugger.wait_for_pause'
            arguments = @{ after_generation = $resume.state_generation; timeout_ms = 8000 }
        } (11 + $attempt * 2)
        if ($wait.isError) {
            throw "Pause observation failed: $($wait.structuredContent | ConvertTo-Json -Compress -Depth 8)"
        }
        $observed = $wait.structuredContent
        if ($observed.pause_reason.kind -eq 'breakpoint' -and
            $observed.pause_reason.address -eq $resolved.address) {
            $mainPause = $observed
        }
    }
    if (!$mainPause) {
        throw 'checksum.exe did not reach the module-relative main breakpoint.'
    }
    if ($mainPause.instruction_pointer -ne $resolved.address -or
        !$mainPause.active_thread_id -or
        !$mainPause.pause_reason.breakpoint_type -or
        $null -eq $mainPause.pause_reason.hit_count -or
        $mainPause.state_generation -le $launch.state_generation) {
        throw 'Main pause snapshot is missing generation-consistent breakpoint metadata.'
    }
    $registerSnapshot = Invoke-Tool 'registers.read' @{ names = @('rip', 'rsp') } 36
    $memorySnapshot = Invoke-Tool 'memory.read' @{ address = $moduleRef; length = 16 } 37
    $disassemblySnapshot = Invoke-Tool 'disassembly.read' @{ address = $moduleRef; count = 4 } 38
    $compactSnapshot = Invoke-Tool 'debugger.snapshot' @{} 39
    $filteredMap = Invoke-Tool 'memory.map' @{
        module = [System.IO.Path]::GetFileName($sample).ToUpperInvariant()
        committed_only = $true; executable_only = $true; compact = $true; limit = 32
    } 41
    if ($registerSnapshot.state_generation -ne $mainPause.state_generation -or
        $memorySnapshot.state_generation -ne $mainPause.state_generation -or
        $disassemblySnapshot.state_generation -ne $mainPause.state_generation -or
        $compactSnapshot.state_generation -ne $mainPause.state_generation -or
        $compactSnapshot.instruction_pointer.address -ne $resolved.address -or
        @($compactSnapshot.registers.PSObject.Properties).Count -ne 4 -or
        @($compactSnapshot.disassembly).Count -ne 8 -or
        @($filteredMap.items).Count -eq 0 -or
        $filteredMap.state_generation -ne $mainPause.state_generation -or
        $memorySnapshot.location.state_generation -ne $memorySnapshot.state_generation -or
        $disassemblySnapshot.location.state_generation -ne $disassemblySnapshot.state_generation) {
        throw 'Installed read tools did not preserve the stable main-pause generation.'
    }

    $moduleName = [System.IO.Path]::GetFileName($sample).ToUpperInvariant()
    $mainSymbols = Invoke-Tool 'symbols.search' @{
        module = $moduleName; query = 'main.main'; limit = 32
    } 50
    $mainFunctions = Invoke-Tool 'functions.list' @{
        module = $moduleName; query = 'main.main'; limit = 32
    } 51
    $analysisOperation = [Guid]::NewGuid().ToString()
    $mainAnalysis = Invoke-Tool 'analysis.function' @{
        operation_id = $analysisOperation; address = $moduleRef
    } 53
    $mainAnalysisReplay = Invoke-Tool 'analysis.function' @{
        operation_id = $analysisOperation; address = $moduleRef
    } 54
    if (($mainAnalysisReplay | ConvertTo-Json -Compress -Depth 12) -ne
        ($mainAnalysis | ConvertTo-Json -Compress -Depth 12) -or
        $mainAnalysis.state_generation -ne $mainPause.state_generation -or
        $mainAnalysis.requested_location.address -ne $resolved.address) {
        throw 'Installed explicit analysis was not generation-consistent or replay-safe.'
    }
    $mainAnalysisFound = $false
    $analysisCursor = $null
    for ($analysisPage = 0; $analysisPage -lt 8; $analysisPage++) {
        $analysisArguments = @{ module = $moduleName; limit = 256 }
        if ($analysisCursor) { $analysisArguments.cursor = $analysisCursor }
        $analysisFunctions = Invoke-Tool 'functions.list' $analysisArguments (80 + $analysisPage)
        if (@($analysisFunctions.items | Where-Object {
            $_.start.address -eq $mainAnalysis.function.start.address
        }).Count -ne 0) {
            $mainAnalysisFound = $true
            break
        }
        $analysisCursor = $analysisFunctions.next_cursor
        if (!$analysisCursor) { break }
    }
    if (!$mainAnalysisFound) {
        throw 'Installed explicit analysis marker was not visible through functions.list.'
    }
    $mainReferences = Invoke-Tool 'references.to' @{ address = $moduleRef; limit = 32 } 52
    $keyString = Find-InstalledString $moduleName 'FlareOn2024' 60
    $promptString = Find-InstalledString $moduleName 'Check sum: %d + %d = ' 70
    foreach ($discovery in @($mainSymbols, $mainFunctions, $mainReferences,
            $keyString.Result, $promptString.Result)) {
        if ($discovery.completeness -ne 'known_only' -or
            $discovery.state_generation -ne $mainPause.state_generation) {
            throw 'Installed discovery result omitted stable known-only metadata.'
        }
    }
    foreach ($found in @($keyString, $promptString)) {
        if ($null -eq $found.Item.match_offset -or $null -eq $found.Item.text_offset -or
            $found.Item.match_offset -lt $found.Item.text_offset -or
            $found.Item.before.Length -gt 32 -or $found.Item.after.Length -gt 32 -or
            $found.Item.text -ne ($found.Item.before + $found.Item.match + $found.Item.after)) {
            throw 'Installed string discovery omitted valid match-context offsets.'
        }
    }

    # Qualify a real installed mutation without changing checksum.exe semantics:
    # use a non-control register and restore it before the session is stopped.
    $writableRegister = 'rdi'
    $registerBeforeWrite = Invoke-Tool 'registers.read' @{ names = @($writableRegister) } 90
    $originalRegisterValue = $registerBeforeWrite.registers.$writableRegister
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
    $registerWrite = Invoke-Tool 'registers.write' $registerWriteArguments 91
    $registerWriteReplay = Invoke-Tool 'registers.write' $registerWriteArguments 92
    $registerAfterWrite = Invoke-Tool 'registers.read' @{ names = @($writableRegister) } 93
    if (!$registerWrite.changed -or
        $registerWrite.previous_value -ne $originalRegisterValue -or
        $registerWrite.value -ne $testRegisterValue -or
        $registerAfterWrite.registers.$writableRegister -ne $testRegisterValue -or
        ($registerWrite | ConvertTo-Json -Compress -Depth 8) -ne
        ($registerWriteReplay | ConvertTo-Json -Compress -Depth 8)) {
        throw 'Installed typed register write was not verified, observable, or replay-safe.'
    }
    $registerRestore = Invoke-Tool 'registers.write' @{
        operation_id = [Guid]::NewGuid().ToString()
        name = $writableRegister
        value = $originalRegisterValue
    } 94
    $registerAfterRestore = Invoke-Tool 'registers.read' @{ names = @($writableRegister) } 95
    if ($registerRestore.value -ne $originalRegisterValue -or
        $registerAfterRestore.registers.$writableRegister -ne $originalRegisterValue) {
        throw 'Installed typed register write did not restore the Flare sample context.'
    }

    $hardwareInstruction = @($disassemblySnapshot.items)[1]
    $memoryInstruction = @($disassemblySnapshot.items)[2]
    if (!$hardwareInstruction -or !$memoryInstruction -or
        $hardwareInstruction.size -lt 1 -or $memoryInstruction.size -lt 1) {
        throw 'Main disassembly has no deterministic instructions for typed breakpoint qualification.'
    }
    $hardwareArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $hardwareInstruction.address }
        access = 'execute'; size = 1
    }
    $hardwareSet = Invoke-Tool 'breakpoints.hardware.set' $hardwareArguments 100
    $hardwareSetReplay = Invoke-Tool 'breakpoints.hardware.set' $hardwareArguments 101
    $hardwareResume = Invoke-Tool 'debugger.resume' @{
        operation_id = [Guid]::NewGuid().ToString()
    } 102
    $hardwarePause = Invoke-Tool 'debugger.wait_for_pause' @{
        after_generation = $hardwareResume.state_generation; timeout_ms = 9000
    } 103
    if (!$hardwareSet.present -or
        ($hardwareSet | ConvertTo-Json -Compress -Depth 10) -ne
        ($hardwareSetReplay | ConvertTo-Json -Compress -Depth 10) -or
        $hardwarePause.pause_reason.kind -ne 'breakpoint' -or
        $hardwarePause.pause_reason.breakpoint_type -ne 'hardware' -or
        $hardwarePause.instruction_pointer -ne $hardwareInstruction.address) {
        throw 'Installed hardware breakpoint was not replay-safe or did not hit the next instruction.'
    }
    $hardwareRemoveArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $hardwareInstruction.address }
        access = 'execute'; size = 1
    }
    $hardwareRemove = Invoke-Tool 'breakpoints.hardware.remove' $hardwareRemoveArguments 104
    $hardwareRemoveReplay = Invoke-Tool 'breakpoints.hardware.remove' $hardwareRemoveArguments 105
    if ($hardwareRemove.present -or
        ($hardwareRemove | ConvertTo-Json -Compress -Depth 10) -ne
        ($hardwareRemoveReplay | ConvertTo-Json -Compress -Depth 10)) {
        throw 'Installed hardware breakpoint removal was not replay-safe.'
    }

    $memoryArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $memoryInstruction.address }
        access = 'execute'; size = $memoryInstruction.size
    }
    $memorySet = Invoke-Tool 'breakpoints.memory.set' $memoryArguments 106
    $memorySetReplay = Invoke-Tool 'breakpoints.memory.set' $memoryArguments 107
    $memoryResume = Invoke-Tool 'debugger.resume' @{
        operation_id = [Guid]::NewGuid().ToString()
    } 108
    $memoryPause = Invoke-Tool 'debugger.wait_for_pause' @{
        after_generation = $memoryResume.state_generation; timeout_ms = 9000
    } 109
    if (!$memorySet.present -or
        ($memorySet | ConvertTo-Json -Compress -Depth 10) -ne
        ($memorySetReplay | ConvertTo-Json -Compress -Depth 10) -or
        $memoryPause.pause_reason.kind -ne 'breakpoint' -or
        $memoryPause.pause_reason.breakpoint_type -ne 'memory' -or
        $memoryPause.instruction_pointer -ne $memoryInstruction.address) {
        throw 'Installed memory breakpoint was not replay-safe or did not hit the following instruction.'
    }
    $memoryRemoveArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $memoryInstruction.address }
        access = 'execute'; size = $memoryInstruction.size
    }
    $memoryRemove = Invoke-Tool 'breakpoints.memory.remove' $memoryRemoveArguments 110
    $memoryRemoveReplay = Invoke-Tool 'breakpoints.memory.remove' $memoryRemoveArguments 111
    if ($memoryRemove.present -or
        ($memoryRemove | ConvertTo-Json -Compress -Depth 10) -ne
        ($memoryRemoveReplay | ConvertTo-Json -Compress -Depth 10)) {
        throw 'Installed memory breakpoint removal was not replay-safe.'
    }

    $stopSubmitted = $true
    $stop = Invoke-Tool 'debugger.stop' @{ operation_id = [Guid]::NewGuid().ToString() } 40
    [ordered]@{
        sample = [System.IO.Path]::GetFileName($sample)
        module_reference = $moduleRef
        resolved_address = $resolved.address
        resolved_module_base = $resolved.module_base
        pause_reason = $mainPause.pause_reason.kind
        breakpoint_type = $mainPause.pause_reason.breakpoint_type
        hit_count = $mainPause.pause_reason.hit_count
        instruction_pointer = $mainPause.instruction_pointer
        active_thread_id = $mainPause.active_thread_id
        state_generation = $mainPause.state_generation
        bootstrap_launch_action_advertised = $true
        registers_generation = $registerSnapshot.state_generation
        memory_generation = $memorySnapshot.state_generation
        disassembly_generation = $disassemblySnapshot.state_generation
        snapshot_generations_equal = $true
        compact_snapshot_instructions = @($compactSnapshot.disassembly).Count
        filtered_executable_regions = @($filteredMap.items).Count
        main_symbols = @($mainSymbols.items).Count
        main_functions = @($mainFunctions.items).Count
        analysis_function_start = $mainAnalysis.function.start.address
        analysis_function_end = $mainAnalysis.function.end.address
        analysis_already_known = $mainAnalysis.already_known
        analysis_generation_unchanged = $true
        analysis_replay_equal = $true
        analysis_visible_in_discovery = $mainAnalysisFound
        inbound_main_references = @($mainReferences.items).Count
        key_string = $keyString.Item.text
        key_string_match = $keyString.Item.match
        key_string_preview_bytes = [Text.Encoding]::UTF8.GetByteCount($keyString.Item.text)
        key_string_page = $keyString.Page
        prompt_string = $promptString.Item.text
        prompt_string_match = $promptString.Item.match
        prompt_string_preview_bytes = [Text.Encoding]::UTF8.GetByteCount($promptString.Item.text)
        prompt_string_page = $promptString.Page
        string_context_bytes = 32
        register_write_name = $writableRegister
        register_write_value = $registerWrite.value
        register_write_replay_equal = $true
        register_restore_value = $registerAfterRestore.registers.$writableRegister
        hardware_breakpoint_address = $hardwarePause.instruction_pointer
        hardware_breakpoint_replay_equal = $true
        memory_breakpoint_address = $memoryPause.instruction_pointer
        memory_breakpoint_size = $memorySet.size
        memory_breakpoint_replay_equal = $true
        stopped = $stop.debuggee_state -eq 'absent'
    } | ConvertTo-Json -Depth 5
} finally {
    if ($debuggerProcess -and !$debuggerProcess.HasExited) {
        $null = $debuggerProcess.CloseMainWindow()
        if (!$debuggerProcess.WaitForExit(7000)) {
            Stop-Process -Id $debuggerProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    if (!$stopSubmitted) {
        Write-Verbose 'No cleanup mutation was retried; closing the debugger owns debuggee teardown.'
    }
    $token = $null
    $headers = $null
}
