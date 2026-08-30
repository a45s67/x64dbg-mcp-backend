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
    $script:InstanceId = ([Guid]::Parse([string]$ready.instance_id)).ToString()
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
    if ($initial.instance_id -ne $script:InstanceId) {
        throw 'Readiness and debugger.state reported different backend instances.'
    }
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
    $explicitThreadRegisters = Invoke-Tool 'registers.read' @{
        names = @('rip', 'rsp'); thread_id = $mainPause.active_thread_id
    } 137
    $callstackSnapshot = Invoke-Tool 'callstack.read' @{
        thread_id = $mainPause.active_thread_id; limit = 32
    } 35
    $memorySnapshot = Invoke-Tool 'memory.read' @{ address = $moduleRef; length = 16 } 37
    $disassemblySnapshot = Invoke-Tool 'disassembly.read' @{ address = $moduleRef; count = 4 } 38
    $compactSnapshot = Invoke-Tool 'debugger.snapshot' @{} 39
    $explicitThreadSnapshot = Invoke-Tool 'debugger.snapshot' @{
        registers = @('rip', 'rsp'); disassembly_count = 2
        thread_id = $mainPause.active_thread_id
    } 138
    $filteredMap = Invoke-Tool 'memory.map' @{
        module = [System.IO.Path]::GetFileName($sample).ToUpperInvariant()
        committed_only = $true; executable_only = $true; compact = $true; limit = 32
    } 41
    if ($registerSnapshot.state_generation -ne $mainPause.state_generation -or
        $memorySnapshot.state_generation -ne $mainPause.state_generation -or
        $disassemblySnapshot.state_generation -ne $mainPause.state_generation -or
        $compactSnapshot.state_generation -ne $mainPause.state_generation -or
        $explicitThreadRegisters.state_generation -ne $mainPause.state_generation -or
        $explicitThreadSnapshot.state_generation -ne $mainPause.state_generation -or
        !$explicitThreadRegisters.current -or !$explicitThreadSnapshot.current -or
        $explicitThreadRegisters.thread_id -ne $mainPause.active_thread_id -or
        $explicitThreadSnapshot.thread_id -ne $mainPause.active_thread_id -or
        $explicitThreadSnapshot.active_thread_id -ne $mainPause.active_thread_id -or
        $explicitThreadRegisters.registers.rip -ne $resolved.address -or
        $explicitThreadSnapshot.instruction_pointer.address -ne $resolved.address -or
        @($explicitThreadSnapshot.disassembly).Count -ne 2 -or
        $compactSnapshot.instruction_pointer.address -ne $resolved.address -or
        @($compactSnapshot.registers.PSObject.Properties).Count -ne 4 -or
        @($compactSnapshot.disassembly).Count -ne 8 -or
        @($filteredMap.items).Count -eq 0 -or
        $filteredMap.state_generation -ne $mainPause.state_generation -or
        $memorySnapshot.location.state_generation -ne $memorySnapshot.state_generation -or
        $disassemblySnapshot.location.state_generation -ne $disassemblySnapshot.state_generation) {
        throw 'Installed read tools did not preserve the stable main-pause generation.'
    }
    if ($callstackSnapshot.thread_id -ne $mainPause.active_thread_id -or
        @($callstackSnapshot.frames).Count -gt 32 -or
        $callstackSnapshot.completeness -notin @('native_bounded', 'inconclusive') -or
        $callstackSnapshot.state_generation -ne $mainPause.state_generation) {
        throw 'Installed native call-stack read was not bounded and generation-consistent.'
    }

    # Qualify managed breakpoint metadata without resuming challenge logic.
    $managedBreakpointInstruction = @($disassemblySnapshot.items)[1]
    if (!$managedBreakpointInstruction -or $managedBreakpointInstruction.size -lt 1 -or
        $managedBreakpointInstruction.size -gt 16) {
        throw 'Main disassembly has no bounded instruction for managed breakpoint qualification.'
    }
    $managedBreakpointTarget = @{ absolute = $managedBreakpointInstruction.address }
    $conditionalArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = $managedBreakpointTarget
        condition = @{
            mode = 'all'
            predicates = @(@{ source = 'hit_count'; operator = 'eq'; value = 1 })
        }
    }
    $conditionalSet = Invoke-Tool 'breakpoints.conditional.set' $conditionalArguments 130
    $conditionalReplay = Invoke-Tool 'breakpoints.conditional.set' $conditionalArguments 131
    $conditionalList = Invoke-Tool 'breakpoints.list' @{ limit = 256 } 132
    $listedConditional = @($conditionalList.items | Where-Object {
        $_.address -eq $managedBreakpointTarget.absolute -and $_.type -eq 'software'
    })[0]
    if (!$conditionalSet.present -or !$conditionalSet.fast_resume -or
        !$listedConditional -or $listedConditional.managed_id -ne $conditionalSet.managed_id -or
        ($conditionalSet | ConvertTo-Json -Compress -Depth 12) -ne
        ($conditionalReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Installed conditional breakpoint was not listed or replay-safe.'
    }
    $conditionalRemoveArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = $managedBreakpointTarget; managed_id = $conditionalSet.managed_id
    }
    $conditionalRemove = Invoke-Tool 'breakpoints.conditional.remove' $conditionalRemoveArguments 133
    $conditionalRemoveReplay = Invoke-Tool 'breakpoints.conditional.remove' $conditionalRemoveArguments 134
    if ($conditionalRemove.present -or
        ($conditionalRemove | ConvertTo-Json -Compress -Depth 12) -ne
        ($conditionalRemoveReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Installed conditional breakpoint removal was not replay-safe.'
    }

    $exceptionArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        code = '0xe0424343'; chance = 'first'
    }
    $exceptionSet = Invoke-Tool 'breakpoints.exception.set' $exceptionArguments 135
    $exceptionReplay = Invoke-Tool 'breakpoints.exception.set' $exceptionArguments 136
    $exceptionList = Invoke-Tool 'breakpoints.list' @{ limit = 256 } 137
    $listedException = @($exceptionList.items | Where-Object {
        $_.type -eq 'exception' -and $_.code -eq '0xe0424343'
    })[0]
    if (!$exceptionSet.present -or $exceptionSet.chance -ne 'first' -or
        !$listedException -or $listedException.managed_id -ne $exceptionSet.managed_id -or
        ($exceptionSet | ConvertTo-Json -Compress -Depth 12) -ne
        ($exceptionReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Installed exception breakpoint was not listed or replay-safe.'
    }
    $exceptionRemoveArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        code = '0xe0424343'; chance = 'first'; managed_id = $exceptionSet.managed_id
    }
    $exceptionRemove = Invoke-Tool 'breakpoints.exception.remove' $exceptionRemoveArguments 138
    $exceptionRemoveReplay = Invoke-Tool 'breakpoints.exception.remove' $exceptionRemoveArguments 139
    if ($exceptionRemove.present -or
        ($exceptionRemove | ConvertTo-Json -Compress -Depth 12) -ne
        ($exceptionRemoveReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Installed exception breakpoint removal was not replay-safe.'
    }

    # Patch the next instruction, verify x64dbg tracking, and restore it before execution.
    $patchInstructionTarget = @($disassemblySnapshot.items)[1]
    if (!$patchInstructionTarget -or $patchInstructionTarget.size -lt 1 -or
        $patchInstructionTarget.size -gt 16) {
        throw 'Main disassembly has no bounded non-current instruction for patch qualification.'
    }
    $patchAddress = @{ absolute = $patchInstructionTarget.address }
    $patchMemory = Invoke-Tool 'memory.read' @{
        address = $patchAddress; length = $patchInstructionTarget.size
    } 120
    $int3Padded = 'cc' + ('90' * ($patchInstructionTarget.size - 1))
    $patchMnemonic = if ($patchMemory.data_hex -eq $int3Padded) { 'nop' } else { 'int3' }
    $patchPreview = Invoke-Tool 'assembly.preview' @{
        address = $patchAddress; instruction = $patchMnemonic
    } 121
    $patchArguments = @{
        operation_id = [Guid]::NewGuid().ToString(); address = $patchAddress
        instruction = $patchMnemonic; expected_bytes_hex = $patchMemory.data_hex
        fill_nop = $true
    }
    $trackedPatch = Invoke-Tool 'assembly.patch' $patchArguments 122
    $trackedPatchReplay = Invoke-Tool 'assembly.patch' $patchArguments 123
    if (!$trackedPatch.patch_tracked -or $patchPreview.byte_count -ne 1 -or
        ($trackedPatch | ConvertTo-Json -Compress -Depth 12) -ne
        ($trackedPatchReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Installed tracked patch was not previewed, verified, or replay-safe.'
    }
    $installedPatchList = Invoke-Tool 'patches.list' @{
        module = [System.IO.Path]::GetFileName($sample); limit = 32
    } 127
    $installedPatch = @($installedPatchList.items | Where-Object {
        $_.start.address -eq $trackedPatch.address
    })[0]
    if (!$installedPatch -or !$installedPatch.current_matches_patch -or
        $installedPatch.patched_bytes_hex -ne $trackedPatch.patched_bytes_hex -or
        $installedPatchList.completeness -ne 'tracked_only') {
        throw 'Installed patch listing did not verify checksum.exe tracked bytes.'
    }
    $restoreArguments = @{
        operation_id = [Guid]::NewGuid().ToString(); address = $patchAddress
        expected_patched_bytes_hex = $trackedPatch.patched_bytes_hex
        expected_original_bytes_hex = $patchMemory.data_hex
    }
    $patchRestore = Invoke-Tool 'patches.restore' $restoreArguments 124
    $patchRestoreReplay = Invoke-Tool 'patches.restore' $restoreArguments 125
    $patchMemoryAfterRestore = Invoke-Tool 'memory.read' @{
        address = $patchAddress; length = $patchInstructionTarget.size
    } 126
    if ($patchRestore.patch_tracked -or
        $patchMemoryAfterRestore.data_hex -ne $patchMemory.data_hex -or
        ($patchRestore | ConvertTo-Json -Compress -Depth 12) -ne
        ($patchRestoreReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Installed patch restore did not exactly recover checksum.exe bytes.'
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
    $mainFunctionAt = Invoke-Tool 'functions.at' @{ address = $moduleRef } 55
    if (!$mainFunctionAt.found -or !$mainFunctionAt.function.contains_query -or
        $mainFunctionAt.function.start.address -ne $mainAnalysis.function.start.address -or
        $mainFunctionAt.function.end_inclusive.address -ne $mainAnalysis.function.end.address) {
        throw 'Installed known-function lookup disagreed with explicit checksum.exe analysis.'
    }
    $exactSymbolName = if (@($mainSymbols.items).Count -gt 0) {
        $mainSymbols.items[0].name
    } else {
        'main.main'
    }
    $mainSymbolExact = Invoke-Tool 'symbols.resolve' @{
        module = $moduleName; name = $exactSymbolName
    } 56
    if ($mainSymbolExact.resolution -notin @('found', 'missing', 'ambiguous') -or
        $mainSymbolExact.completeness -ne 'known_only' -or
        ($mainSymbols.items.Count -gt 0 -and $mainSymbolExact.resolution -eq 'missing')) {
        throw 'Installed exact symbol resolution did not preserve explicit known-only semantics.'
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
    $runToInstruction = @($disassemblySnapshot.items)[3]
    if (!$hardwareInstruction -or !$memoryInstruction -or !$runToInstruction -or
        $hardwareInstruction.size -lt 1 -or $memoryInstruction.size -lt 1 -or
        $runToInstruction.size -lt 1) {
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

    $runToArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        address = @{ absolute = $runToInstruction.address }
        timeout_ms = 2000
    }
    $runTo = Invoke-Tool 'debugger.run_to_address' $runToArguments 112
    $runToReplay = Invoke-Tool 'debugger.run_to_address' $runToArguments 113
    $runToShapeValid = $runTo.resumed -and
        $runTo.temporary_breakpoint_cleaned -and
        $runTo.debuggee_state -eq 'paused' -and
        (($runTo.completed -and $null -eq $runTo.interruption -and
            $runTo.instruction_pointer -eq $runToInstruction.address) -or
         (!$runTo.completed -and $runTo.interruption -in @(
            'breakpoint', 'exception', 'step', 'user_pause', 'timeout', 'unknown')))
    if (!$runToShapeValid -or
        ($runTo | ConvertTo-Json -Compress -Depth 12) -ne
        ($runToReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw "Installed owned run-to did not return a cleaned replay-safe result: $($runTo | ConvertTo-Json -Compress -Depth 12)"
    }

    # A short installed address trace changes only execution position. It
    # verifies the packaged callback path and immutable result transport without
    # enabling whole-program tracing or retaining registers/memory.
    $traceBefore = Invoke-Tool 'debugger.state' @{} 130
    $traceArguments = @{
        operation_id = [Guid]::NewGuid().ToString()
        mode = 'over'; max_steps = 8; timeout_ms = 3000
    }
    $traceStart = Invoke-Tool 'trace.start' $traceArguments 131
    $traceReplay = Invoke-Tool 'trace.start' $traceArguments 132
    if (($traceStart | ConvertTo-Json -Compress -Depth 12) -ne
        ($traceReplay | ConvertTo-Json -Compress -Depth 12)) {
        throw 'Installed bounded trace start was not exactly replay-safe.'
    }
    if ($traceStart.state -in @('starting', 'running')) {
        $null = Invoke-Tool 'debugger.wait_for_pause' @{
            after_generation = $traceBefore.state_generation; timeout_ms = 5000
        } 133
    }
    $traceStatus = Invoke-Tool 'trace.status' @{ trace_id = $traceStart.trace_id } 134
    $traceResults = Invoke-Tool 'trace.results' @{
        trace_id = $traceStart.trace_id; limit = 16
    } 135
    if ($traceStatus.state -ne 'completed' -or $traceStatus.reason -ne 'max_steps' -or
        $traceStatus.steps_executed -ne 8 -or $traceStatus.points_retained -ne 9 -or
        @($traceResults.items).Count -ne 9 -or $traceResults.next_cursor) {
        throw "Installed bounded trace was incomplete: $($traceStatus | ConvertTo-Json -Compress)"
    }

    $stopSubmitted = $true
    $stop = Invoke-Tool 'debugger.stop' @{ operation_id = [Guid]::NewGuid().ToString() } 40
    [ordered]@{
        sample = [System.IO.Path]::GetFileName($sample)
        instance_id = $script:InstanceId
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
        explicit_thread_context_read = $explicitThreadRegisters.thread_id
        explicit_thread_snapshot_instructions = @($explicitThreadSnapshot.disassembly).Count
        filtered_executable_regions = @($filteredMap.items).Count
        main_symbols = @($mainSymbols.items).Count
        main_functions = @($mainFunctions.items).Count
        callstack_frames = @($callstackSnapshot.frames).Count
        callstack_completeness = $callstackSnapshot.completeness
        tracked_patch_list_verified = $true
        known_function_lookup = $true
        exact_symbol_resolution = $mainSymbolExact.resolution
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
        patch_address = $patchInstructionTarget.address
        patch_instruction = $patchMnemonic
        patch_span_length = $trackedPatch.span_length
        patch_replay_equal = $true
        patch_restore_replay_equal = $true
        patch_restored_bytes_equal = $true
        hardware_breakpoint_address = $hardwarePause.instruction_pointer
        hardware_breakpoint_replay_equal = $true
        memory_breakpoint_address = $memoryPause.instruction_pointer
        memory_breakpoint_size = $memorySet.size
        memory_breakpoint_replay_equal = $true
        conditional_breakpoint_managed = $conditionalSet.managed_id
        conditional_breakpoint_replay_equal = $true
        conditional_breakpoint_removed = !$conditionalRemove.present
        exception_breakpoint_managed = $exceptionSet.managed_id
        exception_breakpoint_replay_equal = $true
        exception_breakpoint_removed = !$exceptionRemove.present
        run_to_target = $runToInstruction.address
        run_to_completed = $runTo.completed
        run_to_interruption = $runTo.interruption
        run_to_final_address = $runTo.instruction_pointer
        run_to_replay_equal = $true
        run_to_temporary_breakpoint_cleaned = $true
        trace_id = $traceStart.trace_id
        trace_steps = $traceStatus.steps_executed
        trace_points = @($traceResults.items).Count
        trace_replay_equal = $true
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
