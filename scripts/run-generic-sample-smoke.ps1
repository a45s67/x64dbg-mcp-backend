[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [Parameter(Mandatory)]
    [string]$IntegrationRoot,
    [Parameter(Mandatory)]
    [string]$SamplePath,
    [string]$ServerPath
)

$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$integration = [IO.Path]::GetFullPath($IntegrationRoot)
if (!$integration.StartsWith($workspace + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'IntegrationRoot must remain inside the repository workspace.'
}
$sample = (Resolve-Path -LiteralPath $SamplePath).Path
if ([string]::IsNullOrWhiteSpace($ServerPath)) {
    $ServerPath = Join-Path $workspace 'target\release\x64dbg-mcp-server.exe'
}
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$backendRoot = (Resolve-Path -LiteralPath (Join-Path $integration $Backend)).Path
$debuggerName = if ($Backend -eq 'x32') { 'x32dbg-unsigned.exe' } else { 'x64dbg.exe' }
$debugger = Join-Path $backendRoot $debuggerName

$bytes = [IO.File]::ReadAllBytes($sample)
if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw 'Sample is not a bounded PE file.'
}
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 0 -or $peOffset + 26 -gt $bytes.Length -or
    $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) {
    throw 'Sample has an invalid PE header.'
}
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
$expectedMachine = if ($Backend -eq 'x32') { 0x014c } else { 0x8664 }
if ($machine -ne $expectedMachine) {
    throw ('Sample machine 0x{0:x4} does not match {1}.' -f $machine, $Backend)
}
$backendProcessNames = if ($Backend -eq 'x32') {
    @('x32dbg', 'x32dbg-unsigned')
} else {
    @('x64dbg', 'x64dbg-unsigned')
}
$existingDebuggers = @(Get-Process -Name $backendProcessNames -ErrorAction SilentlyContinue)
if ($existingDebuggers.Count -gt 0) {
    $processList = ($existingDebuggers | ForEach-Object {
        '{0} (PID {1})' -f $_.ProcessName, $_.Id
    }) -join ', '
    throw ("A $Backend debugger instance is already running: $processList. " +
        'Close it before starting an isolated single-instance smoke test.')
}
$sampleLeaf = [IO.Path]::GetFileName($sample)
$stagedSample = Join-Path $backendRoot $sampleLeaf
Copy-Item -LiteralPath $sample -Destination $stagedSample -Force

$plugins = @(Get-ChildItem -LiteralPath (Join-Path $backendRoot 'plugins') -File)
$expectedExtension = if ($Backend -eq 'x32') { '.dp32' } else { '.dp64' }
if ($plugins.Count -ne 1 -or
    $plugins[0].Name -ine "x64dbg-mcp-backend$expectedExtension") {
    throw 'Isolation invariant failed: exactly this project plugin must be present.'
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$tokenBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tokenBytes)
$token = [Convert]::ToBase64String($tokenBytes)
$baseUri = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }
$script:requestId = 0
$script:instanceId = $null

function Invoke-Mcp([string]$Method, $Parameters) {
    $script:requestId++
    $body = @{ jsonrpc = '2.0'; id = $script:requestId; method = $Method; params = $Parameters } |
        ConvertTo-Json -Depth 14 -Compress
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$baseUri/mcp" `
        -Headers $headers -ContentType 'application/json; charset=utf-8' `
        -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 35
    if ($response.error) {
        throw "JSON-RPC error from $Method`: $($response.error | ConvertTo-Json -Compress)"
    }
    return $response.result
}

function Invoke-Tool([string]$Name, $Arguments) {
    if ($null -ne $Arguments.operation_id) {
        $Arguments.instance_id = $script:instanceId
    }
    $result = Invoke-Mcp 'tools/call' @{ name = $Name; arguments = $Arguments }
    if ($result.isError) {
        throw "Tool error from $Name`: $($result.structuredContent | ConvertTo-Json -Depth 10 -Compress)"
    }
    return $result.structuredContent
}

$previous = @{
    Port = $env:X64DBG_MCP_PORT
    Token = $env:X64DBG_MCP_TOKEN
    Server = $env:X64DBG_MCP_SERVER_PATH
}
$debuggerProcess = $null
$stopSubmitted = $false
$summary = $null
try {
    $env:X64DBG_MCP_PORT = [string]$port
    $env:X64DBG_MCP_TOKEN = $token
    $env:X64DBG_MCP_SERVER_PATH = $server
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $debugger
    $startInfo.WorkingDirectory = $backendRoot
    $startInfo.UseShellExecute = $false
    $debuggerProcess = [Diagnostics.Process]::Start($startInfo)

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch {
            $ready = $null
        }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $deadline -or
        $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready') {
        throw 'Isolated debugger MCP sidecar did not become ready.'
    }
    $script:instanceId = ([Guid]::Parse([string]$ready.instance_id)).ToString()
    $null = Invoke-Mcp 'initialize' @{
        protocolVersion = '2025-06-18'
        capabilities = @{}
        clientInfo = @{ name = 'generic-sample-smoke'; version = '1' }
    }
    $initial = Invoke-Tool 'debugger.state' @{}
    if ($initial.debuggee_state -ne 'absent' -or
        $initial.instance_id -ne $script:instanceId) {
        throw 'Fresh isolated backend state or identity is invalid.'
    }

    $launch = Invoke-Tool 'debuggee.launch' @{
        operation_id = [Guid]::NewGuid().ToString()
        path = $stagedSample
        working_directory = $backendRoot
        arguments = @()
    }
    $state = Invoke-Tool 'debugger.state' @{}
    $snapshot = Invoke-Tool 'debugger.snapshot' @{ disassembly_count = 8 }
    $modules = Invoke-Tool 'modules.list' @{ limit = 256 }
    $module = @($modules.items | Where-Object {
        $_.name -ieq $sampleLeaf
    } | Select-Object -First 1)
    if ($module.Count -ne 1) {
        throw 'Launched sample was not present in the bounded module list.'
    }
    $sections = Invoke-Tool 'sections.list' @{ module = $sampleLeaf; limit = 64 }
    $imports = Invoke-Tool 'imports.list' @{ module = $sampleLeaf; limit = 64 }
    $events = Invoke-Tool 'events.list' @{
        types = @('process_created', 'system_breakpoint', 'dll_loaded'); limit = 64
    }
    if ($state.debuggee_state -ne 'paused' -or
        $snapshot.state_generation -ne $state.state_generation -or
        @($sections.items).Count -lt 1 -or @($events.items).Count -lt 1) {
        throw 'Initial-pause sample observations were incomplete or generation-inconsistent.'
    }

    $stopSubmitted = $true
    $stop = Invoke-Tool 'debugger.stop' @{
        operation_id = [Guid]::NewGuid().ToString()
    }
    $summary = [ordered]@{
        backend = $Backend
        architecture = $state.architecture
        sample = $sampleLeaf
        sample_sha256 = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
        instance_id = $script:instanceId
        launch_state = $launch.debuggee_state
        pause_reason = $state.pause_reason.kind
        state_generation = $state.state_generation
        instruction_pointer = $state.instruction_pointer
        snapshot_instruction_count = @($snapshot.disassembly).Count
        module_base = $module[0].base
        section_count = @($sections.items).Count
        import_page_count = @($imports.items).Count
        startup_event_count = @($events.items).Count
        stopped = $stop.debuggee_state -eq 'absent'
    }
} finally {
    if ($debuggerProcess -and !$debuggerProcess.HasExited) {
        $null = $debuggerProcess.CloseMainWindow()
        if (!$debuggerProcess.WaitForExit(7000)) {
            Stop-Process -Id $debuggerProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $env:X64DBG_MCP_PORT = $previous.Port
    $env:X64DBG_MCP_TOKEN = $previous.Token
    $env:X64DBG_MCP_SERVER_PATH = $previous.Server
    $token = $null
    $headers = $null
    if (!$stopSubmitted) {
        Write-Verbose 'No mutation was retried; debugger ownership handled teardown.'
    }
}

if ($debuggerProcess -and !$debuggerProcess.HasExited) {
    throw 'Isolated debugger process remained active after teardown.'
}
$closeDeadline = [DateTime]::UtcNow.AddSeconds(5)
$listenerOpen = $false
do {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync('127.0.0.1', $port)
        $listenerOpen = $connect.Wait(250) -and $client.Connected
    } catch {
        $listenerOpen = $false
    } finally {
        $client.Dispose()
    }
    if ($listenerOpen) {
        Start-Sleep -Milliseconds 100
    }
} until (!$listenerOpen -or [DateTime]::UtcNow -ge $closeDeadline)
if ($listenerOpen) {
    throw 'MCP sidecar listener remained active after debugger teardown.'
}
if ($null -eq $summary) {
    throw 'Smoke test completed without a result summary.'
}
$summary | ConvertTo-Json -Depth 6
