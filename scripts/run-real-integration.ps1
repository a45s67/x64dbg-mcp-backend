[CmdletBinding()]
param(
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [string]$IntegrationRoot,
    [string]$ServerPath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($IntegrationRoot)) {
    $IntegrationRoot = Join-Path $PSScriptRoot '..\artifacts\integration'
}
if ([string]::IsNullOrWhiteSpace($ServerPath)) {
    $ServerPath = Join-Path $PSScriptRoot '..\target\debug\x64dbg-mcp-server.exe'
}
$backendRoot = (Resolve-Path -LiteralPath (Join-Path $IntegrationRoot $Backend)).Path
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$debuggerName = if ($Backend -eq 'x32') { 'x32dbg-unsigned.exe' } else { 'x64dbg.exe' }
$debugger = Join-Path $backendRoot $debuggerName
$fixture = Join-Path $backendRoot 'mcp-debuggee-fixture.exe'
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
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$baseUri/mcp" `
        -Headers $headers -ContentType 'application/json' -Body $request -TimeoutSec 15
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
    $modules = Invoke-Tool 'modules.list' @{ limit = 2 } 7
    $threads = Invoke-Tool 'threads.list' @{ limit = 2 } 8
    $memoryMap = Invoke-Tool 'memory.map' @{ limit = 2 } 9
    $breakpoints = Invoke-Tool 'breakpoints.list' @{ limit = 2 } 10

    $writeOperation = [Guid]::NewGuid().ToString()
    $write = Invoke-Tool 'memory.write' @{
        operation_id = $writeOperation; address = $expression.value; data_hex = $memory.data_hex.Substring(0, 2)
    } 11
    $writeReplay = Invoke-Tool 'memory.write' @{
        operation_id = $writeOperation; address = $expression.value; data_hex = $memory.data_hex.Substring(0, 2)
    } 12
    if (($write | ConvertTo-Json -Compress) -ne ($writeReplay | ConvertTo-Json -Compress)) {
        throw 'Mutation replay did not return the recorded memory.write result.'
    }
    $resume = $null
    $stableRunning = $false
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $beforeResume = Invoke-Tool 'debugger.state' @{} (13 + $attempt * 2)
        if ($beforeResume.debuggee_state -eq 'paused') {
            $resume = Invoke-Tool 'debugger.resume' @{
                operation_id = [Guid]::NewGuid().ToString()
            } (14 + $attempt * 2)
        }
        Start-Sleep -Milliseconds 250
        $afterResume = Invoke-Tool 'debugger.state' @{} (30 + $attempt)
        if ($afterResume.debuggee_state -eq 'running') {
            $stableRunning = $true
            break
        }
    }
    if (!$stableRunning) {
        throw 'Fixture never reached a stable running window after confirmed startup pauses.'
    }
    $pause = Invoke-Tool 'debugger.pause' @{ operation_id = [Guid]::NewGuid().ToString() } 40
    $stepInto = Invoke-Tool 'debugger.step_into' @{ operation_id = [Guid]::NewGuid().ToString() } 17
    $stepOver = Invoke-Tool 'debugger.step_over' @{ operation_id = [Guid]::NewGuid().ToString() } 18
    $breakpointAddress = $disassembly.items[1].address
    $breakpointSet = Invoke-Tool 'breakpoints.set' @{
        operation_id = [Guid]::NewGuid().ToString(); address = $breakpointAddress
    } 19
    $breakpointRemove = Invoke-Tool 'breakpoints.remove' @{
        operation_id = [Guid]::NewGuid().ToString(); address = $breakpointAddress
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
        breakpoints = $breakpoints.items.Count
        write_verified = $write.verified
        write_replay_equal = $true
        resume_state = $resume.debuggee_state
        step_into_state = $stepInto.debuggee_state
        step_over_state = $stepOver.debuggee_state
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
