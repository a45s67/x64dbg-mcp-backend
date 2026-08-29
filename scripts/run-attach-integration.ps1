[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x32', 'x64')]
    [string]$Backend,
    [Parameter(Mandatory)]
    [string]$IntegrationRoot,
    [string]$ServerPath = (Join-Path $PSScriptRoot '..\target\debug\x64dbg-mcp-server.exe'),
    [string]$FixtureName = 'mcp-debuggee-fixture.exe'
)

$ErrorActionPreference = 'Stop'
$backendRoot = (Resolve-Path -LiteralPath (Join-Path $IntegrationRoot $Backend)).Path
$server = (Resolve-Path -LiteralPath $ServerPath).Path
$fixture = (Resolve-Path -LiteralPath (Join-Path $backendRoot $FixtureName)).Path
$debuggerName = if ($Backend -eq 'x32') { 'x32dbg-unsigned.exe' } else { 'x64dbg.exe' }
$debugger = (Resolve-Path -LiteralPath (Join-Path $backendRoot $debuggerName)).Path
$plugins = @(Get-ChildItem -LiteralPath (Join-Path $backendRoot 'plugins') -File)
$extension = if ($Backend -eq 'x32') { '.dp32' } else { '.dp64' }
if ($plugins.Count -ne 1 -or $plugins[0].Name -ine "x64dbg-mcp-backend$extension") {
    throw 'Attach isolation requires exactly this project plugin.'
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$tokenBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($tokenBytes) } finally { $random.Dispose() }
$token = [Convert]::ToBase64String($tokenBytes)
$baseUri = "http://127.0.0.1:$port"
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }
$previous = @{
    Port = [Environment]::GetEnvironmentVariable('X64DBG_MCP_PORT', 'Process')
    Token = [Environment]::GetEnvironmentVariable('X64DBG_MCP_TOKEN', 'Process')
    Server = [Environment]::GetEnvironmentVariable('X64DBG_MCP_SERVER_PATH', 'Process')
}
$env:X64DBG_MCP_PORT = $port.ToString()
$env:X64DBG_MCP_TOKEN = $token
$env:X64DBG_MCP_SERVER_PATH = $server

function Invoke-Mcp([string]$Method, $Params, [int]$Id) {
    if ($Method -eq 'tools/call' -and $null -ne $Params.arguments.operation_id -and
        $null -eq $Params.arguments.instance_id) {
        if ([string]::IsNullOrWhiteSpace($script:InstanceId)) {
            throw 'Mutation attempted before backend instance identity was observed.'
        }
        $Params.arguments.instance_id = $script:InstanceId
    }
    $body = @{ jsonrpc = '2.0'; id = $Id; method = $Method; params = $Params } |
        ConvertTo-Json -Depth 12 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$baseUri/mcp" `
        -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 40
    if ($response.error) { throw "JSON-RPC error: $($response.error | ConvertTo-Json -Compress)" }
    return $response.result
}

function Invoke-Tool([string]$Name, $Arguments, [int]$Id) {
    $result = Invoke-Mcp 'tools/call' @{ name = $Name; arguments = $Arguments } $Id
    if ($result.isError) {
        throw "Tool error from $Name`: $($result.structuredContent | ConvertTo-Json -Compress -Depth 8)"
    }
    return $result.structuredContent
}

function Start-OwnedProcess([string]$FilePath, [string]$WorkingDirectory) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (!$process.Start()) { throw "Process launch returned false: $FilePath" }
        return $process
    } catch {
        $process.Dispose()
        throw
    }
}

$fixtureProcess = $null
$debuggerProcess = $null
$fixtureSurvivedDetach = $false
try {
    $fixtureProcess = Start-OwnedProcess $fixture $backendRoot
    Start-Sleep -Milliseconds 150
    if ($fixtureProcess.HasExited) { throw 'Independent fixture exited before attach.' }
    $debuggerProcess = Start-OwnedProcess $debugger $backendRoot

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 100
        try {
            $ready = Invoke-RestMethod -UseBasicParsing -Uri "$baseUri/health/ready" `
                -Headers $headers -TimeoutSec 2
        } catch { $ready = $null }
    } until ($ready.status -eq 'ready' -or [DateTime]::UtcNow -ge $deadline -or
        $debuggerProcess.HasExited)
    if ($ready.status -ne 'ready' -or $ready.debugger_state -ne 'absent') {
        throw 'Isolated debugger did not become ready without a debuggee.'
    }
    $script:InstanceId = ([Guid]::Parse([string]$ready.instance_id)).ToString()

    $null = Invoke-Mcp 'initialize' @{
        protocolVersion = '2025-06-18'; capabilities = @{}
        clientInfo = @{ name = 'attach-integration'; version = '1' }
    } 1
    $before = Invoke-Tool 'debugger.state' @{} 2
    if ($before.instance_id -ne $script:InstanceId) {
        throw 'Readiness and debugger.state reported different backend instances.'
    }
    if ($before.session_origin -ne $null -or
        @($before.next_actions | Where-Object { $_.tool -eq 'debuggee.attach' }).Count -ne 1) {
        throw 'Absent state omitted the explicit attach action or retained an origin.'
    }

    $selfAttach = Invoke-Mcp 'tools/call' @{
        name = 'debuggee.attach'; arguments = @{
            operation_id = [Guid]::NewGuid().ToString(); process_id = $debuggerProcess.Id
        }
    } 3
    if (!$selfAttach.isError -or
        $selfAttach.structuredContent.error.code -ne 'INVALID_ARGUMENT') {
        throw 'Backend did not reject attaching to its own debugger host.'
    }

    $operation = [Guid]::NewGuid().ToString()
    $attachArguments = @{ operation_id = $operation; process_id = $fixtureProcess.Id }
    $attachCall = Invoke-Mcp 'tools/call' @{ name = 'debuggee.attach'; arguments = $attachArguments } 4
    if ($attachCall.isError) {
        $diagnosticState = Invoke-Tool 'debugger.state' @{} 40
        throw "Attach failed; state=$($diagnosticState | ConvertTo-Json -Compress -Depth 8); error=$($attachCall.structuredContent | ConvertTo-Json -Compress -Depth 8)"
    }
    $attached = $attachCall.structuredContent
    $attachedReplay = Invoke-Tool 'debuggee.attach' $attachArguments 5
    if (($attached | ConvertTo-Json -Compress -Depth 12) -ne
        ($attachedReplay | ConvertTo-Json -Compress -Depth 12) -or
        $attached.session_origin -ne 'attached' -or
        [Convert]::ToUInt32($attached.process_id.Substring(2), 16) -ne $fixtureProcess.Id) {
        throw 'Attach was not PID-correlated, origin-aware, or replay-safe.'
    }

    $state = Invoke-Tool 'debugger.state' @{} 6
    if ($state.debuggee_state -ne 'paused' -or $state.session_origin -ne 'attached' -or
        [Convert]::ToUInt32($state.process_id.Substring(2), 16) -ne $fixtureProcess.Id) {
        throw 'Attached debugger.state omitted its PID or session origin.'
    }
    $unsafeStop = Invoke-Mcp 'tools/call' @{
        name = 'debugger.stop'; arguments = @{ operation_id = [Guid]::NewGuid().ToString() }
    } 7
    if (!$unsafeStop.isError -or
        $unsafeStop.structuredContent.error.code -ne 'INVALID_DEBUGGER_STATE' -or
        $fixtureProcess.HasExited) {
        throw 'Attached-session stop was not safely rejected.'
    }
    $modules = Invoke-Tool 'modules.list' @{ limit = 256 } 8
    if (@($modules.items | Where-Object { $_.name -ieq $FixtureName }).Count -ne 1) {
        throw 'Attached fixture was not visible through bounded module discovery.'
    }

    $detached = Invoke-Tool 'debuggee.detach' @{
        operation_id = [Guid]::NewGuid().ToString()
    } 9
    Start-Sleep -Milliseconds 100
    $fixtureProcess.Refresh()
    $fixtureSurvivedDetach = !$fixtureProcess.HasExited
    if ($detached.debuggee_state -ne 'absent' -or $null -ne $detached.session_origin -or
        [Convert]::ToUInt32($detached.detached_process_id.Substring(2), 16) -ne $fixtureProcess.Id -or
        !$fixtureSurvivedDetach) {
        throw 'Detach did not preserve the independently started fixture.'
    }
    $after = Invoke-Tool 'debugger.state' @{} 10
    if ($after.debuggee_state -ne 'absent' -or $null -ne $after.session_origin) {
        throw 'Debugger retained attached session state after detach.'
    }

    [ordered]@{
        backend = $Backend
        architecture = $state.architecture
        instance_id = $script:InstanceId
        debugger_host_process_id = $debuggerProcess.Id
        fixture_process_id = $fixtureProcess.Id
        sidecar_port = $port
        attached_state = $attached.debuggee_state
        attached_origin = $attached.session_origin
        attach_replay_equal = $true
        self_attach_rejected = $true
        destructive_stop_rejected = $true
        detached_state = $detached.debuggee_state
        fixture_survived_detach = $fixtureSurvivedDetach
    } | ConvertTo-Json -Depth 4
} finally {
    if ($debuggerProcess -and !$debuggerProcess.HasExited) {
        $null = $debuggerProcess.CloseMainWindow()
        if (!$debuggerProcess.WaitForExit(7000)) {
            Stop-Process -Id $debuggerProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    if ($fixtureProcess -and !$fixtureProcess.HasExited) {
        Stop-Process -Id $fixtureProcess.Id -Force -ErrorAction SilentlyContinue
        $null = $fixtureProcess.WaitForExit(3000)
    }
    $env:X64DBG_MCP_PORT = $previous.Port
    $env:X64DBG_MCP_TOKEN = $previous.Token
    $env:X64DBG_MCP_SERVER_PATH = $previous.Server
    $token = $null
    $headers = $null
}
