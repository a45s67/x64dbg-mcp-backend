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
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$baseUri/mcp" `
        -Headers $headers -ContentType 'application/json' -Body $request -TimeoutSec 40
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

    $null = Invoke-Mcp 'initialize' @{
        protocolVersion = '2025-06-18'
        capabilities = @{}
        clientInfo = @{ name = 'flare-checksum-smoke'; version = '1' }
    } 1
    $initial = Invoke-Tool 'debugger.state' @{} 2
    if ($initial.debuggee_state -ne 'absent') {
        throw 'Installed debugger did not start without a debuggee.'
    }
    $launch = Invoke-Tool 'debuggee.launch' @{
        operation_id = [Guid]::NewGuid().ToString()
        path = $sample
        working_directory = Split-Path -Parent $sample
    } 3
    $moduleRef = @{
        module = [System.IO.Path]::GetFileName($sample)
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
