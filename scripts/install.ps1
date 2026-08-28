[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$X64dbgRoot,
    [int]$X32Port = 43132,
    [int]$X64Port = 43164,
    [string]$PackageRoot
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $PackageRoot = Join-Path $PSScriptRoot '..'
}
if ($X32Port -lt 1 -or $X32Port -gt 65535 -or $X64Port -lt 1 -or
    $X64Port -gt 65535 -or $X32Port -eq $X64Port) {
    throw 'X32Port and X64Port must be distinct values from 1 through 65535.'
}
$package = (Resolve-Path -LiteralPath $PackageRoot).Path
$root = (Resolve-Path -LiteralPath $X64dbgRoot).Path
$debuggerRoot = if (Test-Path -LiteralPath (Join-Path $root 'release\x64')) {
    Join-Path $root 'release'
} elseif (Test-Path -LiteralPath (Join-Path $root 'x64')) {
    $root
} else {
    throw 'X64dbgRoot must contain x32 and x64 debugger directories.'
}
if (!(Test-Path -LiteralPath (Join-Path $debuggerRoot 'x32\plugins')) -or
    !(Test-Path -LiteralPath (Join-Path $debuggerRoot 'x64\plugins'))) {
    throw 'Both x32 and x64 plugin directories are required.'
}

$serverSource = Join-Path $package 'server\x64dbg-mcp-server.exe'
$x32Source = Join-Path $package 'x32\plugins\x64dbg-mcp-backend.dp32'
$x64Source = Join-Path $package 'x64\plugins\x64dbg-mcp-backend.dp64'
foreach ($required in @($serverSource, $x32Source, $x64Source)) {
    if (!(Test-Path -LiteralPath $required)) { throw "Package file is missing: $required" }
}

$serverDirectory = Join-Path $debuggerRoot 'server'
if ($PSCmdlet.ShouldProcess($debuggerRoot, 'Install x64dbg MCP backend')) {
    New-Item -ItemType Directory -Path $serverDirectory -Force | Out-Null
    Copy-Item -LiteralPath $serverSource -Destination $serverDirectory -Force
    Copy-Item -LiteralPath $x32Source -Destination (Join-Path $debuggerRoot 'x32\plugins') -Force
    Copy-Item -LiteralPath $x64Source -Destination (Join-Path $debuggerRoot 'x64\plugins') -Force

    $tokenBytes = New-Object byte[] 48
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($tokenBytes) } finally { $generator.Dispose() }
    $token = [Convert]::ToBase64String($tokenBytes)
    foreach ($entry in @(@('x32', $X32Port), @('x64', $X64Port))) {
        $configPath = Join-Path $serverDirectory "x64dbg-mcp-server-$($entry[0]).toml"
        @"
bind = "127.0.0.1"
port = $($entry[1])
bearer_token = "$token"
request_timeout_ms = 10000
mutation_timeout_ms = 30000
shutdown_timeout_ms = 10000
max_inflight = 8
max_header_count = 64
max_header_bytes = 32768
max_requests_per_second = 100
max_body_bytes = 1048576
max_output_bytes = 1048576
allowed_origins = []
"@ | Set-Content -LiteralPath $configPath -Encoding ASCII -NoNewline
    }
    Write-Output "Installed backend. Bearer token (store securely): $token"
    Write-Output "x32 endpoint: http://127.0.0.1:$X32Port/mcp"
    Write-Output "x64 endpoint: http://127.0.0.1:$X64Port/mcp"
}
