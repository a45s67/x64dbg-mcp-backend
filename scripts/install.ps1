[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$X64dbgRoot,
    [int]$X32Port = 43132,
    [int]$X64Port = 43164,
    [string]$PackageRoot,
    [switch]$RotateToken
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $PackageRoot = Join-Path $PSScriptRoot '..'
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
$skillSource = Join-Path $package 'skills\x64dbg-debugging'
$skillFiles = @(
    (Join-Path $skillSource 'SKILL.md'),
    (Join-Path $skillSource '.managed-by-x64dbg-mcp-backend'),
    (Join-Path $skillSource 'references\recipes.md'),
    (Join-Path $skillSource 'references\troubleshooting.md')
)
foreach ($required in @($serverSource, $x32Source, $x64Source) + $skillFiles) {
    if (!(Test-Path -LiteralPath $required)) { throw "Package file is missing: $required" }
}

$serverDirectory = Join-Path $debuggerRoot 'server'
$x32ConfigPath = Join-Path $serverDirectory 'x64dbg-mcp-server-x32.toml'
$x64ConfigPath = Join-Path $serverDirectory 'x64dbg-mcp-server-x64.toml'

function Read-InstalledConfig([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $text = Get-Content -LiteralPath $Path -Raw
    $portMatch = [regex]::Match($text, '(?m)^port = ([0-9]+)\r?$')
    $tokenMatch = [regex]::Match($text, '(?m)^bearer_token = "([^"\r\n]+)"\r?$')
    if (!$portMatch.Success -or !$tokenMatch.Success) {
        throw "Installed backend configuration is invalid: $Path"
    }
    $port = 0
    if (![int]::TryParse($portMatch.Groups[1].Value, [ref]$port) -or
        $port -lt 1 -or $port -gt 65535) {
        throw "Installed backend port is invalid: $Path"
    }
    $token = $tokenMatch.Groups[1].Value
    $tokenBytes = [Text.Encoding]::UTF8.GetByteCount($token)
    if ($tokenBytes -lt 32 -or $tokenBytes -gt 4096 -or
        $token.IndexOfAny([char[]](0..31)) -ge 0) {
        throw "Installed backend bearer token is invalid: $Path"
    }
    [pscustomobject]@{ Port = $port; Token = $token }
}

$x32Installed = Read-InstalledConfig $x32ConfigPath
$x64Installed = Read-InstalledConfig $x64ConfigPath
$effectiveX32Port = if ($PSBoundParameters.ContainsKey('X32Port')) {
    $X32Port
} elseif ($x32Installed) { $x32Installed.Port } else { 43132 }
$effectiveX64Port = if ($PSBoundParameters.ContainsKey('X64Port')) {
    $X64Port
} elseif ($x64Installed) { $x64Installed.Port } else { 43164 }
if ($effectiveX32Port -lt 1 -or $effectiveX32Port -gt 65535 -or
    $effectiveX64Port -lt 1 -or $effectiveX64Port -gt 65535 -or
    $effectiveX32Port -eq $effectiveX64Port) {
    throw 'X32Port and X64Port must be distinct values from 1 through 65535.'
}

$installedTokens = @(@($x32Installed, $x64Installed) |
    Where-Object { $null -ne $_ } | ForEach-Object { $_.Token } | Select-Object -Unique)
if (!$RotateToken -and $installedTokens.Count -gt 1) {
    throw 'Installed x32 and x64 bearer tokens differ. Reconcile them or use -RotateToken.'
}
$tokenWasGenerated = $RotateToken -or $installedTokens.Count -eq 0
if ($tokenWasGenerated) {
    $randomBytes = New-Object byte[] 48
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($randomBytes) } finally { $generator.Dispose() }
    $token = [Convert]::ToBase64String($randomBytes)
} else {
    $token = $installedTokens[0]
}

if ($PSCmdlet.ShouldProcess($debuggerRoot, 'Install x64dbg MCP backend')) {
    New-Item -ItemType Directory -Path $serverDirectory -Force | Out-Null
    Copy-Item -LiteralPath $serverSource -Destination $serverDirectory -Force
    Copy-Item -LiteralPath $x32Source -Destination (Join-Path $debuggerRoot 'x32\plugins') -Force
    Copy-Item -LiteralPath $x64Source -Destination (Join-Path $debuggerRoot 'x64\plugins') -Force

    foreach ($entry in @(@('x32', $effectiveX32Port), @('x64', $effectiveX64Port))) {
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
    $tokenAction = if ($tokenWasGenerated) { 'generated' } else { 'preserved' }
    Write-Output "Installed backend. Bearer token $tokenAction and stored in the two server config files."
    Write-Output "x32 endpoint: http://127.0.0.1:$effectiveX32Port/mcp"
    Write-Output "x64 endpoint: http://127.0.0.1:$effectiveX64Port/mcp"
    Write-Output ''
    Write-Output 'Codex setup is manual. Treat the Authorization value below as a secret.'
    Write-Output 'Do not paste this output into an issue, chat, or build log.'
    Write-Output 'Open the Codex configuration:'
    Write-Output 'notepad.exe "$HOME\.codex\config.toml"'
    Write-Output ''
    Write-Output '[mcp_servers.x64dbg]'
    Write-Output "url = `"http://127.0.0.1:$effectiveX64Port/mcp`""
    Write-Output "http_headers = { Authorization = `"Bearer $token`" }"
    Write-Output ''
    Write-Output '[mcp_servers.x32dbg]'
    Write-Output "url = `"http://127.0.0.1:$effectiveX32Port/mcp`""
    Write-Output "http_headers = { Authorization = `"Bearer $token`" }"
    Write-Output ''
    Write-Output 'Install the complete version-matched workflow skill:'
    Write-Output 'New-Item -ItemType Directory -Force "$HOME\.codex\skills\x64dbg-debugging" | Out-Null'
    $escapedSkillGlob = ((Join-Path $skillSource '*').Replace("'", "''"))
    Write-Output "Copy-Item -Path '$escapedSkillGlob' -Destination `"`$HOME\.codex\skills\x64dbg-debugging`" -Recurse -Force"
    Write-Output 'Restart Codex after saving the configuration and copying the skill.'
}
