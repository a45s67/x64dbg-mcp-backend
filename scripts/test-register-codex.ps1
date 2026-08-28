[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptUnderTest = Join-Path $PSScriptRoot 'register-codex.ps1'
$installerUnderTest = Join-Path $PSScriptRoot 'install.ps1'
$systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $systemTemp ('x64dbg-mcp-register-test-' + [guid]::NewGuid().ToString('N'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw "register-codex contract failed: $Message" }
}

function Write-BackendConfig([string]$Root, [string]$Architecture, [string]$Bind, [int]$Port, [string]$Token) {
    $server = Join-Path $Root 'server'
    [IO.Directory]::CreateDirectory($server) | Out-Null
    $content = "bind = `"$Bind`"`nport = $Port`nbearer_token = `"$Token`"`n"
    [IO.File]::WriteAllText(
        (Join-Path $server "x64dbg-mcp-server-$Architecture.toml"),
        $content,
        (New-Object Text.UTF8Encoding($false)))
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    $debuggerRoot = Join-Path $testRoot 'debugger'
    $codexHome = Join-Path $testRoot 'codex-existing'
    $token = 'contract-token-+/='
    Write-BackendConfig $debuggerRoot 'x32' '127.0.0.1' 43132 $token
    Write-BackendConfig $debuggerRoot 'x64' '::1' 43164 $token
    [IO.Directory]::CreateDirectory($codexHome) | Out-Null

    $seed = @'
model = "keep-me"

[mcp_servers.x32dbg]
url = "http://old.invalid/mcp"
bearer_token_env_var = "OLD_TOKEN"
enabled = false

[mcp_servers.x64dbg]
command = "old-sidecar.exe"
args = ["--old"]
http_headers = { Authorization = "Bearer old" }
tool_timeout_sec = 12

[mcp_servers.unrelated]
url = "http://127.0.0.1:9999/mcp"
'@
    $configPath = Join-Path $codexHome 'config.toml'
    [IO.File]::WriteAllText($configPath, $seed, (New-Object Text.UTF8Encoding($false)))

    $output = & $scriptUnderTest -X64dbgRoot $debuggerRoot -CodexHome $codexHome
    $first = [IO.File]::ReadAllText($configPath)
    Assert-True ($first -match '(?m)^model = "keep-me"\r?$') 'unrelated root setting was not preserved'
    Assert-True ($first -match '(?m)^\[mcp_servers\.unrelated\]\r?$') 'unrelated MCP server was not preserved'
    Assert-True ($first -match '(?m)^enabled = false\r?$') 'x32 non-transport setting was not preserved'
    Assert-True ($first -match '(?m)^tool_timeout_sec = 12\r?$') 'x64 non-transport setting was not preserved'
    Assert-True ($first -notmatch '(?m)^\s*(command|args|bearer_token_env_var)\s*=') 'legacy transport keys remain'
    Assert-True ([regex]::Matches($first, '(?m)^\[mcp_servers\.x32dbg\]\r?$').Count -eq 1) 'x32 section count is not one'
    Assert-True ([regex]::Matches($first, '(?m)^\[mcp_servers\.x64dbg\]\r?$').Count -eq 1) 'x64 section count is not one'
    Assert-True ([regex]::Matches($first, 'http_headers = \{ Authorization = "Bearer contract-token-\+/=" \}').Count -eq 2) 'static Authorization headers are incorrect'
    Assert-True ($first -match 'url = "http://127\.0\.0\.1:43132/mcp"') 'x32 URL is incorrect'
    Assert-True ($first -match 'url = "http://\[::1\]:43164/mcp"') 'x64 IPv6 URL is incorrect'
    Assert-True (($output -join "`n") -notmatch [regex]::Escape($token)) 'helper output disclosed the token'

    & $scriptUnderTest -X64dbgRoot $debuggerRoot -CodexHome $codexHome | Out-Null
    $second = [IO.File]::ReadAllText($configPath)
    Assert-True ($first -ceq $second) 'a repeated registration changed the config'

    $newCodexHome = Join-Path $testRoot 'codex-new'
    & $scriptUnderTest -X64dbgRoot $debuggerRoot -CodexHome $newCodexHome | Out-Null
    $newConfig = [IO.File]::ReadAllText((Join-Path $newCodexHome 'config.toml'))
    Assert-True ($newConfig -match '(?m)^\[mcp_servers\.x32dbg\]\r?$') 'x32 section was not created in a new config'
    Assert-True ($newConfig -match '(?m)^\[mcp_servers\.x64dbg\]\r?$') 'x64 section was not created in a new config'

    $mismatchRoot = Join-Path $testRoot 'debugger-mismatch'
    Write-BackendConfig $mismatchRoot 'x32' '127.0.0.1' 43132 'token-one'
    Write-BackendConfig $mismatchRoot 'x64' '127.0.0.1' 43164 'token-two'
    $mismatchHome = Join-Path $testRoot 'codex-mismatch'
    $failed = $false
    try {
        & $scriptUnderTest -X64dbgRoot $mismatchRoot -CodexHome $mismatchHome | Out-Null
    } catch {
        $failed = $_.Exception.Message -match 'tokens differ'
    }
    Assert-True $failed 'mismatched backend tokens were not rejected'
    Assert-True (!(Test-Path -LiteralPath (Join-Path $mismatchHome 'config.toml'))) 'mismatch failure wrote a partial config'

    $packageRoot = Join-Path $testRoot 'package'
    $installRoot = Join-Path $testRoot 'install-target'
    $installCodexHome = Join-Path $testRoot 'codex-from-installer'
    foreach ($directory in @(
        (Join-Path $packageRoot 'server'),
        (Join-Path $packageRoot 'x32\plugins'),
        (Join-Path $packageRoot 'x64\plugins'),
        (Join-Path $installRoot 'x32\plugins'),
        (Join-Path $installRoot 'x64\plugins')
    )) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    [IO.File]::WriteAllText((Join-Path $packageRoot 'server\x64dbg-mcp-server.exe'), 'server')
    [IO.File]::WriteAllText((Join-Path $packageRoot 'x32\plugins\x64dbg-mcp-backend.dp32'), 'x32')
    [IO.File]::WriteAllText((Join-Path $packageRoot 'x64\plugins\x64dbg-mcp-backend.dp64'), 'x64')
    & $installerUnderTest -X64dbgRoot $installRoot -PackageRoot $packageRoot | Out-Null
    Assert-True (!(Test-Path -LiteralPath (Join-Path $installCodexHome 'config.toml'))) 'debugger installer modified Codex configuration'
    & $scriptUnderTest -X64dbgRoot $installRoot -CodexHome $installCodexHome | Out-Null

    Assert-True ((Get-Content -Raw (Join-Path $installRoot 'x32\plugins\x64dbg-mcp-backend.dp32')) -eq 'x32') 'installer did not deploy x32 plugin'
    Assert-True ((Get-Content -Raw (Join-Path $installRoot 'x64\plugins\x64dbg-mcp-backend.dp64')) -eq 'x64') 'installer did not deploy x64 plugin'
    Assert-True ((Get-Content -Raw (Join-Path $installRoot 'server\x64dbg-mcp-server.exe')) -eq 'server') 'installer did not deploy the shared sidecar'
    $installedX32 = Get-Content -Raw (Join-Path $installRoot 'server\x64dbg-mcp-server-x32.toml')
    $installedX64 = Get-Content -Raw (Join-Path $installRoot 'server\x64dbg-mcp-server-x64.toml')
    $null = $installedX32 -match '(?m)^bearer_token = "([^"]+)"$'
    $installedToken = $Matches[1]
    Assert-True (![string]::IsNullOrWhiteSpace($installedToken)) 'installer did not generate a token'
    Assert-True ($installedX64 -match ('(?m)^bearer_token = "' + [regex]::Escape($installedToken) + '"$')) 'x32 and x64 installed tokens differ'
    $installedCodex = [IO.File]::ReadAllText((Join-Path $installCodexHome 'config.toml'))
    Assert-True ($installedCodex -match 'url = "http://127\.0\.0\.1:43132/mcp"') 'Codex installer did not register x32 endpoint'
    Assert-True ($installedCodex -match 'url = "http://127\.0\.0\.1:43164/mcp"') 'Codex installer did not register x64 endpoint'
    Assert-True ([regex]::Matches($installedCodex, 'http_headers = \{ Authorization = "Bearer [^"]+" \}').Count -eq 2) 'Codex installer did not register both static Authorization headers'

    Write-Output 'register-codex contract tests passed'
} finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    if ($resolvedTestRoot.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolvedTestRoot).StartsWith('x64dbg-mcp-register-test-')) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
