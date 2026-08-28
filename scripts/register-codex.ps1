[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$X64dbgRoot,
    [string]$CodexHome
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $X64dbgRoot).Path
$debuggerRoot = if (Test-Path -LiteralPath (Join-Path $root 'release\server')) {
    Join-Path $root 'release'
} elseif (Test-Path -LiteralPath (Join-Path $root 'server')) {
    $root
} else {
    throw 'X64dbgRoot must contain an installed server directory.'
}

if ([string]::IsNullOrWhiteSpace($CodexHome)) {
    $CodexHome = if (![string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
        $env:CODEX_HOME
    } else {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'
    }
}
$codexHomePath = [IO.Path]::GetFullPath($CodexHome)
$configPath = Join-Path $codexHomePath 'config.toml'

function Read-BackendConfig([string]$Architecture) {
    $path = Join-Path $debuggerRoot "server\x64dbg-mcp-server-$Architecture.toml"
    if (!(Test-Path -LiteralPath $path)) {
        throw "Installed backend configuration is missing: $path"
    }
    $content = Get-Content -Raw -LiteralPath $path
    if ($content -notmatch '(?m)^bind\s*=\s*"([^"]+)"\s*$') {
        throw "Backend bind address is missing from $path"
    }
    $bindAddress = $Matches[1]
    if ($bindAddress -notin @('127.0.0.1', '::1')) {
        throw "Backend bind address must be a loopback address: $path"
    }
    if ($content -notmatch '(?m)^port\s*=\s*([0-9]+)\s*$') {
        throw "Backend port is missing from $path"
    }
    $port = [int]$Matches[1]
    if ($port -lt 1 -or $port -gt 65535) {
        throw "Backend port is outside the valid range: $path"
    }
    if ($content -notmatch '(?m)^bearer_token\s*=\s*"([^"]+)"\s*$') {
        throw "Backend bearer token is missing from $path"
    }
    $token = $Matches[1]
    foreach ($character in $token.ToCharArray()) {
        if ([int]$character -lt 0x20 -or [int]$character -eq 0x7f) {
            throw "Backend bearer token contains a control character: $path"
        }
    }
    [pscustomobject]@{ Bind = $bindAddress; Port = $port; Token = $token }
}

function ConvertTo-TomlBasicString([string]$Value) {
    foreach ($character in $Value.ToCharArray()) {
        if ([int]$character -lt 0x20 -or [int]$character -eq 0x7f) {
            throw 'Codex MCP configuration values cannot contain control characters.'
        }
    }
    $Value.Replace('\', '\\').Replace('"', '\"')
}

function Get-BackendUrl($Backend) {
    $hostAddress = if ($Backend.Bind -eq '::1') { '[::1]' } else { $Backend.Bind }
    "http://$hostAddress`:$($Backend.Port)/mcp"
}

function Update-McpSection(
    [System.Collections.Generic.List[string]]$Lines,
    [string]$Name,
    [string]$Url,
    [string]$Token
) {
    $sectionPattern = '^\s*\[mcp_servers\.' + [regex]::Escape($Name) + '\]\s*(?:#.*)?$'
    $tablePattern = '^\s*\['
    $transportPattern = '^\s*(url|command|args|cwd|env|env_vars|bearer_token_env_var|env_http_headers|http_headers)\s*='
    $result = New-Object 'System.Collections.Generic.List[string]'
    $found = $false
    $index = 0

    while ($index -lt $Lines.Count) {
        if ($Lines[$index] -notmatch $sectionPattern) {
            $result.Add($Lines[$index])
            $index++
            continue
        }

        $sectionEnd = $index + 1
        while ($sectionEnd -lt $Lines.Count -and $Lines[$sectionEnd] -notmatch $tablePattern) {
            $sectionEnd++
        }
        if (!$found) {
            $result.Add("[mcp_servers.$Name]")
            $result.Add('url = "' + (ConvertTo-TomlBasicString $Url) + '"')
            $authorization = ConvertTo-TomlBasicString ('Bearer ' + $Token)
            $result.Add('http_headers = { Authorization = "' + $authorization + '" }')
            for ($preserved = $index + 1; $preserved -lt $sectionEnd; $preserved++) {
                if ($Lines[$preserved] -notmatch $transportPattern) {
                    $result.Add($Lines[$preserved])
                }
            }
            $found = $true
        }
        $index = $sectionEnd
    }

    if (!$found) {
        if ($result.Count -gt 0 -and $result[$result.Count - 1] -ne '') {
            $result.Add('')
        }
        $result.Add("[mcp_servers.$Name]")
        $result.Add('url = "' + (ConvertTo-TomlBasicString $Url) + '"')
        $authorization = ConvertTo-TomlBasicString ('Bearer ' + $Token)
        $result.Add('http_headers = { Authorization = "' + $authorization + '" }')
    }
    return ,$result
}

$x32 = Read-BackendConfig 'x32'
$x64 = Read-BackendConfig 'x64'
if ($x32.Token -cne $x64.Token) {
    throw 'x32 and x64 bearer tokens differ; rerun install.ps1 before registering Codex.'
}
$x32Url = Get-BackendUrl $x32
$x64Url = Get-BackendUrl $x64

if ($PSCmdlet.ShouldProcess($configPath, 'Register x32dbg and x64dbg MCP backends')) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $configPath) {
        foreach ($line in [IO.File]::ReadAllLines($configPath)) { $lines.Add($line) }
    }
    $lines = Update-McpSection $lines 'x64dbg' $x64Url $x64.Token
    $lines = Update-McpSection $lines 'x32dbg' $x32Url $x32.Token

    [IO.Directory]::CreateDirectory($codexHomePath) | Out-Null
    [IO.File]::WriteAllLines($configPath, $lines, (New-Object Text.UTF8Encoding($false)))
    Write-Output "x64dbg: $x64Url"
    Write-Output "x32dbg: $x32Url"
    Write-Output 'Codex MCP registration complete with static Authorization headers. Restart Codex.'
}
