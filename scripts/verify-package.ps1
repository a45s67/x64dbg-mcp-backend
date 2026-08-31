[CmdletBinding()]
param([string]$PackageRoot)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($PackageRoot)) { $PackageRoot = Join-Path $PSScriptRoot '..' }
$root = (Resolve-Path -LiteralPath $PackageRoot).Path

function Get-RelativePackagePath([string]$FullName) {
    $FullName.Substring($root.Length + 1).Replace('\', '/')
}

$requiredFiles = @(
    'install.ps1',
    'mcp/x96dbg-mcp-server.exe',
    'mcp/x96dbg-mcp-server.example.toml',
    'x32/x64dbg-mcp-backend.dp32',
    'x64/x64dbg-mcp-backend.dp64'
)
$actualFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
    Get-RelativePackagePath $_.FullName
} | Sort-Object)
$expectedFiles = @($requiredFiles | Sort-Object)
if (($actualFiles -join "`n") -cne ($expectedFiles -join "`n")) {
    throw "Package must contain exactly: $($requiredFiles -join ', ')"
}

$actualDirectories = @(Get-ChildItem -LiteralPath $root -Recurse -Directory | ForEach-Object {
    Get-RelativePackagePath $_.FullName
} | Sort-Object)
$expectedDirectories = @('mcp', 'x32', 'x64')
if (($actualDirectories -join "`n") -cne ($expectedDirectories -join "`n")) {
    throw 'Package must contain exactly the mcp, x32, and x64 directories.'
}

$configPath = Join-Path $root 'mcp\x96dbg-mcp-server.example.toml'
$settings = @(Get-Content -LiteralPath $configPath | Where-Object { $_ -match '^[a-z_]+\s*=' })
if ($settings.Count -ne 3 -or
    $settings[0] -cne 'bind = "127.0.0.1"' -or
    $settings[1] -cne 'port = 43164' -or
    $settings[2] -cne 'bearer_token = "REPLACE_ME"') {
    throw 'Example config must contain only bind, port, and bearer_token settings.'
}

function Assert-PeMachine([string]$Relative, [uint16]$ExpectedMachine) {
    $path = Join-Path $root ($Relative.Replace('/', '\'))
    $stream = [IO.File]::OpenRead($path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 70 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw "Invalid DOS/PE header: $Relative"
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or [int64]$peOffset + 6 -gt $stream.Length) {
            throw "Invalid PE offset: $Relative"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $Relative" }
        $machine = $reader.ReadUInt16()
        if ($machine -ne $ExpectedMachine) {
            throw ('Unexpected PE machine for {0}: 0x{1:x4}' -f $Relative, $machine)
        }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

Assert-PeMachine 'x32/x64dbg-mcp-backend.dp32' 0x014c
Assert-PeMachine 'x64/x64dbg-mcp-backend.dp64' 0x8664
Assert-PeMachine 'mcp/x96dbg-mcp-server.exe' 0x8664
Write-Output 'Package verified: minimal five-file layout'
