[CmdletBinding()]
param(
    [string]$PackageRoot
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $PackageRoot = Join-Path $PSScriptRoot '..'
}
$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$manifestPath = Join-Path $root 'checksums.txt'
if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Package checksum manifest is missing.'
}

function Get-RelativePackagePath([string]$FullName) {
    $FullName.Substring($root.Length + 1).Replace('\', '/')
}

$expected = @{}
$lineNumber = 0
foreach ($line in Get-Content -LiteralPath $manifestPath) {
    $lineNumber++
    if ($line -notmatch '^([0-9a-f]{64})  ([^\\]+)$') {
        throw "Invalid checksum manifest line $lineNumber."
    }
    $hash = $Matches[1]
    $relative = $Matches[2]
    $segments = @($relative -split '/')
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or
        $segments.Count -eq 0 -or @($segments | Where-Object {
            [string]::IsNullOrWhiteSpace($_) -or $_ -eq '.' -or $_ -eq '..'
        }).Count -ne 0) {
        throw "Unsafe checksum path on line $lineNumber."
    }
    $key = $relative.ToLowerInvariant()
    if ($expected.ContainsKey($key)) {
        throw "Duplicate checksum path on line $lineNumber."
    }
    $expected[$key] = [pscustomobject]@{ Hash = $hash; Relative = $relative }
}
if ($expected.Count -eq 0) { throw 'Package checksum manifest is empty.' }

$actualFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File |
    Where-Object { $_.FullName -ine $manifestPath })
if ($actualFiles.Count -ne $expected.Count) {
    throw "Package file count does not match checksums.txt ($($actualFiles.Count) != $($expected.Count))."
}
foreach ($file in $actualFiles) {
    $relative = Get-RelativePackagePath $file.FullName
    $key = $relative.ToLowerInvariant()
    if (!$expected.ContainsKey($key)) { throw "Unlisted package file: $relative" }
    if ($expected[$key].Relative -cne $relative) {
        throw "Package path casing differs from checksums.txt: $relative"
    }
    $actualHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $expected[$key].Hash) { throw "Checksum mismatch: $relative" }
}

$required = @(
    'x32/plugins/x64dbg-mcp-backend.dp32',
    'x64/plugins/x64dbg-mcp-backend.dp64',
    'server/x64dbg-mcp-server.exe',
    'config/x64dbg-mcp-server-x32.example.toml',
    'config/x64dbg-mcp-server-x64.example.toml',
    'scripts/install.ps1',
    'scripts/register-codex.ps1',
    'scripts/verify-package.ps1',
    'docs/install.md',
    'docs/contracts/ipc-v1.md',
    'version.json',
    'sbom.cdx.json',
    'LICENSES/PROJECT-LICENSE.txt',
    'THIRD-PARTY-NOTICES.md'
)
foreach ($relative in $required) {
    if (!$expected.ContainsKey($relative.ToLowerInvariant())) {
        throw "Required package file is missing from checksums.txt: $relative"
    }
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

Assert-PeMachine 'x32/plugins/x64dbg-mcp-backend.dp32' 0x014c
Assert-PeMachine 'x64/plugins/x64dbg-mcp-backend.dp64' 0x8664
Assert-PeMachine 'server/x64dbg-mcp-server.exe' 0x8664

$version = Get-Content -LiteralPath (Join-Path $root 'version.json') -Raw | ConvertFrom-Json
if ($version.name -cne 'x64dbg-mcp-backend' -or $version.mcp_protocol -cne '2025-06-18' -or
    $version.ipc_protocol.major -ne 1 -or $version.ipc_protocol.minor -ne 0 -or
    @($version.targets).Count -ne 2 -or
    @($version.targets | Where-Object { $_ -ceq 'x32dbg' }).Count -ne 1 -or
    @($version.targets | Where-Object { $_ -ceq 'x64dbg' }).Count -ne 1) {
    throw 'Package version metadata is invalid.'
}
$sbom = Get-Content -LiteralPath (Join-Path $root 'sbom.cdx.json') -Raw | ConvertFrom-Json
if ($sbom.bomFormat -cne 'CycloneDX' -or $sbom.specVersion -cne '1.5' -or
    @($sbom.components).Count -lt 2) {
    throw 'Package SBOM metadata is invalid.'
}

Write-Output "Package verified: $($version.name) $($version.version) ($($expected.Count) files)"
