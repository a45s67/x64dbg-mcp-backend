[CmdletBinding()]
param(
    [string]$Version = '0.19.0',
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $workspace 'dist'
}
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (!$output.StartsWith($workspace + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Package output must remain inside the repository workspace.'
}
$stage = Join-Path $output "x64dbg-mcp-backend-$Version"
$archive = "$stage.zip"
if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $archive)) {
    throw 'Refusing to overwrite an existing release stage or archive.'
}

Push-Location $workspace
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $workspace 'scripts\test-install.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Installer contract tests failed.' }
    & cargo.exe test --offline --locked --workspace --all-targets
    if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed.' }
    & cargo.exe clippy --offline --locked --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Rust Clippy gate failed.' }
    & cargo.exe build --offline --locked --release
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed.' }
    & (Join-Path $workspace 'scripts\build-plugin.cmd') x86 test
    if ($LASTEXITCODE -ne 0) { throw 'x86 plugin build failed.' }
    & (Join-Path $workspace 'scripts\build-plugin.cmd') x64 test
    if ($LASTEXITCODE -ne 0) { throw 'x64 plugin build failed.' }

    New-Item -ItemType Directory -Path $stage | Out-Null
    foreach ($relative in @('x32', 'x64', 'mcp', 'docs', 'docs\contracts', 'LICENSES', 'scripts')) {
        New-Item -ItemType Directory -Path (Join-Path $stage $relative) -Force | Out-Null
    }
    Copy-Item -LiteralPath 'build\windows-x86\x64dbg-mcp-backend.dp32' `
        -Destination (Join-Path $stage 'x32')
    Copy-Item -LiteralPath 'build\windows-x64\x64dbg-mcp-backend.dp64' `
        -Destination (Join-Path $stage 'x64')
    Copy-Item -LiteralPath 'target\release\x64dbg-mcp-server.exe' `
        -Destination (Join-Path $stage 'mcp\x96dbg-mcp-server.exe')
    Copy-Item -Path 'config\*.toml' -Destination (Join-Path $stage 'mcp')
    Copy-Item -LiteralPath 'LICENSE' -Destination (Join-Path $stage 'LICENSES\PROJECT-LICENSE.txt')
    Copy-Item -LiteralPath 'THIRD-PARTY-NOTICES.md' -Destination $stage
    Copy-Item -LiteralPath 'README.md' -Destination $stage
    Copy-Item -LiteralPath 'docs\contracts\ipc-v1.md' -Destination (Join-Path $stage 'docs\contracts')
    Copy-Item -LiteralPath 'scripts\install.ps1' -Destination (Join-Path $stage 'scripts')
    Copy-Item -LiteralPath 'scripts\verify-package.ps1' -Destination (Join-Path $stage 'scripts')

    @{
        name = 'x64dbg-mcp-backend'
        version = $Version
        mcp_protocol = '2025-06-18'
        ipc_protocol = @{ major = 1; minor = 1 }
        x64dbg_baseline = @{ release = '2026.05.27'; commit = '9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87' }
        targets = @('x32dbg', 'x64dbg')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'version.json') -Encoding UTF8

    $lockPackages = New-Object System.Collections.Generic.List[object]
    $current = $null
    foreach ($line in Get-Content -LiteralPath 'Cargo.lock') {
        if ($line -eq '[[package]]') {
            if ($current -and $current.name -and $current.version) { $lockPackages.Add($current) }
            $current = [ordered]@{}
        } elseif ($current -and $line -match '^name = "([^"]+)"$') {
            $current.name = $Matches[1]
        } elseif ($current -and $line -match '^version = "([^"]+)"$') {
            $current.version = $Matches[1]
        } elseif ($current -and $line -match '^source = "([^"]+)"$') {
            $current.source = $Matches[1]
        }
    }
    if ($current -and $current.name -and $current.version) { $lockPackages.Add($current) }
    if ($lockPackages.Count -lt 2) { throw 'Cargo.lock dependency inventory parsing failed.' }
    $components = @($lockPackages | Sort-Object name, version | ForEach-Object {
        $component = [ordered]@{
            type = if ($_.name -eq 'x64dbg-mcp-server') { 'application' } else { 'library' }
            name = $_.name; version = $_.version; purl = "pkg:cargo/$($_.name)@$($_.version)"
        }
        $component
    })
    [ordered]@{
        bomFormat = 'CycloneDX'; specVersion = '1.5'
        version = 1; metadata = @{ component = @{ type = 'application'; name = 'x64dbg-mcp-backend'; version = $Version } }
        components = $components
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $stage 'sbom.cdx.json') -Encoding UTF8

    $checksums = Get-ChildItem -LiteralPath $stage -Recurse -File |
        Sort-Object FullName | ForEach-Object {
            $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $relative"
        }
    $checksums | Set-Content -LiteralPath (Join-Path $stage 'checksums.txt') -Encoding ASCII
    & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $workspace 'scripts\test-package.ps1') -PackageRoot $stage
    if ($LASTEXITCODE -ne 0) { throw 'Package verifier contract tests failed.' }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archiveStream = [System.IO.File]::Open($archive, [System.IO.FileMode]::CreateNew)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new(
            $archiveStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $prefix = [System.IO.Path]::GetFileName($stage)
            $fixedTimestamp = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName) {
                $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
                $entry = $zip.CreateEntry("$prefix/$relative",
                    [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $fixedTimestamp
                $entryStream = $entry.Open()
                $inputStream = [System.IO.File]::OpenRead($file.FullName)
                try { $inputStream.CopyTo($entryStream) } finally {
                    $inputStream.Dispose()
                    $entryStream.Dispose()
                }
            }
        } finally { $zip.Dispose() }
    } finally { $archiveStream.Dispose() }
    Write-Output "Created $archive"
} finally {
    Pop-Location
}
