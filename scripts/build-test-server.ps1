[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$serverManifest = Join-Path $workspace 'crates\server\Cargo.toml'
Push-Location $workspace
try {
    # Cargo resolves CARGO_TARGET_DIR and configured target triples; do not guess a path.
    $messages = & cargo.exe build --offline --locked --release --bin x64dbg-mcp-server --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'Rust test server release build failed.' }
    $artifacts = @($messages | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
        $_.reason -ceq 'compiler-artifact' -and
        $_.target.name -ceq 'x64dbg-mcp-server' -and
        $_.target.kind.Count -eq 1 -and $_.target.kind[0] -ceq 'bin' -and
        !$_.profile.test -and
        ![string]::IsNullOrWhiteSpace($_.manifest_path) -and
        [IO.Path]::GetFullPath($_.manifest_path) -ieq $serverManifest
    })
    if ($artifacts.Count -ne 1 -or [string]::IsNullOrWhiteSpace($artifacts[0].executable)) {
        throw 'Expected exactly one server binary artifact with an executable path.'
    }
    $executable = [IO.Path]::GetFullPath($artifacts[0].executable)
    if (!(Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Cargo server executable does not exist: $executable"
    }
    Write-Output $executable
} finally {
    Pop-Location
}
