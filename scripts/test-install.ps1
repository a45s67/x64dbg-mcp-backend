[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'install.ps1'
$systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $systemTemp ('x64dbg-mcp-install-test-' + [guid]::NewGuid().ToString('N'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw "install contract failed: $Message" }
}

function Read-TestConfig([string]$Path) {
    $text = [IO.File]::ReadAllText($Path)
    $port = [regex]::Match($text, '(?m)^port = ([0-9]+)\r?$').Groups[1].Value
    $token = [regex]::Match($text, '(?m)^bearer_token = "([^"\r\n]+)"\r?$').Groups[1].Value
    [pscustomobject]@{ Port = [int]$port; Token = $token }
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    $package = Join-Path $testRoot 'package'
    $debugger = Join-Path $testRoot 'debugger'
    foreach ($directory in @(
        (Join-Path $package 'server'),
        (Join-Path $package 'x32\plugins'),
        (Join-Path $package 'x64\plugins'),
        (Join-Path $debugger 'release\x32\plugins'),
        (Join-Path $debugger 'release\x64\plugins')
    )) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    $serverSource = Join-Path $package 'server\x64dbg-mcp-server.exe'
    $x32Source = Join-Path $package 'x32\plugins\x64dbg-mcp-backend.dp32'
    $x64Source = Join-Path $package 'x64\plugins\x64dbg-mcp-backend.dp64'
    [IO.File]::WriteAllText($serverSource, 'server-v1')
    [IO.File]::WriteAllText($x32Source, 'x32-v1')
    [IO.File]::WriteAllText($x64Source, 'x64-v1')

    $output = & $installer -X64dbgRoot $debugger -PackageRoot $package
    $serverDirectory = Join-Path $debugger 'release\server'
    $x32ConfigPath = Join-Path $serverDirectory 'x64dbg-mcp-server-x32.toml'
    $x64ConfigPath = Join-Path $serverDirectory 'x64dbg-mcp-server-x64.toml'
    $x32 = Read-TestConfig $x32ConfigPath
    $x64 = Read-TestConfig $x64ConfigPath
    Assert-True ($x32.Port -eq 43132 -and $x64.Port -eq 43164) 'first-install ports are incorrect'
    Assert-True ($x32.Token -ceq $x64.Token -and $x32.Token.Length -ge 32) 'first-install token is not shared and bounded'
    Assert-True (($output -join "`n") -notmatch [regex]::Escape($x32.Token)) 'installer output disclosed the token'
    $firstToken = $x32.Token

    [IO.File]::WriteAllText($serverSource, 'server-v2')
    [IO.File]::WriteAllText($x32Source, 'x32-v2')
    [IO.File]::WriteAllText($x64Source, 'x64-v2')
    & $installer -X64dbgRoot $debugger -PackageRoot $package | Out-Null
    $x32 = Read-TestConfig $x32ConfigPath
    $x64 = Read-TestConfig $x64ConfigPath
    Assert-True ($x32.Token -ceq $firstToken -and $x64.Token -ceq $firstToken) 'idempotent reinstall rotated the token'
    Assert-True ([IO.File]::ReadAllText((Join-Path $serverDirectory 'x64dbg-mcp-server.exe')) -ceq 'server-v2') 'reinstall did not update the sidecar'

    & $installer -X64dbgRoot $debugger -PackageRoot $package -X32Port 44132 -X64Port 44164 | Out-Null
    $x32 = Read-TestConfig $x32ConfigPath
    $x64 = Read-TestConfig $x64ConfigPath
    Assert-True ($x32.Port -eq 44132 -and $x64.Port -eq 44164) 'explicit ports were not installed'
    Assert-True ($x32.Token -ceq $firstToken -and $x64.Token -ceq $firstToken) 'port update rotated the token'

    [IO.File]::Delete($x64ConfigPath)
    & $installer -X64dbgRoot $debugger -PackageRoot $package | Out-Null
    $x32 = Read-TestConfig $x32ConfigPath
    $x64 = Read-TestConfig $x64ConfigPath
    Assert-True ($x32.Port -eq 44132 -and $x64.Port -eq 43164) 'partial repair did not preserve/default ports correctly'
    Assert-True ($x32.Token -ceq $firstToken -and $x64.Token -ceq $firstToken) 'partial repair did not reuse the existing token'

    $mismatchedToken = 'mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm'
    $mismatched = [IO.File]::ReadAllText($x64ConfigPath).Replace($firstToken, $mismatchedToken)
    [IO.File]::WriteAllText($x64ConfigPath, $mismatched)
    [IO.File]::WriteAllText($serverSource, 'server-must-not-copy')
    $mismatchFailed = $false
    try {
        & $installer -X64dbgRoot $debugger -PackageRoot $package | Out-Null
    } catch {
        $mismatchFailed = $_.Exception.Message -match 'tokens differ'
    }
    Assert-True $mismatchFailed 'mismatched installed tokens did not fail closed'
    Assert-True ([IO.File]::ReadAllText((Join-Path $serverDirectory 'x64dbg-mcp-server.exe')) -ceq 'server-v2') 'mismatch failure partially copied binaries'

    & $installer -X64dbgRoot $debugger -PackageRoot $package -RotateToken | Out-Null
    $x32 = Read-TestConfig $x32ConfigPath
    $x64 = Read-TestConfig $x64ConfigPath
    Assert-True ($x32.Token -ceq $x64.Token -and $x32.Token -cne $firstToken) 'explicit rotation did not create one new shared token'
    Assert-True ($x32.Port -eq 44132 -and $x64.Port -eq 43164) 'rotation changed preserved ports'

    $whatIfRoot = Join-Path $testRoot 'whatif-debugger'
    [IO.Directory]::CreateDirectory((Join-Path $whatIfRoot 'release\x32\plugins')) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $whatIfRoot 'release\x64\plugins')) | Out-Null
    & $installer -X64dbgRoot $whatIfRoot -PackageRoot $package -WhatIf | Out-Null
    Assert-True (!(Test-Path -LiteralPath (Join-Path $whatIfRoot 'release\server'))) '-WhatIf wrote the server directory'

    $samePortFailed = $false
    try {
        & $installer -X64dbgRoot $whatIfRoot -PackageRoot $package -X32Port 45000 -X64Port 45000 | Out-Null
    } catch {
        $samePortFailed = $_.Exception.Message -match 'must be distinct'
    }
    Assert-True $samePortFailed 'equal explicit ports were accepted'
    Write-Output 'install contract tests passed'
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
        if (!$resolvedTestRoot.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a test path outside the system temporary directory.'
        }
        [IO.Directory]::Delete($resolvedTestRoot, $true)
    }
}
