# Shared by the test wrappers; this is not a runtime dependency of the server.
function Get-TestPython {
    $arguments = @()
    if (![string]::IsNullOrWhiteSpace($env:X64DBG_MCP_TEST_PYTHON)) {
        $executable = (Get-Command $env:X64DBG_MCP_TEST_PYTHON -ErrorAction Stop).Source
    } elseif ($env:VIRTUAL_ENV -and (Test-Path -LiteralPath (Join-Path $env:VIRTUAL_ENV 'Scripts\python.exe'))) {
        $executable = Join-Path $env:VIRTUAL_ENV 'Scripts\python.exe'
    } else {
        $launcher = Get-Command py -ErrorAction SilentlyContinue
        if ($launcher) {
            $executable = $launcher.Source
            $arguments = @('-3')
        } else {
            $executable = (Get-Command python -ErrorAction Stop).Source
        }
    }
    $version = & $executable @arguments -c 'import sys; print(sys.version_info >= (3, 11))'
    if ($LASTEXITCODE -ne 0 -or $version -cne 'True') {
        throw 'Python 3.11+ is required. Set X64DBG_MCP_TEST_PYTHON to its executable path.'
    }
    return @{ Source = $executable; Arguments = $arguments }
}
