"""Offline safety regressions: never copy/install a runtime or launch a debugger."""

import json
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest

import test_live as live


WORKSPACE = Path(__file__).resolve().parents[2]
SCRIPTS = WORKSPACE / "scripts"
SMOKE = SCRIPTS / "run-flare-checksum-smoke.ps1"
QUALIFICATION = SCRIPTS / "run-flare-qualification.ps1"


@pytest.mark.parametrize("script", [SMOKE, QUALIFICATION])
def test_powershell_parses_without_executing(script):
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell parser required")
    command = (
        "$tokens = $null; $errors = $null; "
        "[void][Management.Automation.Language.Parser]::ParseFile("
        f"'{str(script).replace(chr(39), chr(39) * 2)}', [ref]$tokens, [ref]$errors); "
        "if ($errors.Count) { $errors | ForEach-Object { $_.Message }; exit 1 }"
    )
    result = subprocess.run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("final_newline", [False, True])
def test_installed_config_regex_accepts_installer_line_endings(newline, final_newline):
    script = SMOKE.read_text(encoding="utf-8")
    config = newline.join(['bind = "127.0.0.1"', 'port = 54321', 'bearer_token = "offline-placeholder"'])
    if final_newline:
        config += newline
    for name, expected in (("port", "54321"), ("token", "offline-placeholder"), ("bind", None)):
        pattern = re.search(rf"\${name}Match = \[regex\]::Match\(\$config, '([^']+)'\)", script)[1]
        match = re.search(pattern, config)
        assert match is not None
        if expected:
            assert match[1] == expected


def test_existing_x64_host_guard_never_reaches_runtime_or_python():
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell required")
    # No -Backend: the installed Flare wrapper is unconditionally x64.
    command = r"""
function Get-Process {
    param([string[]]$Name, $ErrorAction)
    if ('x64dbg' -notin $Name -or 'x64dbg-unsigned' -notin $Name) { throw 'wrong guard' }
    [pscustomobject]@{ Id = 123; ProcessName = 'x64dbg' }
}
function Resolve-Path { throw 'must not access runtime' }
function Get-Content { throw 'must not read credentials' }
function Get-TestPython { throw 'must not start Python' }
try {
    & '__SCRIPT__' -X64dbgRoot 'Z:\nonexistent-offline-runtime' -SamplePath 'Z:\never-run.exe'
    throw 'guard did not reject'
} catch {
    if ($_.Exception.Message -ne 'An x64 debugger is already running. Close it before installed Flare qualification.') {
        throw
    }
    'guard rejected before runtime access'
}
""".replace("__SCRIPT__", str(SMOKE).replace("'", "''"))
    result = subprocess.run([powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "guard rejected before runtime access" in result.stdout


def test_qualification_safety_wiring():
    script = QUALIFICATION.read_text(encoding="utf-8")
    assert "[ValidateRange(1, 20)]" in script and "[int]$Iterations = 3" in script
    assert "$python = Get-TestPython" in script
    assert "OutputDirectory already exists; use a fresh directory." in script
    assert "Assert-FlareTree $release" in script
    assert "'userdir', 'qt.conf'" in script
    installer = re.search(r"& \(Join-Path \$PSScriptRoot 'install.ps1'\)[\s\S]+?\| ([^\n]+)", script)
    assert installer and installer[1].strip() == "Out-Null"
    assert len(re.findall(r"^    @\('(?:mcp|x32|x64)\\", script, re.M)) == 4
    assert "--run-live" in script and "'installed_flare'" in script
    assert "'--integration-root', $release" in script
    assert "'--x64dbg-root', $runtimeForLaunch" in script
    assert "'--flare-sample', $stagedSample" in script
    assert "'--junitxml'" in script and "'iteration-{0:d2}'" in script
    assert "X64DBG_MCP_TEST_PYTHON" in script
    assert "[Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')" in script


def test_smoke_authenticates_only_after_ownership_and_reports_only_after_cleanup():
    script = SMOKE.read_text(encoding="utf-8")
    assert script.index("$_.ParentProcessId -eq $debuggerProcess.Id") < script.index("Invoke-RestMethod")
    assert "$startInfo.EnvironmentVariables.Remove($name)" in script
    assert script.index("$env:X64DBG_MCP_TOKEN = $token") > script.index("[System.Diagnostics.Process]::Start")
    assert script.index("if (!$cleanupConfirmed -or !$report)") < script.index("$report | ConvertTo-Json")
    assert "$sidecarProcess.Kill()" in script
    assert "$debuggerProcess.Kill()" in script
    assert "Stop-Process" not in script  # Cleanup uses held process handles, not bare reusable PIDs.


@pytest.mark.parametrize("missing", [None, "stopped", "endpoint_parent_verified", "owned_debugger_exited",
                                    "owned_sidecar_exited", "loopback_port_closed", "sample_unchanged",
                                    "sample_sha256_after"])
def test_installed_flare_requires_cleanup_and_unchanged_sample(missing):
    report = dict.fromkeys(("stopped", "endpoint_parent_verified", "owned_debugger_exited",
                            "owned_sidecar_exited", "loopback_port_closed", "sample_unchanged"), True)
    report.update(sample_sha256_before="abc", sample_sha256_after="abc")
    if missing:
        report[missing] = False
    config = SimpleNamespace(getoption=lambda option: "offline-unused-path")
    calls = []

    def fake_report(*arguments):
        calls.append(arguments)
        return json.loads(json.dumps(report))

    if missing:
        with pytest.raises(AssertionError):
            live.test_installed_flare(config, fake_report)
    else:
        live.test_installed_flare(config, fake_report)
    assert "-Backend" not in calls[0]
