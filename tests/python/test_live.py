"""Pytest entry points for the PowerShell-owned runtime lifecycle."""

from pathlib import Path

import pytest


pytestmark = pytest.mark.live


@pytest.mark.parametrize("backend", ["x32", "x64"])
@pytest.mark.parametrize("scenario", ["real", "attach", "generic"])
def test_live_scenario(backend, scenario, pytestconfig, workspace, server_path, run_live_report):
    arguments = ["-Backend", backend, "-IntegrationRoot",
                 Path(pytestconfig.getoption("integration_root")).absolute(), "-ServerPath", server_path]
    if scenario == "real":
        script = "run-integration-soak.ps1"
        arguments += ["-Iterations", pytestconfig.getoption("integration_iterations")]
    elif scenario == "attach":
        script = "run-attach-integration.ps1"
    else:
        script = "run-generic-sample-smoke.ps1"
        architecture = "x86" if backend == "x32" else "x64"
        sample = workspace / "build" / f"windows-{architecture}" / "x64dbg_mcp_debuggee_fixture.exe"
        assert sample.is_file(), f"Build the {architecture} native fixtures first: {sample}"
        arguments += ["-SamplePath", sample]
    report = run_live_report(f"{scenario}-{backend}", script, *arguments)
    if scenario == "real":
        assert report["iterations"] == pytestconfig.getoption("integration_iterations")
        assert report["backends"] == backend
        assert report["runs"] == report["iterations"] == len(report["reports"])
        assert report["all_owned_sidecars_exited"] is True
        assert report["all_loopback_ports_closed"] is True
        assert all(run["stop_state"] == "absent" for run in report["reports"])
    else:
        assert report["backend"] == backend
        if scenario == "attach":
            assert report["fixture_survived_detach"] is True
            assert report["detached_state"] == "absent"
        else:
            assert report["endpoint_parent_verified"] is True
            assert report["stopped"] is True


@pytest.mark.installed_flare
def test_installed_flare(pytestconfig, run_live_report):
    report = run_live_report(
        "installed-flare", "run-flare-checksum-smoke.ps1",
        "-X64dbgRoot", Path(pytestconfig.getoption("x64dbg_root")).absolute(),
        "-SamplePath", Path(pytestconfig.getoption("flare_sample")).absolute(),
    )
    assert report["stopped"] is True
    assert report["endpoint_parent_verified"] is True
    assert report["owned_debugger_exited"] is True
    assert report["owned_sidecar_exited"] is True
    assert report["loopback_port_closed"] is True
    assert report["sample_unchanged"] is True
    assert report["sample_sha256_before"] == report["sample_sha256_after"]
