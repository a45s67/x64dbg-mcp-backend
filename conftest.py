"""Opt-in process fixtures; normal pytest runs never launch a debugger."""

import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

import pytest


WORKSPACE = Path(__file__).resolve().parent


def pytest_addoption(parser):
    group = parser.getgroup("x64dbg integration")
    group.addoption("--run-live", action="store_true", help="Run serial real-debugger scenarios")
    group.addoption("--integration-root", help="Prepared isolated x32/x64 runtime trees")
    group.addoption("--server-path", help="Built server executable for real HTTP and live tests")
    group.addoption("--integration-iterations", type=int, default=1, help="Soak iterations per backend (1-20)")
    group.addoption("--x64dbg-root", help="Installed runtime root, required for installed Flare")
    group.addoption("--flare-sample", help="Opt in to installed Flare checksum qualification")
    group.addoption("--report-directory", help="Write per-scenario JSON reports here")


def pytest_configure(config):
    config.addinivalue_line("markers", "live: serial real-debugger integration (requires --run-live)")
    config.addinivalue_line("markers", "installed_flare: optional installed Flare qualification")
    config.addinivalue_line("markers", "server: disconnected real HTTP server integration")
    if not 1 <= config.getoption("integration_iterations") <= 20:
        raise pytest.UsageError("--integration-iterations must be between 1 and 20")
    if config.getoption("run_live"):
        if (config.getoption("numprocesses", default=0) not in (None, 0, "0")
                or hasattr(config, "workerinput") or os.environ.get("PYTEST_XDIST_WORKER")):
            raise pytest.UsageError("--run-live requires serial pytest; xdist workers share debugger trees")
        if os.name != "nt":
            raise pytest.UsageError("--run-live requires Windows and the full x64dbg runtime")
        for option in ("integration_root", "server_path"):
            if not config.getoption(option):
                raise pytest.UsageError(f"--run-live requires --{option.replace('_', '-')}")
    if config.getoption("flare_sample"):
        if not config.getoption("run_live") or not config.getoption("x64dbg_root"):
            raise pytest.UsageError("--flare-sample requires --run-live and --x64dbg-root")
    for option in ("server_path", "flare_sample", "integration_root", "x64dbg_root"):
        value = config.getoption(option)
        if value:
            path = Path(value)
            valid = path.is_file() if option in ("server_path", "flare_sample") else path.is_dir()
            if not valid:
                raise pytest.UsageError(f"--{option.replace('_', '-')} does not exist: {path}")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "live" in item.keywords and not config.getoption("run_live"):
            item.add_marker(pytest.mark.skip(reason="requires --run-live"))
        if "installed_flare" in item.keywords and not config.getoption("flare_sample"):
            item.add_marker(pytest.mark.skip(reason="requires explicit --flare-sample and --x64dbg-root"))


@pytest.fixture(scope="session")
def workspace():
    return WORKSPACE


@pytest.fixture(scope="session")
def server_path(pytestconfig):
    value = pytestconfig.getoption("server_path")
    if not value:
        pytest.skip("requires a built server supplied with --server-path")
    return Path(value).resolve()


@pytest.fixture
def run_live_report(pytestconfig):
    def run(name, script, *arguments):
        # subprocess.run kills its child on Ctrl-C, bypassing PowerShell's finally.
        # Let the inherited console interrupt unwind the wrapper before falling
        # back to terminating only this owned process tree.
        process = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(WORKSPACE / "scripts" / script), *map(str, arguments)],
            cwd=WORKSPACE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
            env={**os.environ, "X64DBG_MCP_TEST_PYTHON": sys.executable},
        )
        try:
            stdout, stderr = process.communicate()
        except KeyboardInterrupt:
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                try:
                    process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    subprocess.run(["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, check=False, timeout=10)
                    process.communicate(timeout=5)
            finally:
                signal.signal(signal.SIGINT, previous)
            raise
        assert process.returncode == 0, (
            f"{name} exited {process.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
        try:
            report = json.loads(stdout.lstrip("\ufeff"))
        except ValueError:
            pytest.fail(f"{name} did not emit a JSON report:\n{stdout}\n{stderr}")
        assert isinstance(report, dict) and report, f"{name} emitted an empty/non-object report"
        directory = pytestconfig.getoption("report_directory")
        if directory:
            destination = Path(directory)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / f"{name}.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
            )
        return report

    return run


@pytest.fixture(scope="session")
def disconnected_server(server_path, tmp_path_factory):
    directory = tmp_path_factory.mktemp("disconnected-server")
    config = directory / "server.toml"
    config.write_text("", encoding="ascii")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    token = secrets.token_hex(32)
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith("X64DBG_MCP_")}
    environment.update(X64DBG_MCP_BIND="127.0.0.1", X64DBG_MCP_PORT=str(port),
                       X64DBG_MCP_TOKEN=token, X64DBG_MCP_MAX_REQUESTS_PER_SECOND="1000")
    base_url = f"http://127.0.0.1:{port}"
    opener = build_opener(ProxyHandler({}))
    with (directory / "server.log").open("w+b") as log:
        process = subprocess.Popen(
            [str(server_path), "--config", str(config)], cwd=directory, env=environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 15
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    with opener.open(base_url + "/health/live", timeout=1) as response:
                        if response.status == 200:
                            break
                except (URLError, TimeoutError):
                    time.sleep(0.05)
            else:
                log.seek(0)
                pytest.fail(f"Server did not listen (exit={process.poll()}):\n"
                            + log.read().decode("utf-8", errors="replace"))
            yield base_url, token
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
