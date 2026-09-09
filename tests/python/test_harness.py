import json
import subprocess
import sys
from types import SimpleNamespace

import pytest


def test_live_wrapper_uses_same_interpreter(monkeypatch, run_live_report):
    launched = []

    def launch(command, **kwargs):
        launched.append((command, kwargs))
        return SimpleNamespace(returncode=0, communicate=lambda: (json.dumps({"passed": True}), ""))

    monkeypatch.setattr(subprocess, "Popen", launch)
    assert run_live_report("fake", "never-run.ps1") == {"passed": True}
    assert launched[0][1]["env"]["X64DBG_MCP_TEST_PYTHON"] == sys.executable


@pytest.mark.parametrize("hangs", [False, True])
def test_interrupted_wrapper_gets_cleanup_grace_before_owned_tree_fallback(monkeypatch, run_live_report, hangs):
    waits = []
    killed = []

    def communicate(timeout=None):
        waits.append(timeout)
        if timeout is None:
            raise KeyboardInterrupt
        if hangs and timeout == 30:
            raise subprocess.TimeoutExpired("owned-wrapper", timeout)
        return "", ""

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs:
                        SimpleNamespace(pid=123, communicate=communicate))
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: killed.append(command))
    with pytest.raises(KeyboardInterrupt):
        run_live_report("fake", "never-run.ps1")
    assert waits == ([None, 30, 5] if hangs else [None, 30])
    assert killed == ([["taskkill.exe", "/PID", "123", "/T", "/F"]] if hangs else [])
