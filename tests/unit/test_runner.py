import sys

import pytest

from bop.runner.base import sandbox_env
from bop.runner.local import LocalNamespaceRunner

SECRETS = {
    "NEBIUS_API_KEY": "k",
    "TAVILY_API_KEY": "t",
    "GITLAB_TOKEN": "g",
    "AWS_SECRET_ACCESS_KEY": "a",
    "PATH": "/usr/bin",
    "HOME": "/root",
    "HTTPS_PROXY": "http://proxy:1",
}


def test_sandbox_env_drops_secrets_and_proxies_offline():
    env = sandbox_env(network=False, source=SECRETS)
    assert set(env) == {"PATH", "HOME", "LANG"}
    online = sandbox_env(network=True, source=SECRETS)
    assert online["HTTPS_PROXY"] == "http://proxy:1" and "NEBIUS_API_KEY" not in online


runner = LocalNamespaceRunner()
needs_namespaces = pytest.mark.skipif(not runner.available()[0], reason="user namespaces unavailable")


@needs_namespaces
def test_network_is_cut(tmp_path):
    probe = (
        "import socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), timeout=3)\n    print('CONNECTED')\n"
        "except OSError as e:\n    print('BLOCKED', e)\n"
    )
    result = runner.run([sys.executable, "-c", probe], cwd=tmp_path, timeout_s=30, network=False)
    assert "BLOCKED" in result.stdout, result.stdout + result.stderr


@needs_namespaces
def test_secrets_do_not_reach_the_command(tmp_path, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "must-not-leak")
    result = runner.run(["env"], cwd=tmp_path, timeout_s=30)
    assert "must-not-leak" not in result.stdout


@needs_namespaces
def test_timeout_kills_the_command(tmp_path):
    result = runner.run([sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout_s=2)
    assert result.timed_out and not result.ok and result.duration_s < 15
