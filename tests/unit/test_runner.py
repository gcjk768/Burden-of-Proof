import sys
from pathlib import Path

import pytest

from bop.runner import local
from bop.runner.base import sandbox_env
from bop.runner.jail import privilege_state, privileges_dropped
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


@needs_namespaces
def test_host_files_outside_the_snapshot_are_invisible(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (tmp_path / "secret.env").write_text("NEBIUS_API_KEY=sk-should-not-leak")
    readme = Path(__file__).resolve().parents[2] / "README.md"
    for target in (tmp_path / "secret.env", readme):
        result = runner.run(["cat", str(target)], cwd=work, timeout_s=30)
        assert result.exit_code != 0 and "sk-should-not-leak" not in result.stdout, target


@needs_namespaces
def test_home_is_empty_and_snapshot_writable_and_system_read_only(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    script = (
        "import os\n"
        "print('home', os.listdir(os.environ['HOME']))\n"
        "open('out.txt', 'w').write('ok')\n"
        "try:\n    open('/usr/bop-probe', 'w')\n    print('usr writable')\n"
        "except OSError:\n    print('usr read-only')\n"
    )
    result = runner.run([sys.executable, "-c", script], cwd=work, timeout_s=30)
    assert "home []" in result.stdout and "usr read-only" in result.stdout, result.stdout + result.stderr
    assert (work / "out.txt").read_text() == "ok"


@needs_namespaces
def test_declared_paths_are_visible(tmp_path):
    work, extra, out = tmp_path / "work", tmp_path / "rules", tmp_path / "out"
    for d in (work, extra, out):
        d.mkdir()
    (extra / "rules.yaml").write_text("rules: []")
    result = runner.run(
        ["sh", "-c", f"cat {extra}/rules.yaml && echo hi > {out}/x && (echo no > {extra}/y 2>/dev/null || echo ro)"],
        cwd=work,
        timeout_s=30,
        readable=[extra],
        writable=[out],
    )
    assert "rules: []" in result.stdout and "ro" in result.stdout, result.stdout + result.stderr
    assert (out / "x").read_text().strip() == "hi"


@needs_namespaces
def test_loopback_works_without_network(tmp_path):
    probe = (
        "import socket\ns = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(1)\n"
        "socket.create_connection(s.getsockname(), timeout=3); print('LOOPBACK OK')\n"
    )
    result = runner.run([sys.executable, "-c", probe], cwd=tmp_path, timeout_s=30, network=False)
    assert "LOOPBACK OK" in result.stdout, result.stdout + result.stderr


def test_privilege_state_parsing():
    status = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
    status += "CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
    assert privileges_dropped(privilege_state(status))
    assert not privileges_dropped(privilege_state(status.replace("CapBnd:\t0000000000000000", "CapBnd:\t000001ff")))
    assert not privileges_dropped(privilege_state(status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")))
    assert not privileges_dropped(privilege_state("Name:\tx\n"))


@needs_namespaces
def test_command_has_no_capabilities_and_only_loopback(tmp_path):
    status = runner.run(["cat", "/proc/self/status"], cwd=tmp_path, timeout_s=30)
    assert privileges_dropped(privilege_state(status.stdout)), status.stdout
    interfaces = runner.run(["cat", "/proc/net/dev"], cwd=tmp_path, timeout_s=30, network=False)
    names = [line.split(":")[0].strip() for line in interfaces.stdout.splitlines()[2:]]
    assert names == ["lo"], interfaces.stdout


# The classic break-out: chroot into a subdirectory, climb out with "..", chroot again.
ESCAPE = """
import os
{prelude}
os.makedirs('/tmp/esc', exist_ok=True)
os.chroot('/tmp/esc')
for _ in range(64):
    os.chdir('..')
os.chroot('.')
print(open({secret!r}).read())
"""


@needs_namespaces
@pytest.mark.parametrize(
    "prelude",
    [
        "",  # directly: chroot needs a capability the command no longer has
        "os.unshare(os.CLONE_NEWUSER)\nos.unshare(os.CLONE_NEWNS)",  # full capabilities again, in a nested namespace
    ],
)
def test_chroot_escape_cannot_reach_host_files(tmp_path, prelude):
    work = tmp_path / "work"
    work.mkdir()
    secret = tmp_path / "host-secret.txt"
    secret.write_text("HOST-SECRET")
    result = runner.run(
        [sys.executable, "-c", ESCAPE.format(prelude=prelude, secret=str(secret))], cwd=work, timeout_s=30
    )
    assert "HOST-SECRET" not in result.stdout
    assert result.exit_code != 0


@needs_namespaces
def test_read_only_paths_cannot_be_remounted_writable(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    shared = tmp_path / "shared"
    shared.mkdir()
    probe = (
        "import ctypes, os\n"
        "os.unshare(os.CLONE_NEWUSER)\nos.unshare(os.CLONE_NEWNS)\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        f"print('remount', libc.mount(None, {str(shared)!r}.encode(), None, 4096 | 32 | 16384, None))\n"
        f"open({str(shared / 'planted')!r}, 'w').write('x')\n"
    )
    result = runner.run([sys.executable, "-c", probe], cwd=work, timeout_s=30, readable=[shared])
    assert "remount -1" in result.stdout, result.stdout + result.stderr
    assert not (shared / "planted").exists()


def test_link_targets_follow_symlinked_config_outside_system_paths(tmp_path):
    real = tmp_path / "run" / "stub-resolv.conf"
    real.parent.mkdir()
    real.write_text("nameserver 127.0.0.53\n")
    link = tmp_path / "etc" / "resolv.conf"
    link.parent.mkdir()
    link.symlink_to(real)
    plain = tmp_path / "etc" / "hosts"
    plain.write_text("127.0.0.1 localhost\n")
    to_proc = tmp_path / "etc" / "mtab"
    to_proc.symlink_to("/proc/self/mounts")
    assert local.link_targets([str(link), str(plain), str(to_proc), str(tmp_path / "missing")]) == [str(real)]


@needs_namespaces
def test_symlinked_resolv_conf_is_readable_in_the_sandbox(tmp_path, monkeypatch):
    # The systemd-resolved layout: /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf
    real = tmp_path / "run" / "stub-resolv.conf"
    real.parent.mkdir()
    real.write_text("nameserver 127.0.0.53\n")
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "resolv.conf").symlink_to(real)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(local, "HOST_CONFIG_FILES", (str(etc / "resolv.conf"),))
    result = runner.run(["cat", str(etc / "resolv.conf")], cwd=work, timeout_s=30, network=True, readable=[etc])
    assert "nameserver 127.0.0.53" in result.stdout, result.stderr


@needs_namespaces
def test_proxy_credentials_reach_the_command_but_not_its_argv(tmp_path):
    secret = "http://alice:S3cretProxyPass@proxy.example:3128"
    spec = runner._spec(["true"], tmp_path, True, {"HTTPS_PROXY": secret, "HOME": "/root"}, [], [], str(tmp_path))
    assert secret not in " ".join(runner._command(spec, True))
    result = runner.run(
        ["sh", "-c", 'echo "$HTTPS_PROXY"'], cwd=tmp_path, timeout_s=30, network=True, env={"HTTPS_PROXY": secret}
    )
    assert secret in result.stdout
