"""Відкриті тести задачі 10.

Запуск: pytest tests/test_lab_10.py. Тут лише приклади з карток варіантів;
повний набір перевірок є у викладача.
Тести, що потребують просторів імен користувача або cgroups v2, пропускаються з поясненням (envcheck.py).
"""
import ast
import errno
import json
import os
import signal
import socket
import sys
from pathlib import Path

import pytest
from conftest import load
from envcheck import USERNS_REASON, cgroup_parent, has_cap_sys_admin, requires_cgroup, requires_userns, userns_ok

PY = sys.executable


def _ids(cases, prefix):
    return [f"{prefix}-{c[0]}-{i}" for i, c in enumerate(cases)]


@pytest.fixture(autouse=True)
def _watchdog():
    """Тест, що завис (наприклад, через незакритий кінець каналу), завершується за 40 с."""
    def boom(signum, frame):
        raise TimeoutError("тест завис довше 40 с: перевірте закриття кінців каналів і waitpid")
    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(40)
    yield
    signal.alarm(0)
    signal.signal(signal.SIGALRM, old)


def fork_json(job):
    """Виконує job() у окремому процесі й повертає його JSON-результат (допоміжна функція тестів)."""
    read_end, write_end = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        try:
            os.write(write_end, json.dumps(job()).encode())
            os._exit(0)
        except BaseException as exc:
            os.write(write_end, json.dumps({"test_error": f"{type(exc).__name__}: {exc}"}).encode())
            os._exit(3)
    os.close(write_end)
    data = b""
    while chunk := os.read(read_end, 65536):
        data += chunk
    os.close(read_end)
    os.waitpid(pid, 0)
    result = json.loads(data.decode())
    assert not (isinstance(result, dict) and "test_error" in result), result.get("test_error")
    return result


def map_ids_here(uid, gid):
    """Відображає користувача uid:gid на root у новому просторі user (допоміжна функція тестів)."""
    for name, text in (("setgroups", "deny"), ("uid_map", f"0 {uid} 1"), ("gid_map", f"0 {gid} 1")):
        with open(f"/proc/self/{name}", "w") as handle:
            handle.write(text)


def open_fds():
    """Кількість відкритих дескрипторів поточного процесу (без дескриптора самого читання каталогу)."""
    return len(os.listdir("/proc/self/fd")) - 1


def assert_no_shortcuts(number):
    """Заборонено готові обгортки: subprocess, os.system, os.popen, os.posix_spawn, pty."""
    source = Path(load(number).__file__).read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            assert not any(a.name.split(".")[0] in ("subprocess", "pty") for a in node.names), "заборонено subprocess"
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in ("subprocess", "pty"), "заборонено subprocess"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
            assert node.attr not in ("system", "popen", "posix_spawn", "posix_spawnp"), "заборонено os.%s" % node.attr


def check(actual, expected):
    if isinstance(expected, Exception):
        raise AssertionError("очікувалася помилка " + repr(expected))
    assert actual == expected


# ---- Задача 10. Міні-контейнер (plan_steps, audit, run_container)

ECHO = {"argv": ["echo", "hi"], "namespaces": ["user", "mnt", "pid", "uts"], "hostname": "kon"}
SAFE = {"namespaces": ["user", "pid", "mnt", "net"], "memory": "64M", "pids": 16, "rootfs": "/srv/r", "readonly_root": True}
CODE = "import os, socket, sys, resource; "


def _py(code):
    return [PY, "-c", code]


T10_PUBLIC = [
    ("S1", ECHO, (1000, 1000),
     [("unshare", "user,mnt,pid,uts"), ("idmap", "1000:1000"), ("hostname", "kon"), ("fork", "init"),
      ("mount", "private /"), ("mount", "proc /proc"), ("exec", "echo hi")]),
    ("S1", {"argv": ["sleep", "5"], "namespaces": []}, (1000, 1000), [("exec", "sleep 5")]),
    ("S1", {"argv": ["python3", "app.py"], "namespaces": ["pid", "user", "mnt"], "memory": "64M", "pids": 16, "nofile": 64},
     (2000, 2000),
     [("cgroup", "memory.max=67108864"), ("cgroup", "pids.max=16"), ("unshare", "user,mnt,pid"), ("idmap", "2000:2000"),
      ("fork", "init"), ("rlimit", "NOFILE=64"), ("mount", "private /"), ("mount", "proc /proc"),
      ("exec", "python3 app.py")]),
    ("S2", SAFE, []),
    ("S2", {}, ["NO_USER_NS", "NO_PID_NS", "NO_MNT_NS", "NET_SHARED", "NO_MEMORY_LIMIT", "NO_PIDS_LIMIT", "NO_ROOTFS"]),
    ("S2", dict(SAFE, readonly_root=False), ["WRITABLE_ROOT"]),
    ("S3", "hostname"),
    ("S3", "pid"),
    ("S3", "exit7"),
]
T10_HIDDEN = []  # повний набір є лише у викладача
T10 = T10_PUBLIC + T10_HIDDEN


@pytest.mark.parametrize("case", [c for c in T10 if c[0] == "S1"], ids=_ids([c for c in T10 if c[0] == "S1"], "T10"))
def test_plan_steps(case):
    _, cfg, ids, expected = case
    M = load(10)
    before = json.dumps(cfg, sort_keys=True)
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            M.plan_steps(cfg, *ids)
        assert str(info.value) == str(expected)
    else:
        assert M.plan_steps(cfg, *ids) == expected
    assert json.dumps(cfg, sort_keys=True) == before          # конфігурацію не змінено


@pytest.mark.parametrize("case", [c for c in T10 if c[0] == "S2"], ids=_ids([c for c in T10 if c[0] == "S2"], "T10"))
def test_audit(case):
    _, cfg, expected = case
    assert load(10).audit(cfg) == expected


def _config(kind):
    base = ["user", "mnt", "pid", "uts"]
    table = {
        "hostname": (dict(argv=_py(CODE + "print(socket.gethostname())"), namespaces=base, hostname="kon"), (0, "kon\n")),
        "pid": (dict(argv=_py(CODE + "print(os.getpid(), len([n for n in os.listdir('/proc') if n.isdigit()]))"),
                     namespaces=base), (0, "1 1\n")),
        "exit7": (dict(argv=_py(CODE + "sys.exit(7)"), namespaces=["user"]), (7, "")),
        "uid": (dict(argv=_py(CODE + "print(os.getuid(), os.getgid())"), namespaces=["user"]), (0, "0 0\n")),
        "nofile": (dict(argv=_py(CODE + "print(resource.getrlimit(resource.RLIMIT_NOFILE))"), namespaces=["user"],
                        nofile=64), (0, "(64, 64)\n")),
        "sigkill": (dict(argv=_py(CODE + "import signal; os.kill(os.getpid(), signal.SIGKILL)"), namespaces=["user"]), (137, "")),
        "sigterm": (dict(argv=_py(CODE + "import signal; os.kill(os.getpid(), signal.SIGTERM)"), namespaces=["user"]), (143, "")),
        "net": (dict(argv=_py(CODE + "print(socket.if_nameindex())"), namespaces=["user", "net"]), (0, "[(1, 'lo')]\n")),
        "multiline": (dict(argv=_py(CODE + "print('перший'); print('другий'); sys.stdout.flush()"), namespaces=["user", "uts"],
                           hostname="x"), (0, "перший\nдругий\n")),
        "missing": (dict(argv=["/немає/такої/програми"], namespaces=["user"]), (125, "")),
    }
    return table[kind]


@pytest.mark.parametrize("case", [c for c in T10 if c[0] == "S3"], ids=_ids([c for c in T10 if c[0] == "S3"], "T10"))
@requires_userns
def test_run_container(case):
    _, kind = case
    M = load(10)
    if kind == "invalid":
        with pytest.raises(ValueError) as info:
            M.run_container({"argv": ["x"], "namespaces": ["user", "pid"]})
        assert str(info.value) == "Простір pid потребує mnt"
    elif kind == "host":
        before = socket.gethostname()
        M.run_container(_config("hostname")[0])
        assert socket.gethostname() == before
        assert os.getpid() != 1 and len(os.listdir("/proc")) > 5
    else:
        cfg, expected = _config(kind)
        assert M.run_container(cfg) == expected


def test_no_shortcuts():
    assert_no_shortcuts(10)
