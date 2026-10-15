"""Відкриті тести задачі 2.

Запуск: pytest tests/test_lab_02.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 2. Прапорці clone(2)/unshare(2) (ns_flag, combine, decode, order_for_unshare)

ALL = ["user", "mnt", "pid", "uts", "ipc", "net", "cgroup", "time"]
T02_PUBLIC = [
    ("S1", ["uts"], 0x04000000),
    ("S1", ["user", "pid"], 0x30000000),
    ("S1", ["mnt", "pid", "uts"], 0x24020000),
    ("S2", 0x04000000, ["uts"]),
    ("S2", 0x30000000, ["user", "pid"]),
    ("S2", 0x24020000, ["mnt", "pid", "uts"]),
    ("S3", "combine", ["uts"], 0x14000000),
    ("S3", "order", ["uts", "user", "mnt"], ["user", "mnt", "uts"]),
    ("S3", "order", ["pid", "pid", "net"], ["pid", "net"]),
]
T02_HIDDEN = []  # повний набір є лише у викладача
T02 = T02_PUBLIC + T02_HIDDEN


def _expect_error(call, expected):
    with pytest.raises(ValueError) as info:
        call()
    assert str(info.value) == str(expected)


@pytest.mark.parametrize("case", [c for c in T02 if c[0] == "S1"], ids=_ids([c for c in T02 if c[0] == "S1"], "T02"))
def test_combine(case):
    _, names, expected = case
    M = load(2)
    if isinstance(expected, ValueError):
        _expect_error(lambda: M.combine(names), expected)
    else:
        assert M.combine(names) == expected


@pytest.mark.parametrize("case", [c for c in T02 if c[0] == "S2"], ids=_ids([c for c in T02 if c[0] == "S2"], "T02"))
def test_decode(case):
    _, mask, expected = case
    M = load(2)
    if isinstance(expected, ValueError):
        _expect_error(lambda: M.decode(mask), expected)
    else:
        assert M.decode(mask) == expected


@pytest.mark.parametrize("case", [c for c in T02 if c[0] == "S3"], ids=_ids([c for c in T02 if c[0] == "S3"], "T02"))
def test_rootless_and_order(case):
    _, kind, names, expected = case
    M = load(2)
    func = (lambda: M.combine(names, rootless=True)) if kind == "combine" else (lambda: M.order_for_unshare(names))
    if isinstance(expected, ValueError):
        _expect_error(func, expected)
    else:
        assert func() == expected


@pytest.mark.parametrize("name,const", [("uts", "CLONE_NEWUTS"), ("ipc", "CLONE_NEWIPC"), ("net", "CLONE_NEWNET"),
                                        ("pid", "CLONE_NEWPID"), ("user", "CLONE_NEWUSER"), ("mnt", "CLONE_NEWNS"),
                                        ("cgroup", "CLONE_NEWCGROUP"), ("time", "CLONE_NEWTIME")])
def test_matches_python_constants(name, const):
    M = load(2)
    if hasattr(os, const):
        assert M.ns_flag(name) == getattr(os, const)


def test_round_trip():
    M = load(2)
    for mask in range(0, 256):
        names = [n for i, n in enumerate(ALL) if mask >> i & 1]
        assert M.decode(M.combine(names)) == names


