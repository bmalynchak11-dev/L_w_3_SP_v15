"""Відкриті тести задачі 5.

Запуск: pytest tests/test_lab_05.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 5. Простір імен PID (pid_view, probe_kill, parse_nspid, nspid_of_init)

NSPID_TEXT = "Name:\tpython3\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t12345\nPid:\t12345\nPPid:\t1\nNSpid:\t12345\t1\nNSsid:\t5\n"
T05_PUBLIC = [
    ("S1", 0),
    ("S1", 1),
    ("S1", 3),
    ("S2", 1, 0),
    ("S2", "self", errno.ESRCH),
    ("S2", 2, errno.ESRCH),
    ("S3", NSPID_TEXT, [12345, 1]),
    ("S3", "NSpid:\t77\n", [77]),
    ("S3", "Pid:\t5\nNSpid:\t900\t12\t1\n", [900, 12, 1]),
]
T05_HIDDEN = []  # повний набір є лише у викладача
T05 = T05_PUBLIC + T05_HIDDEN


@pytest.mark.parametrize("case", [c for c in T05 if c[0] == "S1"], ids=_ids([c for c in T05 if c[0] == "S1"], "T05"))
@requires_userns
def test_pid_view(case):
    _, children = case
    view = load(5).pid_view(children)
    assert view == {"pid": 1, "ppid": 0, "proc": list(range(1, children + 2))}


@pytest.mark.parametrize("case", [c for c in T05 if c[0] == "S2"], ids=_ids([c for c in T05 if c[0] == "S2"], "T05"))
@requires_userns
def test_probe_kill(case):
    _, target, expected = case
    if target == "self":
        target = os.getpid()
    if target == "parent":
        target = os.getppid()
    if target in (os.getpid(), os.getppid()) and target == 1:
        pytest.skip("тестовий процес сам має номер 1")
    assert load(5).probe_kill(target) == expected


@pytest.mark.parametrize("case", [c for c in T05 if c[0] == "S3"], ids=_ids([c for c in T05 if c[0] == "S3"], "T05"))
def test_parse_nspid(case):
    _, text, expected = case
    M = load(5)
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            M.parse_nspid(text)
        assert str(info.value) == str(expected)
    else:
        assert M.parse_nspid(text) == expected


def test_parse_own_status():
    with open("/proc/self/status", encoding="utf-8") as handle:
        chain = load(5).parse_nspid(handle.read())
    assert chain[-1] == os.getpid()


@requires_userns
def test_nspid_of_init():
    outer, chain = load(5).nspid_of_init()
    assert outer > 1 and outer != os.getpid()
    assert chain[0] == outer
    assert chain[-1] == 1 and len(chain) == 2


def test_no_shortcuts():
    assert_no_shortcuts(5)


