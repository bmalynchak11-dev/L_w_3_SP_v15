"""Відкриті тести задачі 3.

Запуск: pytest tests/test_lab_03.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 3. Відображення ідентифікаторів користувача (id_map_lines, parse_id_map, to_outside, to_inside)

MAPPING = [(0, 1000, 1), (1, 100000, 65536)]
T03_PUBLIC = [
    ("S1", (1000, 1000), {"setgroups": "deny", "uid_map": "0 1000 1", "gid_map": "0 1000 1"}),
    ("S1", (1001, 100), {"setgroups": "deny", "uid_map": "0 1001 1", "gid_map": "0 100 1"}),
    ("S1", (1000, 1000, 1000, 1000), {"setgroups": "deny", "uid_map": "1000 1000 1", "gid_map": "1000 1000 1"}),
    ("S2", "         0       1000          1\n", [(0, 1000, 1)]),
    ("S2", "0 100000 65536\n", [(0, 100000, 65536)]),
    ("S2", "0 1000 1\n1 100000 65536\n", MAPPING),
    ("S3", "out", MAPPING, 0, 1000),
    ("S3", "out", MAPPING, 5, 100004),
    ("S3", "in", MAPPING, 1000, 0),
]
T03_HIDDEN = []  # повний набір є лише у викладача
T03 = T03_PUBLIC + T03_HIDDEN


@pytest.mark.parametrize("case", [c for c in T03 if c[0] == "S1"], ids=_ids([c for c in T03 if c[0] == "S1"], "T03"))
def test_id_map_lines(case):
    _, args, expected = case
    result = load(3).id_map_lines(*args)
    assert result == expected
    assert list(result) == ["setgroups", "uid_map", "gid_map"]      # setgroups записують першим


@pytest.mark.parametrize("case", [c for c in T03 if c[0] == "S2"], ids=_ids([c for c in T03 if c[0] == "S2"], "T03"))
def test_parse_id_map(case):
    _, text, expected = case
    M = load(3)
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            M.parse_id_map(text)
        assert str(info.value) == str(expected)
    else:
        assert M.parse_id_map(text) == expected


@pytest.mark.parametrize("case", [c for c in T03 if c[0] == "S3"], ids=_ids([c for c in T03 if c[0] == "S3"], "T03"))
def test_translate(case):
    _, direction, mapping, value, expected = case
    M = load(3)
    func = M.to_outside if direction == "out" else M.to_inside
    assert func(mapping, value) == expected


@requires_userns
def test_own_map_after_unshare():
    assert load(3).own_map_after_unshare() == [(0, os.getuid(), 1)]


