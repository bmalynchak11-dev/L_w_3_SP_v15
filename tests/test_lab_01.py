"""Відкриті тести задачі 1.

Запуск: pytest tests/test_lab_01.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 1. Простори імен процесу в /proc (parse_ns_link, read_namespaces, differing)

T01_PUBLIC = [
    ("S1", "uts:[4026531838]", ("uts", 4026531838)),
    ("S1", "pid:[4026531836]", ("pid", 4026531836)),
    ("S1", "mnt:[4026532500]", ("mnt", 4026532500)),
    ("S2", {"uts": "uts:[4026531838]", "pid": "pid:[4026531836]"}, {"pid": 4026531836, "uts": 4026531838}),
    ("S2", {"pid": "pid:[10]", "pid_for_children": "pid:[11]"}, {"pid": 10, "pid_for_children": 11}),
    ("S2", {"uts": "uts:[7]", "junk": "not-a-namespace"}, {"uts": 7}),
    ("S3", {"uts": 1, "pid": 2}, {"uts": 1, "pid": 3}, ["pid"]),
    ("S3", {"uts": 1}, {"uts": 1}, []),
    ("S3", {"user": 5, "mnt": 6, "uts": 7}, {"user": 50, "mnt": 6, "uts": 70}, ["user", "uts"]),
]
T01_HIDDEN = []  # повний набір є лише у викладача
T01 = T01_PUBLIC + T01_HIDDEN


@pytest.mark.parametrize("case", [c for c in T01 if c[0] == "S1"], ids=_ids([c for c in T01 if c[0] == "S1"], "T01"))
def test_parse_ns_link(case):
    _, link, expected = case
    M = load(1)
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            M.parse_ns_link(link)
        assert str(info.value) == str(expected)
    else:
        assert M.parse_ns_link(link) == expected


@pytest.mark.parametrize("case", [c for c in T01 if c[0] == "S2"], ids=_ids([c for c in T01 if c[0] == "S2"], "T01"))
def test_read_namespaces(case, tmp_path):
    _, links, expected = case
    M = load(1)
    if links is not None:
        ns_dir = tmp_path / "ns"
        ns_dir.mkdir()
        for name, target in links.items():
            os.symlink(target, ns_dir / name)
    if isinstance(expected, Exception):
        with pytest.raises(FileNotFoundError):
            M.read_namespaces(str(tmp_path))
    else:
        result = M.read_namespaces(str(tmp_path))
        assert result == expected
        assert list(result) == sorted(expected)


@pytest.mark.parametrize("case", [c for c in T01 if c[0] == "S3"], ids=_ids([c for c in T01 if c[0] == "S3"], "T01"))
def test_differing(case):
    _, first, second, expected = case
    M = load(1)
    copy_first, copy_second = dict(first), dict(second)
    assert M.differing(first, second) == expected
    assert first == copy_first and second == copy_second


def test_read_own_namespaces():
    M = load(1)
    result = M.read_namespaces("/proc/self")
    for kind in ("mnt", "net", "pid", "uts", "user", "ipc"):
        assert kind in result and result[kind] > 0
    assert result == M.read_namespaces("/proc/self")
    assert M.differing(result, result) == []


@requires_userns
def test_live_differing():
    M = load(1)
    mine = M.read_namespaces("/proc/self")

    uid, gid = os.getuid(), os.getgid()

    def job():
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWUTS)
        map_ids_here(uid, gid)
        return M.read_namespaces("/proc/self")

    theirs = fork_json(job)
    assert M.differing(mine, theirs) == ["user", "uts"]


