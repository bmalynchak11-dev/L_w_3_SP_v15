"""Відкриті тести задачі 4.

Запуск: pytest tests/test_lab_04.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 4. unshare(2) через ctypes (unshare, uts_demo, ns_changed)

T04_PUBLIC = [
    ("S1", 0, None),
    ("S1", 1, errno.EINVAL),
    ("S1", 0x7F, errno.EINVAL),
    ("S2", "kontejner"),
    ("S2", "lab03"),
    ("S2", "a"),
    ("S3", ["uts"], {"uts": True}),
    ("S3", ["uts", "ipc"], {"uts": True, "ipc": True}),
    ("S3", ["mnt"], {"mnt": True}),
]
T04_HIDDEN = []  # повний набір є лише у викладача
T04 = T04_PUBLIC + T04_HIDDEN


@pytest.mark.parametrize("case", [c for c in T04 if c[0] == "S1"], ids=_ids([c for c in T04 if c[0] == "S1"], "T04"))
def test_unshare_errors(case):
    _, flags, expected = case
    M = load(4)
    if expected is None:
        assert M.unshare(flags) is None
    else:
        with pytest.raises(OSError) as info:
            M.unshare(flags)
        assert info.value.errno == expected
        assert info.value.strerror == os.strerror(expected)


@pytest.mark.skipif(os.geteuid() == 0 or has_cap_sys_admin(), reason="процес має права адміністратора, помилки EPERM не буде")
def test_unshare_without_user_namespace_is_denied():
    M = load(4)
    flags = 0x04000000      # CLONE_NEWUTS без попереднього CLONE_NEWUSER

    def job():
        try:
            M.unshare(flags)
        except OSError as exc:
            return exc.errno
        return 0

    assert fork_json(job) == errno.EPERM


@pytest.mark.parametrize("case", [c for c in T04 if c[0] == "S2"], ids=_ids([c for c in T04 if c[0] == "S2"], "T04"))
@requires_userns
def test_uts_demo(case):
    _, hostname = case
    M = load(4)
    before = socket.gethostname()
    inside, outside = M.uts_demo(hostname)
    assert inside == hostname
    assert outside == before
    assert socket.gethostname() == before


@pytest.mark.parametrize("case", [c for c in T04 if c[0] == "S3"], ids=_ids([c for c in T04 if c[0] == "S3"], "T04"))
@requires_userns
def test_ns_changed(case):
    _, kinds, expected = case
    M = load(4)
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            M.ns_changed(kinds)
        assert str(info.value) == str(expected)
    else:
        result = M.ns_changed(kinds)
        assert result == expected
        assert list(result) == list(kinds)


def test_no_shortcuts_and_ctypes():
    assert_no_shortcuts(4)
    source = Path(load(4).__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert "ctypes" in imported, "unshare(2) має викликатися через ctypes і libc"
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
            assert node.attr != "unshare", "у цій задачі os.unshare заборонено: викликайте libc.unshare через ctypes"


