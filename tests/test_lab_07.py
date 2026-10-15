"""Відкриті тести задачі 7.

Запуск: pytest tests/test_lab_07.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 7. Кореневий каталог і chroot(2) (plan_rootfs, safe_join, resolve_in_root, build_rootfs, enter_root)

T07_PUBLIC = [
    ("S1", ["/bin/", "/etc/hostname"], [("dir", "/bin"), ("dir", "/etc"), ("file", "/etc/hostname")]),
    ("S1", ["/usr/lib/libc.so"], [("dir", "/usr"), ("dir", "/usr/lib"), ("file", "/usr/lib/libc.so")]),
    ("S1", [], []),
    ("S2", "join", "/srv/r", "etc/passwd", "/srv/r/etc/passwd"),
    ("S2", "join", "/srv/r", "/etc/passwd", "/srv/r/etc/passwd"),
    ("S2", "join", "/srv/r", "../../etc/passwd", "/srv/r/etc/passwd"),
    ("S3", "build", ["/bin/", "/etc/hostname"], 3),
    ("S3", "enter", ["/etc/os-release", "/bin/", "/tmp/"], (["bin", "etc", "tmp"], False)),
    ("S3", "enter", ["/etc/passwd", "/home/"], (["etc", "home"], True)),
]
T07_HIDDEN = []  # повний набір є лише у викладача
T07 = T07_PUBLIC + T07_HIDDEN


@pytest.mark.parametrize("case", [c for c in T07 if c[0] == "S1"], ids=_ids([c for c in T07 if c[0] == "S1"], "T07"))
def test_plan_rootfs(case):
    _, spec, expected = case
    M = load(7)
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            M.plan_rootfs(spec)
        assert str(info.value) == str(expected)
    else:
        assert M.plan_rootfs(spec) == expected


@pytest.fixture()
def tree(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "dir").mkdir()
    (root / "etc" / "hostname").write_text("kontejner\n")
    (root / "etc" / "passwd").write_text("root:x:0:0\n")
    os.symlink("/etc", root / "lnk")
    os.symlink("etc", root / "rel")
    os.symlink("../../..", root / "up")
    os.symlink("loop", root / "loop")
    os.symlink("chain2", root / "chain1")
    os.symlink("/etc/hostname", root / "chain2")
    os.symlink("..", root / "dir" / "back")
    os.symlink("/etc/passwd", root / "host")
    return str(root)


@pytest.mark.parametrize("case", [c for c in T07 if c[0] == "S2"], ids=_ids([c for c in T07 if c[0] == "S2"], "T07"))
def test_safe_paths(case, tree):
    M = load(7)
    if case[1] == "join":
        _, _, root, path, expected = case
        assert M.safe_join(root, path) == expected
        return
    _, _, path, expected = case
    if isinstance(expected, OSError):
        with pytest.raises(OSError) as info:
            M.resolve_in_root(tree, path)
        assert info.value.errno == errno.ELOOP
    else:
        assert M.resolve_in_root(tree, path) == expected.format(R=tree)


@pytest.mark.parametrize("case", [c for c in T07 if c[0] == "S3"], ids=_ids([c for c in T07 if c[0] == "S3"], "T07"))
def test_rootfs_build_and_enter(case, tmp_path):
    M = load(7)
    kind, spec, expected = case[1], case[2], case[3]
    root = tmp_path / "rootfs"
    root.mkdir()
    if kind == "missing":
        listing_before = sorted(os.listdir("/"))
        if not userns_ok():
            pytest.skip(USERNS_REASON)
        with pytest.raises(RuntimeError):
            M.enter_root(str(tmp_path / "немає"))
        assert sorted(os.listdir("/")) == listing_before
        return
    if kind == "build":
        assert M.build_rootfs(str(root), spec) == expected
        for item_kind, path in M.plan_rootfs(spec):
            full = root / path.lstrip("/")
            assert (full.is_dir() if item_kind == "dir" else full.is_file()), path
        assert M.build_rootfs(str(root), spec) == expected         # повторний виклик нічого не ламає
        return
    if not userns_ok():
        pytest.skip(USERNS_REASON)
    M.build_rootfs(str(root), spec)
    cwd, listing_before = os.getcwd(), sorted(os.listdir("/"))
    assert M.enter_root(str(root)) == expected
    assert os.getcwd() == cwd and sorted(os.listdir("/")) == listing_before


def test_build_keeps_existing_content(tmp_path):
    M = load(7)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hostname").write_text("старе\n")
    M.build_rootfs(str(tmp_path), ["/etc/hostname", "/bin/"])
    assert (tmp_path / "etc" / "hostname").read_text() == "старе\n"


def test_no_shortcuts():
    assert_no_shortcuts(7)


