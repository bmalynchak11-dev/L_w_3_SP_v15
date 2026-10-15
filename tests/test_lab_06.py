"""Відкриті тести задачі 6.

Запуск: pytest tests/test_lab_06.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 6. Простір імен монтування (parse_mountinfo, is_mount_point, private_tmpfs, tmpfs_capacity, readonly_errno)

MI_EXT3 = "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue"
MI_ROOT = "44 1 259:5 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p5 rw"
MI_TMP = "52 44 0:40 / /tmp/a\\040b rw,nosuid,nodev - tmpfs tmpfs rw,size=1024k"
MI_PROC = "30 22 0:25 / /proc rw,nosuid,nodev,noexec,relatime shared:5 master:2 - proc proc rw"
MI_LABEL = "61 44 8:1 /my\\040dir /mnt/disk ro - vfat /dev/disk/by-label/My\\040Disk ro"
E_EXT3 = {"id": 36, "parent": 35, "root": "/mnt1", "mount_point": "/mnt2", "options": ["rw", "noatime"],
          "fstype": "ext3", "source": "/dev/root"}
E_ROOT = {"id": 44, "parent": 1, "root": "/", "mount_point": "/", "options": ["rw", "relatime"],
          "fstype": "ext4", "source": "/dev/nvme0n1p5"}
E_TMP = {"id": 52, "parent": 44, "root": "/", "mount_point": "/tmp/a b", "options": ["rw", "nosuid", "nodev"],
         "fstype": "tmpfs", "source": "tmpfs"}
E_PROC = {"id": 30, "parent": 22, "root": "/", "mount_point": "/proc",
          "options": ["rw", "nosuid", "nodev", "noexec", "relatime"], "fstype": "proc", "source": "proc"}
E_LABEL = {"id": 61, "parent": 44, "root": "/my dir", "mount_point": "/mnt/disk", "options": ["ro"],
           "fstype": "vfat", "source": "/dev/disk/by-label/My Disk"}
MI_ALL = "\n".join([MI_ROOT, MI_TMP, MI_PROC]) + "\n"

T06_PUBLIC = [
    ("S1", "parse", MI_EXT3, [E_EXT3]),
    ("S1", "parse", MI_ROOT + "\n", [E_ROOT]),
    ("S1", "parse", MI_ROOT + "\n" + MI_TMP + "\n", [E_ROOT, E_TMP]),
    ("S2", "a", 1, []),
    ("S2", "b", 2, []),
    ("S2", "c", 4, ["old.txt"]),
    ("S3", "cap", 65536),
    ("S3", "cap", 262144),
    ("S3", "ro", 0),
]
T06_HIDDEN = []  # повний набір є лише у викладача
T06 = T06_PUBLIC + T06_HIDDEN


@pytest.mark.parametrize("case", [c for c in T06 if c[0] == "S1"], ids=_ids([c for c in T06 if c[0] == "S1"], "T06"))
def test_mountinfo(case):
    M = load(6)
    if case[1] == "parse":
        assert M.parse_mountinfo(case[2]) == case[3]
    else:
        _, _, path, text, expected = case
        assert M.is_mount_point(path, text) is expected


@pytest.mark.parametrize("case", [c for c in T06 if c[0] == "S2"], ids=_ids([c for c in T06 if c[0] == "S2"], "T06"))
@requires_userns
def test_private_tmpfs(case, tmp_path):
    _, name, size_mb, old_files = case
    M = load(6)
    target = tmp_path / name
    target.mkdir(parents=True)
    for old in old_files:
        (target / old).write_text("до монтування")
    result = M.private_tmpfs(str(target), size_mb)
    assert result == {"inside": True, "outside": False, "files_inside": ["hello.txt"], "files_outside": sorted(old_files)}
    with open("/proc/self/mountinfo", encoding="utf-8") as handle:
        assert M.is_mount_point(str(target), handle.read()) is False


@pytest.mark.parametrize("case", [c for c in T06 if c[0] == "S3"], ids=_ids([c for c in T06 if c[0] == "S3"], "T06"))
@requires_userns
def test_tmpfs_capacity_and_readonly(case, tmp_path):
    _, kind, value = case
    M = load(6)
    target = tmp_path / "mnt"
    target.mkdir()
    if kind == "cap":
        assert M.tmpfs_capacity(str(target), value) == value
    else:
        assert M.readonly_errno(str(target)) == errno.EROFS
    assert os.listdir(target) == []


def test_no_shortcuts():
    assert_no_shortcuts(6)


