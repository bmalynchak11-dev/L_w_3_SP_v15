"""Перевірка можливостей середовища.

Тести, що потребують просторів імен користувача або делегованої групи cgroups v2, пропускаються з поясненням,
якщо середовище їх не дозволяє. Повний дослід виконують на сервері коледжу або у ВМ (див. розділ 3 завдання).
"""
import functools
import os
import subprocess
import sys

import pytest

_PROBE = r"""
import ctypes, os, sys, tempfile
libc = ctypes.CDLL(None, use_errno=True)
uid, gid = os.getuid(), os.getgid()
os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS | os.CLONE_NEWPID | os.CLONE_NEWUTS)
for name, text in (("setgroups", "deny"), ("uid_map", f"0 {uid} 1"), ("gid_map", f"0 {gid} 1")):
    with open(f"/proc/self/{name}", "w") as handle:
        handle.write(text)
tmp = tempfile.mkdtemp()
pid = os.fork()
if pid == 0:
    ok = (libc.mount(b"none", b"/", None, 0x4000 | (1 << 18), None) == 0
          and libc.mount(b"proc", b"/proc", b"proc", 0, None) == 0
          and libc.mount(b"tmpfs", tmp.encode(), b"tmpfs", 0, b"size=64k") == 0)
    os._exit(0 if ok else 5)
_, status = os.waitpid(pid, 0)
libc.umount(tmp.encode())
os.rmdir(tmp)
sys.exit(os.waitstatus_to_exitcode(status))
"""

USERNS_REASON = ("потрібні простори імен користувача без root (user namespaces), а це середовище їх не дозволяє: "
                 "виконайте роботу на сервері коледжу або у ВМ")
CGROUP_REASON = ("потрібна делегована група cgroups v2 із контролерами memory і pids, якої тут немає: "
                 "виконайте роботу на сервері коледжу або у ВМ (змінна SP_CGROUP_PARENT вказує готову групу)")


@functools.lru_cache(maxsize=1)
def userns_ok() -> bool:
    """Чи дозволяє ядро створити простори user, mnt, pid, uts, змонтувати /proc і tmpfs без root."""
    if not hasattr(os, "unshare"):
        return False
    try:
        result = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _usable(path: str) -> bool:
    """У групі path можна створити підгрупу, і в ній доступні контролери memory та pids."""
    probe = os.path.join(path, f"sp_probe_{os.getpid()}")
    try:
        with open(os.path.join(path, "cgroup.subtree_control"), encoding="utf-8") as handle:
            if not {"memory", "pids"} <= set(handle.read().split()):
                return False
        os.mkdir(probe)
    except OSError:
        return False
    try:
        with open(os.path.join(probe, "cgroup.controllers"), encoding="utf-8") as handle:
            return {"memory", "pids"} <= set(handle.read().split())
    except OSError:
        return False
    finally:
        try:
            os.rmdir(probe)
        except OSError:
            pass


@functools.lru_cache(maxsize=1)
def cgroup_parent():
    """Шлях до групи cgroups v2, у якій користувач може створювати підгрупи; None, якщо такої немає."""
    forced = os.environ.get("SP_CGROUP_PARENT")
    if forced:
        return forced if _usable(forced) else None
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as handle:
            line = next(l for l in handle if l.startswith("0::"))
    except (OSError, StopIteration):
        return None
    path = line.strip().split("::", 1)[1]
    while path and path != "/":
        full = "/sys/fs/cgroup" + path
        if _usable(full):
            return full
        path = os.path.dirname(path)
    root = "/sys/fs/cgroup"
    return root if os.path.exists(root + "/cgroup.controllers") and _usable(root) else None


def has_cap_sys_admin() -> bool:
    """Чи має поточний процес CAP_SYS_ADMIN у своєму просторі користувача (тоді тест EPERM не має сенсу)."""
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << 21))
    except OSError:
        pass
    return False


requires_userns = pytest.mark.skipif(not userns_ok(), reason=USERNS_REASON)
requires_cgroup = pytest.mark.skipif(cgroup_parent() is None, reason=CGROUP_REASON)
