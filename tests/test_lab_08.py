"""Відкриті тести задачі 8.

Запуск: pytest tests/test_lab_08.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 8. Обмеження ресурсів, rlimit (parse_limits, run_limited, count_open_until_emfile, file_size_limit)

LIMITS_HEAD = "Limit                     Soft Limit           Hard Limit           Units     \n"
L_CPU = "Max cpu time              unlimited            unlimited            seconds   \n"
L_FILES = "Max open files            1024                 524288               files     \n"
L_NICE = "Max nice priority         0                    0                    \n"
L_STACK = "Max stack size            8388608              unlimited            bytes     \n"

T08_PUBLIC = [
    ("S1", LIMITS_HEAD + L_CPU, {"Max cpu time": (None, None)}),
    ("S1", LIMITS_HEAD + L_FILES, {"Max open files": (1024, 524288)}),
    ("S1", LIMITS_HEAD + L_CPU + L_FILES, {"Max cpu time": (None, None), "Max open files": (1024, 524288)}),
    ("S2", "exit7"),
    ("S2", "none"),
    ("S2", "raises"),
    ("S3", "fds", 40),
    ("S3", "fds", 64),
    ("S3", "fsize", 50),
]
T08_HIDDEN = []  # повний набір є лише у викладача
T08 = T08_PUBLIC + T08_HIDDEN


@pytest.mark.parametrize("case", [c for c in T08 if c[0] == "S1"], ids=_ids([c for c in T08 if c[0] == "S1"], "T08"))
def test_parse_limits(case):
    _, text, expected = case
    M = load(8)
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            M.parse_limits(text)
        assert str(info.value) == str(expected)
    else:
        assert M.parse_limits(text) == expected


def _vm_size():
    with open("/proc/self/status", encoding="utf-8") as handle:
        return next(int(l.split()[1]) for l in handle if l.startswith("VmSize:")) * 1024


def _job_open_until_emfile():
    try:
        for _ in range(1000):
            os.open("/dev/null", os.O_RDONLY)
    except OSError as exc:
        return 4 if exc.errno == errno.EMFILE else 5
    return 6


def _job_alloc():
    try:
        block = bytearray(300 * 1024 * 1024)
        for i in range(0, len(block), 4096):
            block[i] = 1
    except MemoryError:
        return 9
    return 0


def _job_spin():
    while True:
        pass


def _job_check_pair():
    import resource
    return 1 if resource.getrlimit(resource.RLIMIT_NOFILE) == (50, 60) else 2


def _job_raise():
    raise RuntimeError("збій")


@pytest.mark.parametrize("case", [c for c in T08 if c[0] == "S2"], ids=_ids([c for c in T08 if c[0] == "S2"], "T08"))
def test_run_limited(case):
    _, kind = case
    M = load(8)
    if kind == "exit7":
        assert M.run_limited(lambda: 7, {}) == (7, None)
    elif kind == "none":
        assert M.run_limited(lambda: None, {}) == (0, None)
    elif kind == "raises":
        assert M.run_limited(_job_raise, {}) == (3, None)
    elif kind == "cpu":
        assert M.run_limited(_job_spin, {"CPU": (1, 5)}) == (None, signal.SIGXCPU)
    elif kind == "memory":
        assert M.run_limited(_job_alloc, {"AS": _vm_size() + 100 * 1024 * 1024}) == (9, None)
        assert M.run_limited(_job_alloc, {}) == (0, None)
    elif kind == "nofile":
        assert M.run_limited(_job_open_until_emfile, {"NOFILE": open_fds() + 20}) == (4, None)
    elif kind == "pair":
        assert M.run_limited(_job_check_pair, {"NOFILE": (50, 60)}) == (1, None)
        assert M.run_limited(_job_check_pair, {"NOFILE": 50}) == (2, None)
    else:
        with pytest.raises(ValueError) as info:
            M.run_limited(lambda: 0, {"FOO": 1})
        assert str(info.value) == "Невідомий ліміт: FOO"


@pytest.mark.parametrize("case", [c for c in T08 if c[0] == "S3"], ids=_ids([c for c in T08 if c[0] == "S3"], "T08"))
def test_real_limits(case, tmp_path):
    _, kind, value = case
    M = load(8)
    if kind == "fds":
        before = open_fds()
        assert M.count_open_until_emfile(value) == value - before
    elif kind == "fsize":
        assert M.file_size_limit(value, str(tmp_path)) == value
    else:
        soft_hard = value

        def job():
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, soft_hard)
            with open("/proc/self/limits", encoding="utf-8") as handle:
                return M.parse_limits(handle.read())["Max open files"]

        assert tuple(fork_json(job)) == soft_hard


def test_parent_limits_untouched():
    import resource
    M = load(8)
    before = resource.getrlimit(resource.RLIMIT_NOFILE)
    M.run_limited(lambda: 0, {"NOFILE": 30})
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == before


def test_no_shortcuts():
    assert_no_shortcuts(8)


