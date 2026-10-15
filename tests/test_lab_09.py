"""Відкриті тести задачі 9.

Запуск: pytest tests/test_lab_09.py. Тут лише приклади з карток варіантів;
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


# ---- Задача 9. Налаштування cgroups v2 (parse_size, format_size, cgroup_settings, parse_keyed, run_in_cgroup)

T09_PUBLIC = [
    ("S1", "parse", "64M", 67108864),
    ("S1", "parse", "1G", 1073741824),
    ("S1", "parse", "512K", 524288),
    ("S1", "format", 67108864, "64M"),
    ("S1", "format", 1073741824, "1G"),
    ("S1", "format", 524288, "512K"),
    ("S2", "settings", {"memory": "64M"}, {"memory.max": "67108864", "memory.swap.max": "0"}),
    ("S2", "settings", {"pids": 32}, {"pids.max": "32"}),
    ("S2", "settings", {"memory": "1G", "pids": 100, "cpu_percent": 50},
     {"memory.max": "1073741824", "memory.swap.max": "0", "pids.max": "100", "cpu.max": "50000 100000"}),
    ("S2", "cpu", "50000 100000", 50.0),
    ("S3", "keyed", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0}),
    ("S3", "oom", "max 12\noom 1\noom_kill 1\n", True),
    ("S3", "apply", {"memory.max": "67108864", "pids.max": "32"}),
    ("S3", "live", "oom"),
]
T09_HIDDEN = []  # повний набір є лише у викладача
T09 = T09_PUBLIC + T09_HIDDEN


def _expect(call, expected):
    if isinstance(expected, ValueError):
        with pytest.raises(ValueError) as info:
            call()
        assert str(info.value) == str(expected)
    else:
        assert call() == expected


@pytest.mark.parametrize("case", [c for c in T09 if c[0] == "S1"], ids=_ids([c for c in T09 if c[0] == "S1"], "T09"))
def test_sizes(case):
    _, kind, value, expected = case
    M = load(9)
    _expect((lambda: M.parse_size(value)) if kind == "parse" else (lambda: M.format_size(value)), expected)


@pytest.mark.parametrize("case", [c for c in T09 if c[0] == "S2"], ids=_ids([c for c in T09 if c[0] == "S2"], "T09"))
def test_settings(case):
    M = load(9)
    if case[1] == "cpu":
        _expect(lambda: M.parse_cpu_max(case[2]), case[3])
    else:
        _, _, kwargs, expected = case
        if isinstance(expected, ValueError):
            _expect(lambda: M.cgroup_settings(**kwargs), expected)
        else:
            result = M.cgroup_settings(**kwargs)
            assert result == expected
            assert list(result) == list(expected)          # порядок ключів має значення


def _alloc_and_touch():
    block = bytearray(200 * 1024 * 1024)
    for i in range(0, len(block), 4096):
        block[i] = 1
    return 0


def _fork_until_failure():
    read_end, write_end = os.pipe()
    made = 0
    try:
        while True:
            pid = os.fork()
            if pid == 0:
                os.close(write_end)
                os.read(read_end, 1)
                os._exit(0)
            made += 1
    except OSError:
        pass
    finally:
        os.close(write_end)
        try:
            while True:
                os.wait()
        except ChildProcessError:
            pass
    return made


def _live(kind, name):
    M = load(9)
    parent = cgroup_parent()
    if kind == "oom":
        result = M.run_in_cgroup(parent, name, M.cgroup_settings(memory="64M"), _alloc_and_touch)
        assert result["exit"] is None and result["signal"] == signal.SIGKILL
        assert result["memory_events"]["oom_kill"] >= 1
        assert result["memory_max"] == "67108864"
    elif kind == "ok":
        result = M.run_in_cgroup(parent, name, M.cgroup_settings(memory="256M"), lambda: 5)
        assert result["exit"] == 5 and result["signal"] is None
        assert result["memory_events"].get("oom_kill", 0) == 0
        assert result["memory_max"] == "268435456"
    elif kind == "pids":
        result = M.run_in_cgroup(parent, name, M.cgroup_settings(pids=3), _fork_until_failure)
        assert result["exit"] == 2 and result["signal"] is None
        assert result["pids_events"]["max"] >= 1
    else:
        result = M.run_in_cgroup(parent, name, {}, lambda: 0)
        assert result["exit"] == 0 and result["memory_max"] == "max"
    assert not os.path.exists(os.path.join(parent, name)), "групу має бути видалено"


@pytest.mark.parametrize("case", [c for c in T09 if c[0] == "S3"], ids=_ids([c for c in T09 if c[0] == "S3"], "T09"))
def test_files_and_live(case, tmp_path):
    M = load(9)
    kind = case[1]
    if kind == "keyed":
        assert M.parse_keyed(case[2]) == case[3]
    elif kind == "oom":
        assert M.oom_killed(case[2]) is case[3]
    elif kind == "apply":
        M.apply_settings(str(tmp_path), case[2])
        assert {p.name: p.read_text() for p in tmp_path.iterdir()} == case[2]
    else:
        if cgroup_parent() is None:
            pytest.skip("потрібна делегована група cgroups v2 із контролерами memory і pids, якої тут немає: "
                        "виконайте роботу на сервері коледжу або у ВМ (змінна SP_CGROUP_PARENT вказує готову групу)")
        _live(case[2], f"sp_lab03_{os.getpid()}_{case[2]}")


def test_no_shortcuts():
    assert_no_shortcuts(9)


