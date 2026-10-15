import os
import sys
import json
import ctypes
import errno

# Константи прапорців просторів імен ядра Linux
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000

# Константи монтування
MS_REC = 0x4000
MS_PRIVATE = 1 << 18


def _get_libc():
    """Завантаження системної бібліотеки libc через ctypes."""
    return ctypes.CDLL(None, use_errno=True)


def _setup_id_map(uid: int, gid: int) -> None:
    """Запис відображення uid/gid у просторі user."""
    with open('/proc/self/setgroups', 'w') as f:
        f.write('deny')
    with open('/proc/self/uid_map', 'w') as f:
        f.write(f'0 {uid} 1')
    with open('/proc/self/gid_map', 'w') as f:
        f.write(f'0 {gid} 1')


def parse_nspid(status_text: str) -> list[int]:
    """Розбирає рядок NSpid у тексті статусу процесу /proc/<PID>/status."""
    for line in status_text.splitlines():
        if line.startswith('NSpid:'):
            parts = line.split()
            # parts[0] - це 'NSpid:', решта - цілочисельні PID у ланцюжку просторів
            return [int(x) for x in parts[1:]]
    raise ValueError("У status немає рядка NSpid")


def nspid_of_init() -> tuple[int, list[int]]:
    """
    Створює новий простір PID і повертає зовнішній PID першого процесу (init)
    та розібраний список NSpid з його файлу /proc/<pid>/status.
    """
    sys.stdout.flush()
    sys.stderr.flush()

    orig_uid = os.getuid()
    orig_gid = os.getgid()

    # Канал зв'язку між батьком і посередником (для передачі результату)
    res_r, res_w = os.pipe()

    pid_intermediate = os.fork()
    if pid_intermediate == 0:
        os.close(res_r)
        try:
            # Створюємо простір користувача та PID
            os.unshare(CLONE_NEWUSER | CLONE_NEWPID)
            _setup_id_map(orig_uid, orig_gid)

            # Канал синхронізації: дитина (init нового простору) чекає, поки посередник прочитає її статус
            sync_r, sync_w = os.pipe()

            init_pid = os.fork()
            if init_pid == 0:
                os.close(sync_w)
                os.close(res_w)
                # Чекаємо сигналу завершення зчитування (закриття sync_w у посереднику)
                try:
                    os.read(sync_r, 1)
                finally:
                    os.close(sync_r)
                    os._exit(0)

            # Посередник: закриваємо читаючий кінець
            os.close(sync_r)

            # Читаємо /proc/<init_pid>/status ззовні нового простору PID
            status_path = f'/proc/{init_pid}/status'
            with open(status_path, 'r', encoding='utf-8') as f:
                status_text = f.read()

            nspid_list = parse_nspid(status_text)

            # Відпускаємо init-процес
            os.close(sync_w)
            os.waitpid(init_pid, 0)

            # Передаємо результат батьківському процесу
            payload = json.dumps({'init_pid': init_pid, 'nspid': nspid_list}).encode('utf-8')
            os.write(res_w, payload)
            os.close(res_w)
            os._exit(0)
        except Exception as e:
            err_payload = json.dumps({'error': str(e)}).encode('utf-8')
            try:
                os.write(res_w, err_payload)
                os.close(res_w)
            except Exception:
                pass
            os._exit(1)

    os.close(res_w)
    data = b""
    while True:
        chunk = os.read(res_r, 4096)
        if not chunk:
            break
        data += chunk
    os.close(res_r)
    _, status = os.waitpid(pid_intermediate, 0)

    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise RuntimeError("Не вдалося створити простір PID або зчитати NSpid")

    res = json.loads(data.decode('utf-8'))
    if 'error' in res:
        raise RuntimeError(res['error'])

    return res['init_pid'], res['nspid']


def pid_view(children: int = 0) -> dict:
    """Повертає огляд процесів з точки зору першого процесу нового простору PID."""
    sys.stdout.flush()
    sys.stderr.flush()

    orig_uid = os.getuid()
    orig_gid = os.getgid()
    res_r, res_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        os.close(res_r)
        try:
            os.unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)
            _setup_id_map(orig_uid, orig_gid)

            init_pid = os.fork()
            if init_pid == 0:
                libc = _get_libc()
                # Робимо корінь приватним і перемонтовуємо /proc
                if libc.mount(b"none", b"/", None, MS_REC | MS_PRIVATE, None) != 0:
                    err = ctypes.get_errno()
                    raise OSError(err, os.strerror(err))

                if libc.mount(b"proc", b"/proc", b"proc", 0, None) != 0:
                    err = ctypes.get_errno()
                    raise OSError(err, os.strerror(err))

                sync_pipes = []
                child_pids = []
                for _ in range(children):
                    cr, cw = os.pipe()
                    cpid = os.fork()
                    if cpid == 0:
                        os.close(cw)
                        os.close(res_w)
                        os.read(cr, 1)
                        os.close(cr)
                        os._exit(0)
                    os.close(cr)
                    sync_pipes.append(cw)
                    child_pids.append(cpid)

                proc_entries = sorted([int(entry) for entry in os.listdir('/proc') if entry.isdigit()])
                result = {
                    'pid': os.getpid(),
                    'ppid': os.getppid(),
                    'proc': proc_entries
                }

                for cw in sync_pipes:
                    os.close(cw)
                for cpid in child_pids:
                    os.waitpid(cpid, 0)

                payload = json.dumps(result).encode('utf-8')
                os.write(res_w, payload)
                os.close(res_w)
                os._exit(0)

            os.close(res_w)
            _, s = os.waitpid(init_pid, 0)
            os._exit(os.WEXITSTATUS(s) if os.WIFEXITED(s) else 1)
        except Exception as e:
            try:
                os.write(res_w, json.dumps({'error': str(e)}).encode('utf-8'))
                os.close(res_w)
            except Exception:
                pass
            os._exit(1)

    os.close(res_w)
    data = b""
    while True:
        chunk = os.read(res_r, 4096)
        if not chunk:
            break
        data += chunk
    os.close(res_r)
    _, status = os.waitpid(pid, 0)

    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise RuntimeError("Помилка виконання в pid_view")

    res = json.loads(data.decode('utf-8'))
    if 'error' in res:
        raise RuntimeError(res['error'])
    return res


def probe_kill(pid: int) -> int:
    """Виконує kill(pid, 0) у новому просторі PID і повертає 0 або код errno."""
    sys.stdout.flush()
    sys.stderr.flush()

    orig_uid = os.getuid()
    orig_gid = os.getgid()
    res_r, res_w = os.pipe()

    fork_pid = os.fork()
    if fork_pid == 0:
        os.close(res_r)
        try:
            os.unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)
            _setup_id_map(orig_uid, orig_gid)

            init_pid = os.fork()
            if init_pid == 0:
                libc = _get_libc()
                libc.mount(b"none", b"/", None, MS_REC | MS_PRIVATE, None)
                libc.mount(b"proc", b"/proc", b"proc", 0, None)

                try:
                    os.kill(pid, 0)
                    ret = 0
                except OSError as e:
                    ret = e.errno

                payload = json.dumps({'errno': ret}).encode('utf-8')
                os.write(res_w, payload)
                os.close(res_w)
                os._exit(0)

            os.close(res_w)
            _, s = os.waitpid(init_pid, 0)
            os._exit(os.WEXITSTATUS(s) if os.WIFEXITED(s) else 1)
        except Exception:
            os._exit(1)

    os.close(res_w)
    data = b""
    while True:
        chunk = os.read(res_r, 4096)
        if not chunk:
            break
        data += chunk
    os.close(res_r)
    _, status = os.waitpid(fork_pid, 0)

    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise RuntimeError("Помилка виконання в probe_kill")

    return json.loads(data.decode('utf-8'))['errno']