"""Лабораторна SP-LAB03. Задача 9: Налаштування cgroups v2.

Правила — у student.md (розділ 7, задача 9) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_09.py
"""


def parse_size(text: str) -> int | None:
    """'64M' -> 67108864; 'max' -> None; суфікси K, M, G (кратні 1024, регістр не важливий)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def format_size(size: int | None) -> str:
    """Найкоротший точний запис: 67108864 -> '64M'; 1000 -> '1000'; None -> 'max'."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def cgroup_settings(memory=None, pids=None, cpu_percent=None, swap=False) -> dict[str, str]:
    """Файли контрольної групи та значення. Порядок ключів: memory.max, memory.swap.max, pids.max, cpu.max."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def parse_cpu_max(text: str) -> float | None:
    """'50000 100000' -> 50.0 (відсотків одного ядра); 'max 100000' -> None."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def parse_keyed(text: str) -> dict[str, int]:
    """Файли 'ключ число' (memory.events, pids.events, cpu.stat) -> словник."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def oom_killed(events_text: str) -> bool:
    """Реалізуйте за описом задачі."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def apply_settings(group_dir: str, settings: dict[str, str]) -> None:
    """Реалізуйте за описом задачі."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def run_in_cgroup(parent: str, name: str, settings: dict[str, str], job) -> dict:
    """Створює групу parent/name, застосовує settings, виконує job() у дитині, що перейшла в групу.
Повертає {'exit', 'signal', 'memory_events', 'pids_events', 'memory_max'}; групу в кінці видаляє."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
