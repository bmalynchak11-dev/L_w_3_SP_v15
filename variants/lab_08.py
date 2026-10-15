"""Лабораторна SP-LAB03. Задача 8: Обмеження ресурсів, rlimit.

Правила — у student.md (розділ 7, задача 8) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_08.py
"""


def run_limited(job, limits: dict) -> tuple[int | None, int | None]:
    """Виконує job() у дочірньому процесі з лімітами {'NOFILE': 40, 'CPU': (1, 5), ...}.
Повертає (код виходу, номер сигналу): з двох значень одне завжди None."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def parse_limits(text: str) -> dict[str, tuple[int | None, int | None]]:
    """/proc/<pid>/limits -> {'Max open files': (м'який, жорсткий)}; 'unlimited' перетворюється на None."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def count_open_until_emfile(limit: int) -> int:
    """Скільки разів вдається відкрити /dev/null, коли RLIMIT_NOFILE дорівнює limit (до помилки EMFILE)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def file_size_limit(limit: int, directory: str) -> int:
    """Скільки байтів (по одному) вдається дописати у файл directory/data.bin при RLIMIT_FSIZE = limit."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
