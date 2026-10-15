"""Лабораторна SP-LAB03. Задача 6: Простір імен монтування.

Правила — у student.md (розділ 7, задача 6) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_06.py
"""


def parse_mountinfo(text: str) -> list[dict]:
    """Розбирає /proc/self/mountinfo у список словників (id, parent, root, mount_point, options, fstype, source)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def is_mount_point(path: str, mountinfo_text: str) -> bool:
    """Реалізуйте за описом задачі."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def private_tmpfs(path: str, size_mb: int) -> dict:
    """tmpfs розміром size_mb МіБ на path лише у власному просторі mnt; що бачать дитина і батько."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def tmpfs_capacity(path: str, size_bytes: int) -> int:
    """Скільки байтів вдається записати у tmpfs з size=size_bytes до помилки ENOSPC."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def readonly_errno(path: str) -> int:
    """Монтує tmpfs лише для читання й повертає errno спроби створити там файл."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
