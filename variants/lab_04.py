"""Лабораторна SP-LAB03. Задача 4: unshare(2) через ctypes.

Правила — у student.md (розділ 7, задача 4) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_04.py
"""


def unshare(flags: int) -> None:
    """unshare(2) через libc; при помилці піднімає OSError з відповідним errno."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def uts_demo(hostname: str) -> tuple[str, str]:
    """(ім'я хоста всередині нового простору UTS, ім'я хоста батька після цього)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def ns_changed(kinds: list[str]) -> dict[str, bool]:
    """Для кожного виду з kinds: чи змінилося посилання /proc/self/ns/<вид> після unshare."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
