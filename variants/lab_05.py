"""Лабораторна SP-LAB03. Задача 5: Простір імен PID.

Правила — у student.md (розділ 7, задача 5) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_05.py
"""


def pid_view(children: int = 0) -> dict:
    """Як бачить світ процес 1 нового простору PID, що створив children дітей, які чекають."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def probe_kill(pid: int) -> int:
    """Усередині нового простору PID виконує kill(pid, 0); повертає 0 або номер errno."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def parse_nspid(status_text: str) -> list[int]:
    """Рядок NSpid з /proc/<pid>/status -> список номерів від зовнішнього простору до внутрішнього."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def nspid_of_init() -> tuple[int, list[int]]:
    """(номер першого процесу нового простору за межами простору, його ланцюжок NSpid)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
