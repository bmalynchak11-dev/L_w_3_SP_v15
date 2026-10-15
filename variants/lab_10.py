"""Лабораторна SP-LAB03. Задача 10: Міні-контейнер.

Правила — у student.md (розділ 7, задача 10) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_10.py
"""


def plan_steps(cfg: dict, uid: int = 1000, gid: int = 1000) -> list[tuple[str, str]]:
    """Упорядкований план запуску контейнера як список (дія, аргумент)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def audit(cfg: dict) -> list[str]:
    """Коди зауважень щодо безпеки конфігурації у фіксованому порядку."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def run_container(cfg: dict) -> tuple[int, str]:
    """Запускає cfg['argv'] у новому наборі просторів; повертає (код завершення, stdout).
Код: звичайний; завершення сигналом N дає 128 + N; помилка налаштування дає 125."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
