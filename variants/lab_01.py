"""Лабораторна SP-LAB03. Задача 1: Простори імен процесу в /proc.

Правила — у student.md (розділ 7, задача 1) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_01.py
"""


def parse_ns_link(link: str) -> tuple[str, int]:
    """'uts:[4026531838]' -> ('uts', 4026531838); інакше ValueError."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def read_namespaces(pid_dir: str) -> dict[str, int]:
    """Читає <pid_dir>/ns/* і повертає {вид: ідентифікатор}, відсортований за видом."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def differing(first: dict[str, int], second: dict[str, int]) -> list[str]:
    """Види, присутні в обох словниках, ідентифікатори яких різні (відсортовано)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
