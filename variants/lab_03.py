"""Лабораторна SP-LAB03. Задача 3: Відображення ідентифікаторів користувача.

Правила — у student.md (розділ 7, задача 3) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_03.py
"""


def id_map_lines(uid: int, gid: int, inside_uid: int = 0, inside_gid: int = 0) -> dict[str, str]:
    """Що записати у /proc/self/{setgroups,uid_map,gid_map} (саме в такому порядку)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def parse_id_map(text: str) -> list[tuple[int, int, int]]:
    """Розбирає вміст uid_map/gid_map у список (всередині, ззовні, довжина)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def to_outside(mapping: list[tuple[int, int, int]], inside_id: int) -> int | None:
    """Реалізуйте за описом задачі."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def to_inside(mapping: list[tuple[int, int, int]], outside_id: int) -> int | None:
    """Реалізуйте за описом задачі."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def own_map_after_unshare() -> list[tuple[int, int, int]]:
    """У дочірньому процесі: unshare(CLONE_NEWUSER), id_map_lines -> /proc/self/*, повернути parse_id_map(uid_map)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
