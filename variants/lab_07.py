"""Лабораторна SP-LAB03. Задача 7: Кореневий каталог і chroot(2).

Правила — у student.md (розділ 7, задача 7) та в картці вашого варіанта.
Відкриті тести: pytest tests/test_lab_07.py
"""


def plan_rootfs(spec: list[str]) -> list[tuple[str, str]]:
    """Список ('dir'|'file', шлях) за описом; шлях із '/' наприкінці — каталог; батьки додаються самі."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def safe_join(root: str, path: str) -> str:
    """root + path, де '..' ніколи не виходить за root (як у chroot); символічні посилання не розкриваються."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def resolve_in_root(root: str, path: str) -> str:
    """Як safe_join, але розкриває символічні посилання всередині root (абсолютні цілі рахуються від root)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def build_rootfs(root: str, spec: list[str]) -> int:
    """Створює на диску все з plan_rootfs(spec) усередині root; повертає кількість записів."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі


def enter_root(root: str) -> tuple[list[str], bool]:
    """У дитині (user+mnt): chroot(root), chdir('/'); повертає (вміст '/', чи видно /etc/passwd)."""
    raise NotImplementedError  # TODO: реалізуйте за описом задачі
