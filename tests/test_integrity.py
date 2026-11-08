"""Целостность кода: бот не должен звать то, чего у него нет.

Повод прямой. При переносе кода метод `vless_link` попал в заменяемый кусок и
исчез, а кнопка на него осталась — человек нажал и получил
`'Bot' object has no attribute 'vless_link'`. Такое не ловится ни разбором
синтаксиса, ни тестами на отдельные сценарии: падает ровно та кнопка, на
которую теста не написали. Поэтому проверяем разом все обращения `self.…`
во всех классах и все кнопки бота.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def classes(tree: ast.Module):
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            # Классы с внешним родителем пропускаем: часть их атрибутов
            # приходит по наследству, и судить о них по этому файлу нельзя.
            external = any(not (isinstance(b, ast.Name) and b.id == "object")
                           for b in node.bases)
            if not external:
                yield node


def members(cls: ast.ClassDef) -> set[str]:
    """Всё, что у класса есть: методы, атрибуты класса и всё, что он
    присваивает себе в любом из методов."""
    out = set()
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            out |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
    for node in ast.walk(cls):
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
                and isinstance(node.value, ast.Name) and node.value.id == "self"):
            out.add(node.attr)
    return out


def used(cls: ast.ClassDef) -> set[str]:
    return {node.attr for node in ast.walk(cls)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "self"}


class CodeIntegrityTest(unittest.TestCase):
    def test_ни_один_класс_не_зовёт_потерянный_метод(self):
        broken = {}
        for path in sorted((ROOT / "rotator").glob("*.py")):
            tree = ast.parse(path.read_text())
            for cls in classes(tree):
                missing = used(cls) - members(cls)
                if missing:
                    broken[f"{path.name}:{cls.name}"] = sorted(missing)
        self.assertEqual(broken, {}, f"код зовёт то, чего нет: {broken}")

    def test_у_каждой_кнопки_есть_обработчик(self):
        """Кнопка без разбора callback_data — это нажатие в пустоту. Молча и
        навсегда: ошибки в чате не будет, просто ничего не произойдёт."""
        tree = ast.parse((ROOT / "rotator/bot.py").read_text())
        handler = next(n for n in ast.walk(tree)
                       if isinstance(n, ast.FunctionDef) and n.name == "on_callback")

        # Что разбирается: ветви `data == "…"`, `data in ("…", …)` и
        # `data.startswith("…")`. Разбор идёт по семействам, поэтому литерал
        # обработчика — это префикс, а не полное значение кнопки.
        known: set[str] = set()

        def literals(node) -> set[str]:
            out = set()
            for item in ast.walk(node):
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    out.add(item.value)
            return out

        for node in ast.walk(handler):
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) \
                    and node.left.id == "data":
                for comparator in node.comparators:
                    known |= literals(comparator)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "startswith" \
                    and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id == "data":
                for arg in node.args:
                    known |= literals(arg)
        self.assertIn("vless:menu", known, "разбор callback_data не распознан")

        source = (ROOT / "rotator/bot.py").read_text()
        # Из f-строк берём только постоянную часть: "vless:go:full:{name}".
        targets = set(re.findall(r'"callback_data":\s*f?"([^"{]*)', source))
        lost = sorted(t for t in targets if t and not any(
            t.startswith(k) or k.startswith(t) for k in known))
        self.assertEqual(lost, [], f"кнопки без обработчика: {lost}")


if __name__ == "__main__":
    unittest.main()
