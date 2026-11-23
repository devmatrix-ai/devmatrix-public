"""Every failure the seal binding reports carries one reason class, so
``--verdict-json`` can name it: no failure list holds plain text."""

import ast
import json
import unittest
from pathlib import Path

import verify_fingerprint as vf

ROOT = Path(__file__).resolve().parents[1]


def _is_text(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    return isinstance(node, ast.BinOp) and (_is_text(node.left) or _is_text(node.right))


def _returns_failures(function: ast.FunctionDef) -> bool:
    return function.returns is not None and "Failure" in ast.unparse(function.returns)


def _failure_position(function: ast.FunctionDef) -> int | None:
    """Which element of a returned tuple holds the failures, or ``None``
    when the function returns them alone."""
    returns = function.returns
    if isinstance(returns, ast.Subscript) and ast.unparse(returns.value) == "tuple":
        elements = returns.slice.elts if isinstance(returns.slice, ast.Tuple) else [returns.slice]
        for index, element in enumerate(elements):
            if "Failure" in ast.unparse(element):
                return index
    return None


def _failure_lists(function: ast.FunctionDef) -> list[ast.AST]:
    """The expressions a function that returns failures uses as failures:
    what it returns in their place, what it assigns to a failures list, and
    what it adds to one."""
    position = _failure_position(function)
    found: list[ast.AST] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Return) and node.value is not None:
            value = node.value
            if position is not None and isinstance(value, ast.Tuple) and len(value.elts) > position:
                found.append(value.elts[position])
            elif position is None:
                found.append(value)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id in ("failures", "failed") for target in targets):
                found.append(node.value)
    return found


def _texts_in(expression: ast.AST) -> list[int]:
    """The lines where ``expression`` puts text in place of a Failure: a
    text element of a list it builds, or the text itself."""
    if _is_text(expression):
        return [expression.lineno]
    if isinstance(expression, ast.List):
        return [element.lineno for element in expression.elts if _is_text(element)]
    if isinstance(expression, ast.ListComp):
        return [expression.elt.lineno] if _is_text(expression.elt) else []
    if isinstance(expression, ast.BinOp):
        return _texts_in(expression.left) + _texts_in(expression.right)
    if isinstance(expression, ast.IfExp):
        return _texts_in(expression.body) + _texts_in(expression.orelse)
    return []


def _plain_text_failures(tree: ast.Module) -> list[str]:
    """Where a function that returns failures puts text in place of a
    Failure, or anything appends text to a failures list."""
    found = []
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        if _returns_failures(function):
            for expression in _failure_lists(function):
                found += [f"{function.name}:{line}" for line in _texts_in(expression)]
        for node in ast.walk(function):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("append", "extend")
                    and isinstance(node.func.value, ast.Name) and node.func.value.id in ("failures", "failed")
                    and any(_texts_in(argument) for argument in node.args)):
                found.append(f"{function.name}:{node.lineno}")
    return sorted(set(found))


class EveryFailure(unittest.TestCase):
    def test_no_failure_is_plain_text(self) -> None:
        """MUT-RED: one failure written as plain text again."""
        tree = ast.parse((ROOT / "verify_fingerprint.py").read_text(encoding="utf-8"))
        functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and _returns_failures(node)]
        self.assertGreater(len(functions), 10, "no function returning failures found: the check reads nothing")
        self.assertEqual(_plain_text_failures(tree), [])

    def test_a_reason_class_outside_the_contract_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            vf.Failure("x", "other")

    def test_the_verdict_names_a_failure_without_a_class_unclassified(self) -> None:
        """MUT-RED: a failure without a class dropped from the verdict."""
        document = vf.verdict_document(False, [vf.Failure("a", "runner"), "plain text"], "fixture")
        self.assertEqual(document, {"verdict": "FAILED", "reason_classes": ["runner", "unclassified"],
                                    "key_class": "fixture"})

    def test_the_verdict_of_a_binding_that_held(self) -> None:
        self.assertEqual(vf.verdict_document(True, [], "production"),
                         {"verdict": "VERIFIED", "reason_classes": [], "key_class": "production"})
        self.assertEqual(json.loads(json.dumps(vf.verdict_document(True, [], "fixture")))["verdict"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
