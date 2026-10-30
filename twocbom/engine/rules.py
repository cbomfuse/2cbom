"""Rule abstraction and global registry.

A rule is a pair (``when``, ``then``):

* ``when(wm)`` is a generator yielding *bindings* -- tuples of hashable values
  (usually facts) for which the rule is applicable;
* ``then(wm, *binding)`` returns the facts to assert (or None).

Rules are *monotonic*: actions only add facts, never retract.  Together with
set semantics in the working memory this gives a well-defined fixpoint.
"""
from __future__ import annotations

from typing import Callable, Iterable, Optional

_REGISTRY: list = []


class Rule:
    def __init__(self, name: str, salience: int, phase: str, doc: str, when: Callable):
        self.name = name
        self.salience = salience
        self.phase = phase
        self.doc = doc
        self.when = when
        self._then: Optional[Callable] = None
        self.order = len(_REGISTRY)

    def then(self, fn: Callable) -> Callable:
        self._then = fn
        return fn

    def fire(self, wm, binding: tuple) -> Iterable:
        if self._then is None:
            return ()
        result = self._then(wm, *binding)
        return result or ()

    def __repr__(self):
        return f"Rule({self.name!r}, salience={self.salience}, phase={self.phase!r})"


def rule(name: str, salience: int, phase: str, doc: str = "") -> Callable:
    """Decorator turning a condition generator into a registered :class:`Rule`."""
    def deco(fn: Callable) -> Rule:
        r = Rule(name, salience, phase, doc or (fn.__doc__ or "").strip(), fn)
        _REGISTRY.append(r)
        return r
    return deco


def registered_rules() -> list:
    return sorted(_REGISTRY, key=lambda r: (-r.salience, r.order))


def clear_registry() -> None:
    _REGISTRY.clear()
