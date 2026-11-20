"""The recognise-act cycle with an explanation trace."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .facts import Fact, WorkingMemory
from .rules import Rule, registered_rules


@dataclass
class TraceEntry:
    cycle: int
    rule: str
    phase: str
    binding: str
    derived: list


@dataclass
class RunResult:
    cycles: int = 0
    fired: dict = field(default_factory=dict)      # rule name -> number of activations fired
    derived: int = 0
    trace: list = field(default_factory=list)
    elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {"cycles": self.cycles, "fired": dict(sorted(self.fired.items())), "derived": self.derived,
                "elapsed": round(self.elapsed, 4),
                "trace": [{"cycle": t.cycle, "rule": t.rule, "phase": t.phase, "binding": t.binding,
                           "derived": t.derived} for t in self.trace]}


def _binding_key(binding: tuple):
    return tuple(binding)


class Engine:
    """Salience-ordered, refractory, monotonic forward chaining.

    On every cycle the engine computes the conflict set (all (rule, binding)
    activations not yet fired), picks the rule with the highest salience (ties
    broken by registration order) and fires *all* of its activations.  Because
    actions only add facts, the loop reaches a fixpoint; because the choice is
    a function of the current fact set only, the result does not depend on the
    order in which inputs were asserted.
    """

    def __init__(self, rules: Optional[list] = None, trace: bool = True, max_cycles: int = 100000):
        self.rules = rules if rules is not None else registered_rules()
        self.trace_enabled = trace
        self.max_cycles = max_cycles

    def run(self, wm: WorkingMemory) -> RunResult:
        t0 = time.perf_counter()
        fired: set = set()
        result = RunResult()
        cycle = 0
        while cycle < self.max_cycles:
            cycle += 1
            chosen = None
            activations = []
            for r in self.rules:  # already sorted by (-salience, order)
                if chosen is not None and r.salience < chosen.salience:
                    break
                acts = []
                for binding in r.when(wm):
                    key = (r.name, _binding_key(binding))
                    if key in fired:
                        continue
                    acts.append((key, binding))
                if acts:
                    chosen, activations = r, acts
                    break
            if chosen is None:
                break
            for key, binding in activations:
                fired.add(key)
                new = []
                for f in chosen.fire(wm, binding):
                    if isinstance(f, Fact) and wm.add(f):
                        new.append(f)
                result.fired[chosen.name] = result.fired.get(chosen.name, 0) + 1
                result.derived += len(new)
                if self.trace_enabled:
                    result.trace.append(TraceEntry(
                        cycle, chosen.name, chosen.phase,
                        ", ".join(b.describe() if isinstance(b, Fact) else str(b) for b in binding),
                        [f.describe() for f in new]))
        result.cycles = cycle
        result.elapsed = time.perf_counter() - t0
        return result


def explain(result: RunResult, subject: str) -> list:
    """Explanation facility: trace entries that mention ``subject`` (a canonical id or raw ref)."""
    out = []
    for t in result.trace:
        if subject in t.binding or any(subject in d for d in t.derived):
            out.append({"cycle": t.cycle, "rule": t.rule, "phase": t.phase, "binding": t.binding,
                        "derived": [d for d in t.derived if subject in d] or t.derived})
    return out
