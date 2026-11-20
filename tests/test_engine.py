from dataclasses import dataclass

from twocbom.engine.facts import Fact, WorkingMemory
from twocbom.engine.inference import Engine, explain
from twocbom.engine.rules import Rule


@dataclass(frozen=True)
class Num(Fact):
    n: int


@dataclass(frozen=True)
class Even(Fact):
    n: int


@dataclass(frozen=True)
class Done(Fact):
    count: int


def make_rules():
    def when_even(wm):
        for f in wm.get(Num):
            if f.n % 2 == 0:
                yield (f,)

    r1 = Rule("even", 10, "a", "mark evens", when_even)
    r1.then(lambda wm, f: [Even(f.n)])

    def when_done(wm):
        yield (frozenset(wm.get(Even)),)

    r2 = Rule("done", 1, "b", "count evens after everything else", when_done)
    r2.then(lambda wm, evens: [Done(len(evens))])
    return [r1, r2]


def test_salience_refraction_and_trace():
    wm = WorkingMemory()
    for n in range(6):
        wm.add(Num(n))
    run = Engine(make_rules()).run(wm)
    assert run.fired == {"even": 3, "done": 1}
    assert wm.get(Done) == [Done(3)]
    assert not wm.add(Even(0))          # set semantics
    assert run.cycles >= 2
    ex = explain(run, "Even(n=2)")
    assert ex and ex[0]["rule"] == "even"


def test_order_independence():
    def run(order):
        wm = WorkingMemory()
        for n in order:
            wm.add(Num(n))
        Engine(make_rules(), trace=False).run(wm)
        return sorted(f.n for f in wm.get(Even)), wm.get(Done)
    assert run([0, 1, 2, 3, 4]) == run([4, 3, 2, 1, 0])


def test_indexes():
    wm = WorkingMemory()
    wm.add_all([Num(1), Num(2), Num(2)])
    assert len(wm) == 2
    assert wm.find(Num, n=2) == [Num(2)]
    assert wm.one(Num, n=3) is None
    wm.add(Num(3))
    assert wm.exists(Num, n=3)
