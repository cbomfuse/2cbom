"""A small but complete forward-chaining production system.

* :mod:`facts`      -- immutable typed facts and the working memory (with indexes);
* :mod:`rules`      -- the rule abstraction (condition generator + action) and registry;
* :mod:`inference`  -- the recognise-act cycle: salience-ordered agenda, refraction,
                       monotonic fixpoint, and an explanation trace.
"""
from .facts import *  # noqa: F401,F403
from .rules import Rule, rule, registered_rules, clear_registry  # noqa: F401
from .inference import Engine, RunResult, TraceEntry, explain  # noqa: F401
