"""The rule base.  Importing this package registers every rule with the engine registry.

Salience bands (higher fires first):

    900  normalize   canonical identity candidates
    850  resolve     subsumption (stratified before materialisation)
    800  resolve     materialisation, attributes, evidence, relations
    700  closure     referenced algorithms, cipher suites, hybrid constituents
    600  enrich      knowledge-base facts
    500  settle      attribute resolution and conflicts
    400  assess      quantum / compliance assessment
    300  check       conformance findings
"""
from . import normalize, resolve, closure, enrich, settle, assess, check  # noqa: F401
from ..engine.rules import registered_rules

PHASES = ("normalize", "resolve", "closure", "enrich", "settle", "assess", "check")


def rule_catalogue() -> list:
    """Human-readable listing of the rule base."""
    return [{"name": r.name, "phase": r.phase, "salience": r.salience, "doc": r.doc} for r in registered_rules()]
