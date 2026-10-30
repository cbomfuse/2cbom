"""twocbom -- Canonical Cryptography Bill of Materials (2CBOM) tooling.

The package has three layers:

* ``twocbom.model`` / ``twocbom.canonical``  -- the 2CBOM data model, closed
  vocabularies, canonical naming grammar and canonical (RFC 8785) serialisation;
* ``twocbom.ingest``                          -- adapters that lift CycloneDX 1.5/1.6/1.7
  CBOMs and pre-standard IBM ``1.4-cbom-1.0`` documents into a format-agnostic
  intermediate representation;
* ``twocbom.engine`` / ``twocbom.rules``      -- a forward-chaining production system
  (working memory, salience-ordered agenda, refraction, explanation trace) and the
  knowledge-base-driven rule sets that reconcile the inputs into one 2CBOM.
"""

__version__ = "1.0.0"
RULESET_VERSION = "1.0"
