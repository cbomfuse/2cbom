"""twocbom command-line interface.

    twocbom merge a.json b.json c.json -o merged.2cbom.json [--cyclonedx out.cdx.json] [--report out.md]
                  [--trace trace.json] [--profile strict|core] [--strip-prefix PREFIX]... [--tool path=name]...
    twocbom validate merged.2cbom.json
    twocbom inspect input.json
    twocbom canon "AES/GCM/NoPadding" ["SHA256withRSA" ...]
    twocbom explain trace.json 2cbom:alg:aes-128-gcm
    twocbom rules
    twocbom schema > twocbom-1.0.schema.json
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .canonical import jcs_dumps, parse_algorithm, parse_cipher_suite
from .export import to_cyclonedx, to_markdown
from .ingest import detect_format, ingest_file, load_json
from .merge import MergeOptions, merge_files
from .validate import schema_json, validate_document


def _write(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def cmd_merge(args) -> int:
    overrides = {}
    for item in args.tool or []:
        path, _, name = item.partition("=")
        overrides[path] = name
    opts = MergeOptions(profile=args.profile, strip_prefixes=tuple(args.strip_prefix or ()),
                        tool_overrides=overrides, trace=bool(args.trace), timestamp=args.timestamp)
    result = merge_files(args.inputs, opts)
    doc = result.document
    text = jcs_dumps(doc) if args.compact else json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True)
    _write(args.output, text)
    if args.cyclonedx:
        _write(args.cyclonedx, json.dumps(to_cyclonedx(doc), indent=2, ensure_ascii=False))
    if args.report:
        _write(args.report, to_markdown(doc))
    if args.trace:
        _write(args.trace, json.dumps(result.run.to_dict(), indent=1, ensure_ascii=False))
    conf = doc["conformance"]
    sys.stderr.write(f"twocbom: merged {len(args.inputs)} source(s) -> {len(doc['assets'])} assets, "
                     f"{len(doc['components'])} components, {len(doc['relations'])} relations; "
                     f"{result.run.cycles} inference cycles, {sum(result.run.fired.values())} rule firings; "
                     f"profile={conf['profile']} conformant={conf['conformant']} "
                     f"(errors={conf['errors']}, warnings={conf['warnings']}, infos={conf['infos']})\n")
    return 0 if (conf["conformant"] or not args.fail_on_nonconformance) else 2


def cmd_validate(args) -> int:
    with open(args.document, encoding="utf-8") as fh:
        doc = json.load(fh)
    errors = validate_document(doc)
    if errors:
        for e in errors:
            print(e)
        print(f"{len(errors)} validation error(s)")
        return 1
    conf = doc.get("conformance", {})
    print(f"valid 2CBOM {doc.get('2cbomVersion')} document; profile={conf.get('profile')} conformant={conf.get('conformant')} "
          f"errors={conf.get('errors')} warnings={conf.get('warnings')}")
    return 0 if conf.get("conformant", True) or not args.fail_on_nonconformance else 2


def cmd_inspect(args) -> int:
    for path in args.inputs:
        doc, digest = load_json(path)
        info = detect_format(doc)
        print(f"{path}: format={info.family} specVersion={info.spec_version} confidence={info.confidence} digest={digest}")
        for n in info.notes:
            print(f"  note: {n}")
        if info.family == "unknown":
            continue
        res = ingest_file(path)
        print(f"  tool={res.source.tool} {res.source.tool_version} assets={len(res.assets)} components={len(res.components)} "
              f"evidence={len(res.evidence)} relations={len(res.relations)}")
        for a in res.assets:
            pr = parse_algorithm(a.name, {k: a.fields.get(k) for k in ("primitive", "parameterSetIdentifier", "curve", "mode", "padding")} | ({"oid": a.oid} if a.oid else {})) if a.asset_type == "algorithm" else None
            canon = pr.descriptor.canonical() if pr and pr.ok else ("<unresolved>" if pr else "")
            print(f"    [{a.asset_type}] {a.ref}: {a.name!r} -> {canon}")
        for code, msg in res.findings:
            print(f"  finding: {code}: {msg}")
    return 0


def cmd_canon(args) -> int:
    for name in args.names:
        suite = parse_cipher_suite(name)
        if suite and (name.upper().startswith("TLS_") or name.lower().startswith("0x")):
            comps = ", ".join(f"{role}={d.canonical()}" for role, d in suite["components"])
            print(f"{name}: cipher suite {suite['name']} -> {comps} (key exchange {'known' if suite['kex_known'] else 'negotiated separately'})")
            continue
        pr = parse_algorithm(name)
        if pr.ok:
            print(f"{name}: {pr.descriptor.cid()}  primitive={pr.descriptor.primitive} confidence={pr.confidence}"
                  + (f" notes={pr.notes}" if pr.notes else ""))
        else:
            print(f"{name}: UNRESOLVED notes={pr.notes} residue={pr.residue}")
    return 0


def cmd_explain(args) -> int:
    from .engine.inference import RunResult, TraceEntry, explain
    with open(args.trace, encoding="utf-8") as fh:
        data = json.load(fh)
    run = RunResult(cycles=data["cycles"], fired=data["fired"], derived=data["derived"],
                    trace=[TraceEntry(t["cycle"], t["rule"], t["phase"], t["binding"], t["derived"]) for t in data["trace"]])
    entries = explain(run, args.subject)
    if not entries:
        print(f"no rule firing mentions {args.subject}")
        return 1
    for e in entries:
        print(f"cycle {e['cycle']:>4}  [{e['phase']}] {e['rule']}")
        print(f"      because: {e['binding'][:300]}")
        for d in e["derived"][:12]:
            print(f"      derived: {d[:300]}")
    return 0


def cmd_rules(args) -> int:
    from .rules import rule_catalogue
    for r in rule_catalogue():
        print(f"{r['salience']:>4} {r['phase']:<10} {r['name']:<40} {r['doc']}")
    return 0


def cmd_schema(args) -> int:
    print(schema_json())
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="twocbom", description="2CBOM: canonical CBOM model and merge expert system")
    parser.add_argument("--version", action="version", version=f"twocbom {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("merge", help="merge CBOMs into one 2CBOM document")
    p.add_argument("inputs", nargs="+")
    p.add_argument("-o", "--output", default="-")
    p.add_argument("--cyclonedx", help="also write a CycloneDX 1.6 projection")
    p.add_argument("--report", help="also write a Markdown report")
    p.add_argument("--trace", help="write the inference trace (explanation facility)")
    p.add_argument("--profile", choices=("strict", "core"), default="strict")
    p.add_argument("--strip-prefix", action="append", help="path prefix to strip from evidence locations (repeatable)")
    p.add_argument("--tool", action="append", help="override the tool of a source: path=name (repeatable)")
    p.add_argument("--timestamp", help="ISO 8601 generation timestamp (default: now)")
    p.add_argument("--compact", action="store_true", help="write RFC 8785 canonical JSON instead of pretty JSON")
    p.add_argument("--fail-on-nonconformance", action="store_true", help="exit 2 when the document is not conformant")
    p.set_defaults(func=cmd_merge)

    p = sub.add_parser("validate", help="validate a 2CBOM document")
    p.add_argument("document")
    p.add_argument("--fail-on-nonconformance", action="store_true")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("inspect", help="detect the format of CBOM files and preview their canonicalisation")
    p.add_argument("inputs", nargs="+")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("canon", help="canonicalise algorithm or cipher-suite names")
    p.add_argument("names", nargs="+")
    p.set_defaults(func=cmd_canon)

    p = sub.add_parser("explain", help="show the rule firings that produced facts about a subject")
    p.add_argument("trace")
    p.add_argument("subject")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("rules", help="list the rule base")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("schema", help="print the 2CBOM JSON Schema")
    p.set_defaults(func=cmd_schema)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
