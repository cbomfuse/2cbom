"""Human-readable Markdown report of a 2CBOM document."""
from __future__ import annotations


def _short(cid: str, n: int = 60) -> str:
    return cid if len(cid) <= n else cid[: n - 3] + "..."


def _benchmark_section(bench: dict) -> list:
    lines = ["", "## Benchmark", ""]
    tp = bench.get("toolProfiles")
    pr = bench.get("priors")
    if tp:
        base = tp.get("baseline", {})
        lines.append(f"- Tool profile `{tp.get('version')}` (scoring model {bench.get('scoringModelVersion', '-')}, "
                     f"baseline {base.get('commit', '-')[:12]}), digest `{tp.get('digest', '')[:23]}…`")
    if pr:
        lines.append(f"- Reliability priors from run `{pr.get('run')}` ({'with' if pr.get('ledger') else 'without'} ledger), "
                     f"digest `{pr.get('digest', '')[:23]}…`; settlement rule: {bench.get('settlement', {}).get('rule', '-')}")
    tools = (tp or {}).get("tools") or {}
    measured = (pr or {}).get("tools") or {}
    if tools or measured:
        lines.append("")
        lines.append("| tool | measured version | trust | strengths |")
        lines.append("|---|---|---|---|")
        for tid in sorted(set(tools) | set(measured)):
            t, m = tools.get(tid, {}), measured.get(tid, {})
            version = t.get("version") or m.get("version") or "-"
            lines.append(f"| {tid} | {version} | {t.get('trust', '-')} | {', '.join(t.get('strengths', [])) or '-'} |")
    return lines


def to_markdown(doc: dict) -> str:
    lines = []
    conf = doc.get("conformance", {})
    summary = doc.get("summary", {})
    lines.append(f"# 2CBOM report ({doc.get('profile')} profile)")
    lines.append("")
    lines.append(f"- Serial number: `{doc.get('serialNumber')}`")
    lines.append(f"- Digest: `{doc.get('integrity', {}).get('digest')}`")
    lines.append(f"- Generated: {doc.get('generated', {}).get('timestamp')} by twocbom {doc.get('generated', {}).get('generator', {}).get('version')}")
    lines.append(f"- Conformant: **{'yes' if conf.get('conformant') else 'no'}** "
                 f"({conf.get('errors', 0)} errors, {conf.get('warnings', 0)} warnings, {conf.get('infos', 0)} infos)")
    lines.append(f"- Assets: {summary.get('assetCount')} | Components: {summary.get('componentCount')} | Relations: {summary.get('relationCount')}")
    lines.append("")
    lines.append("## Sources")
    lines.append("")
    lines.append("| id | tool | format | spec | trust | assets | digest |")
    lines.append("|---|---|---|---|---|---|---|")
    for s in doc.get("lineage", {}).get("sources", []):
        lines.append(f"| {s['id']} | {s['tool'].get('name')} {s['tool'].get('version', '')} | {s['format']} | {s['specVersion']} | {s['trust']} | {s.get('assetCount', 0)} | `{s['digest'][:23]}…` |")
    bench = doc.get("lineage", {}).get("benchmark")
    if bench:
        lines.extend(_benchmark_section(bench))
    lines.append("")
    lines.append("## Post-quantum readiness")
    lines.append("")
    by_class = summary.get("assetsByQuantumClass", {})
    by_prio = summary.get("assetsByMigrationPriority", {})
    lines.append("| quantum class | assets |  | migration priority | assets |")
    lines.append("|---|---|---|---|---|")
    classes = ["classically-weak", "quantum-vulnerable", "unknown", "quantum-safe"]
    prios = ["immediate", "high", "medium", "low", "none", "unknown"]
    for i in range(max(len(classes), len(prios))):
        c = classes[i] if i < len(classes) else ""
        p = prios[i] if i < len(prios) else ""
        lines.append(f"| {c} | {by_class.get(c, 0) if c else ''} |  | {p} | {by_prio.get(p, 0) if p else ''} |")
    lines.append("")
    lines.append("## Assets")
    lines.append("")
    lines.append("| id | type | quantum class | NIST IR 8547 | NIST cat. | classical bits | CNSA 2.0 | priority | sources | evidence |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for a in doc.get("assets", []):
        s = a.get("assessment") or {}
        lines.append(f"| `{_short(a['id'])}` | {a['type']} | {s.get('quantumClass', '-')} | {s.get('nistIr8547', '-')} | "
                     f"{s.get('nistQuantumSecurityLevel', '-') if s.get('nistQuantumSecurityLevel') is not None else '-'} | "
                     f"{s.get('classicalSecurityLevel', '-') if s.get('classicalSecurityLevel') is not None else '-'} | "
                     f"{'yes' if s.get('cnsa2') else 'no'} | {s.get('migrationPriority', '-')} | {len(a.get('sources', []))} | {len(a.get('evidence', []))} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not doc.get("findings"):
        lines.append("None.")
    for f in doc.get("findings", []):
        if f["severity"] == "info":
            continue
        lines.append(f"- **{f['severity']}** `{f['code']}` `{_short(f['subject'], 50)}`: {f['message']}")
    infos = [f for f in doc.get("findings", []) if f["severity"] == "info"]
    if infos:
        lines.append("")
        lines.append(f"<details><summary>{len(infos)} informational findings</summary>")
        lines.append("")
        for f in infos:
            lines.append(f"- `{f['code']}` `{_short(f['subject'], 50)}`: {f['message']}")
        lines.append("")
        lines.append("</details>")
    conflicts = doc.get("lineage", {}).get("conflicts", [])
    if conflicts:
        lines.append("")
        lines.append("## Resolved conflicts")
        lines.append("")
        for c in conflicts:
            cands = "; ".join(f"{x['origin']}={x['value']!r}" for x in c["candidates"])
            lines.append(f"- `{_short(c['subject'], 50)}`.{c['attribute']} → `{c['chosen']!r}` ({c['rule']}); candidates: {cands}")
            for r in c.get("reconciliation") or []:
                used = ";".join(f"{k}={v}" for k, v in sorted((r.get("categoryUsed") or {}).items())) or "*"
                verdict = f"prefers {r['preferred']}" if r.get("preferred") else "undecided"
                lines.append(f"  - benchmark, {r['toolA']} vs {r['toolB']}: {verdict} (confidence {r['confidence']}, "
                             f"{r['tier']} evidence in `{used}`)")
    lines.append("")
    return "\n".join(lines)
