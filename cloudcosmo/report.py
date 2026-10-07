"""Render findings + score into JSON and a single-file HTML report."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

HTML_TEMPLATE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>CloudCosmo - Rapport</title>
<style>
body{{font-family:-apple-system,Segoe UI,Arial,sans-serif;margin:2rem;color:#111}}
h1{{margin-bottom:0}} .meta{{color:#555;margin-bottom:1.5rem}}
.grade{{display:inline-block;font-size:2rem;font-weight:bold;padding:.2rem .8rem;
  border-radius:.4rem;background:{grade_color};color:#fff}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;font-size:.9rem;vertical-align:top}}
th{{background:#f4f4f4}}
.sev-Critical{{color:#b00020;font-weight:bold}} .sev-High{{color:#d35400;font-weight:bold}}
.sev-Medium{{color:#b8860b}} .sev-Low{{color:#666}}
</style></head><body>
<h1>CloudCosmo &mdash; rapport de cartographie</h1>
<div class="meta">Généré le {generated} &middot; {total} finding(s)</div>
<p>Score : <span class="grade">{grade}</span> ({score} / 100)</p>
<table>
<tr><th>Règle</th><th>Sévérité</th><th>Ressource</th><th>Description</th></tr>
{rows}
</table>
</body></html>"""

GRADE_COLORS = {"S": "#2e7d32", "A": "#558b2f", "B": "#f9a825",
                "C": "#ef6c00", "D": "#c62828", "E": "#8e0000"}


def to_json(findings, scoring) -> str:
    return json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "score": scoring,
        "findings": [asdict(f) for f in findings],
    }, indent=2, ensure_ascii=False)


def to_html(findings, scoring) -> str:
    rows = "\n".join(
        f'<tr><td>{f.rule_id}</td><td class="sev-{f.severity}">{f.severity}</td>'
        f'<td>{f.resource}</td><td>{f.description}</td></tr>'
        for f in findings
    )
    return HTML_TEMPLATE.format(
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        total=len(findings), grade=scoring["grade"], score=scoring["score"],
        grade_color=GRADE_COLORS.get(scoring["grade"], "#555"), rows=rows or "<tr><td colspan=4>Aucun finding</td></tr>",
    )
