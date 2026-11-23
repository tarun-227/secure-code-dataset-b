"""Print the generation prompt for one row of an issue CSV.

Usage: python tools/make_prompt.py issues/lla-1_01.csv --row 3
       python tools/make_prompt.py issues/lla-1_01.csv --id lla_89_py_0007
Paste the output into Ollama (or let tools/generate.py do it for you).
"""
from __future__ import annotations

import argparse

from common import read_rows
from vocab import CASE, CWE_NAME, FIX, LANG_NAME, PATTERN, SHAPE, SHAPE_BY_LANG, SOURCE, VALUE


def prompt(r) -> str:
    lang, cwe = LANG_NAME[r["language"]], r["cwe"]
    vulnerable = r["label"] == "1"
    lines = [
        f"Write one {lang} function for this task: {r['task_description']}",
        f"It must be {CASE[r['case_type']]}, for {CWE_NAME[cwe]} ({cwe}).",
    ]
    if r["case_type"] in ("hard_positive", "hard_negative"):
        lines.append(f"Use this idea: {PATTERN[r['pattern']]}.")
    if r["case_type"] != "no_code":
        if cwe == "CWE-338":
            if r["cwe_detail"] != "non_security":
                lines.append(f"The random value is used as a {VALUE[r['cwe_detail']]}.")
        else:
            lines.append(f"Use {r['cwe_detail'].replace('_', ' ')}.")
        if r["case_type"] in ("normal", "hard_positive"):
            lines.append(f"Build the dangerous value with {r['build_style'].replace('_', ' ')}.")
        if r["source"] != "not_applicable":
            lines.append(f"The untrusted input comes from {SOURCE[r['source']]}.")
    shape = SHAPE_BY_LANG.get(r["shape"], {}).get(r["language"], SHAPE[r["shape"]])
    lines.append(f"Write it as {shape}. Make the code about {r['target_lines']} lines long (it must stay within {r['band']} lines).")
    lines.append("Do not write any comment, name or string that says whether the code is safe, vulnerable or fixed.")
    if vulnerable:
        lines.append(f"Also write fixed_code: the same function made safe by changing as few lines as possible (at most 10). Fix it this way: {FIX[r['fix_type']]}.")
        lines.append("List vulnerable_lines: the line numbers in code (counting from 1) that build or use the dangerous value.")
        lines.append('Reply with JSON only: {"code": "...", "fixed_code": "...", "vulnerable_lines": [..]}')
    else:
        lines.append('Reply with JSON only: {"code": "..."}')
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--row", type=int)
    ap.add_argument("--id")
    a = ap.parse_args()
    d = read_rows(a.file)
    r = d[d.sample_id == a.id].iloc[0] if a.id else d.iloc[(a.row or 1) - 1]
    print(prompt(r))
