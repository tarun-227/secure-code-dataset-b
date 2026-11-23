"""Check a finished issue file before you commit it. Fix every ERROR; read every WARNING.

Usage: python tools/validate.py submissions/lla-1_01.csv
       (compares against issues/lla-1_01.csv automatically when it exists, or pass --issue PATH)
Exit code 0 = no errors.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import re
import sys
from pathlib import Path

from common import BAND_RANGE, COLUMNS, FILLED, ROOT, SPEC, parse_lines, read_rows

HINT = re.compile(r"(?i)vulnerab|insecure|\bunsafe\b|sanitiz|sanitis|exploit|inject|\bcwe[-_ ]?\d|\bfix(ed|es)?\b|attack|malicious|\bhack|\bsecure version\b|\bsafe version\b|\bbad\b.*\binput\b")
COMMENT = {"python": r"#.*|\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''", "c": r"//.*|/\*[\s\S]*?\*/", "cpp": r"//.*|/\*[\s\S]*?\*/", "go": r"//.*|/\*[\s\S]*?\*/"}


def norm(code: str) -> str:
    return re.sub(r"\s+", "", code)


def strip_strings(code: str) -> str:
    return re.sub(r'"(\\.|[^"\\])*"|\'(\\.|[^\'\\])*\'|`[^`]*`', '""', code)


def braces_ok(code: str) -> bool:
    s = re.sub(r"//.*|/\*[\s\S]*?\*/", "", strip_strings(code))
    depth = 0
    for ch in s:
        depth += {"{": 1, "}": -1}.get(ch, 0)
        if depth < 0:
            return False
    return depth == 0 and s.count("(") == s.count(")")


def func_name(code: str, lang: str):
    if lang == "python":
        try:
            t = ast.parse(code)
        except SyntaxError:
            return None
        f = [n.name for n in ast.walk(t) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        return f[-1] if f else None
    if lang == "go":
        m = re.findall(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", code, re.M)
    else:
        m = re.findall(r"^[A-Za-z_][\w\s\*:<>,&]*?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?\{", code, re.M)
    return m[-1] if m else None


def check_row(r, errors, warnings):
    sid, lang, vul = r["sample_id"], r["language"], r["label"] == "1"
    e = lambda m: errors.append(f"{sid}: {m}")
    w = lambda m: warnings.append(f"{sid}: {m}")
    code = r["code"]
    if not code.strip():
        e("code is empty")
        return
    n = len(code.rstrip("\n").split("\n"))
    lo, hi = BAND_RANGE[r["band"]]
    if not lo <= n <= hi:
        e(f"code has {n} lines but the band is {r['band']}")
    elif abs(n - int(r["target_lines"])) > max(3, int(r["target_lines"]) // 2):
        w(f"code has {n} lines; the target was {r['target_lines']}")
    for name, text in (("code", code), ("fixed_code", r["fixed_code"])):
        words = re.sub(r"([a-z])([A-Z])", r"\1 \2", text).replace("_", " ") if text else ""
        if words and HINT.search(words):
            e(f"{name} contains a word that gives away the label: '{HINT.search(words).group(0)}' (remove it from comments, names and strings)")
    if lang == "python":
        for name, text in (("code", code), ("fixed_code", r["fixed_code"])):
            if text:
                try:
                    ast.parse(text)
                except SyntaxError as x:
                    e(f"{name} is not valid Python: line {x.lineno}: {x.msg}")
    else:
        for name, text in (("code", code), ("fixed_code", r["fixed_code"])):
            if text and not braces_ok(text):
                e(f"{name} has unbalanced braces or brackets")
    try:
        vl = parse_lines(r["vulnerable_lines"])
    except Exception:
        e("vulnerable_lines must look like [3, 4]")
        vl = None
    if vul:
        if not r["fixed_code"].strip():
            e("vulnerable row without fixed_code")
        if vl is not None and not vl:
            e("vulnerable row without vulnerable_lines")
        if vl:
            bad = [x for x in vl if not 1 <= x <= n]
            if bad:
                e(f"vulnerable_lines {bad} are outside the code (1-{n})")
            blank = [x for x in vl if 1 <= x <= n and not code.split("\n")[x - 1].strip()]
            if blank:
                e(f"vulnerable_lines {blank} point at empty lines")
        if r["fixed_code"].strip():
            if norm(r["fixed_code"]) == norm(code):
                e("fixed_code is the same as code")
            a, b = code.split("\n"), r["fixed_code"].split("\n")
            changed = sum(max(i2 - i1, j2 - j1) for t, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes() if t != "equal")
            if changed > 10:
                e(f"fixed_code changes {changed} lines; keep it to 10 or fewer")
            if func_name(code, lang) and func_name(code, lang) != func_name(r["fixed_code"], lang):
                e("fixed_code renames the function")
    else:
        if r["fixed_code"].strip():
            e("safe row must leave fixed_code empty")
        if vl:
            e("safe row must leave vulnerable_lines empty")
    if func_name(code, lang) is None:
        w("could not find a function definition")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--issue", help="the original issue CSV (default: issues/<same name>)")
    a = ap.parse_args()
    d = read_rows(a.file)
    errors, warnings = [], []
    missing = [c for c in COLUMNS if c not in d.columns]
    if missing:
        print("ERROR: missing columns:", missing)
        sys.exit(1)
    issue = Path(a.issue) if a.issue else ROOT / "issues" / Path(a.file).name
    if issue.exists():
        src = read_rows(issue).set_index("sample_id")
        if set(src.index) != set(d.sample_id):
            errors.append(f"rows differ from the issue: missing {sorted(set(src.index) - set(d.sample_id))}, extra {sorted(set(d.sample_id) - set(src.index))}")
        for r in d.itertuples(index=False):
            if r.sample_id in src.index:
                changed = [c for c in SPEC if c != "sample_id" and str(getattr(r, c)) != str(src.at[r.sample_id, c])]
                if changed:
                    errors.append(f"{r.sample_id}: pre-filled columns were edited: {changed}")
    else:
        warnings.append(f"no issue file found at {issue}; pre-filled columns not compared")
    for _, r in d.iterrows():
        check_row(r, errors, warnings)
    keys = d.code.map(norm)
    for k in keys[keys.duplicated() & (keys != "")]:
        errors.append(f"duplicate code: {', '.join(d.sample_id[keys == k])}")
    others = [f for f in (ROOT / "submissions").glob("*.csv") if f.resolve() != Path(a.file).resolve()]
    seen = {}
    for f in others:
        for sid, c in zip(read_rows(f).sample_id, read_rows(f).code):
            if c:
                seen[norm(c)] = sid
    for sid, k in zip(d.sample_id, keys):
        if k and k in seen and seen[k] != sid:
            errors.append(f"{sid}: same code as {seen[k]} in another submission")
    for m in warnings:
        print("WARNING:", m)
    for m in errors:
        print("ERROR:", m)
    print(f"\n{len(d)} rows, {len(errors)} errors, {len(warnings)} warnings")
    print("OK - you can commit and push this file" if not errors else "Fix the errors and run again.")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
