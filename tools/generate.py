"""Ask your local Ollama model for every row of an issue CSV and write a checked first draft.

For each row:
  1. the model writes the code (prompt from make_prompt.prompt);
  2. for vulnerable rows, a second prompt asks it to fix that code (make_prompt.fix_prompt);
  3. every answer is checked automatically (parses/compiles, imports present, length inside the band, no give-away
     words, case type plausible, fix small) and asked again, up to 3 times, until it passes;
  4. vulnerable_lines comes from the model's '@@' line markers, which are then removed.
If a row still has problems after 3 tries, the best try is kept and its problems are written into `notes`
starting with "AUTO-CHECK:". Fix those by hand or run the row again with --only.

The draft is a starting point: read every row yourself before you commit.

Usage: python tools/generate.py issues/lla-1_01.csv            -> submissions/lla-1_01.csv
       python tools/generate.py issues/lla-1_01.csv --only 3   (redo row 3 only)
Needs Ollama running (ollama serve) and the row's model pulled (ollama pull <generator>).
"""
from __future__ import annotations

import argparse
import difflib
import json
import urllib.request
from pathlib import Path

from checks import extract_code, give_away, label_problems, syntax_problems, take_markers
from common import BAND_RANGE, code_lines, ROOT, numbered, read_rows, write_rows
from make_prompt import fix_prompt, prompt

URL = "http://localhost:11434/api/generate"
TRIES = 3


def ask(model: str, text: str, temperature: float) -> str:
    body = json.dumps({"model": model, "prompt": text, "stream": False,
                       "options": {"temperature": temperature, "num_ctx": 8192, "num_predict": 3000}}).encode()
    req = urllib.request.Request(URL, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=900) as res:
        return json.loads(res.read())["response"]


def changed_lines(a: str, b: str) -> int:
    ops = difflib.SequenceMatcher(None, a.split("\n"), b.split("\n"), autojunk=False).get_opcodes()
    return sum(max(i2 - i1, j2 - j1) for t, i1, i2, j1, j2 in ops if t != "equal")


def diff_lines(a: str, b: str):
    """Lines of a that the fix replaced or deleted (fallback when the model gave no markers)."""
    ops = difflib.SequenceMatcher(None, a.split("\n"), b.split("\n"), autojunk=False).get_opcodes()
    return [i + 1 for t, i1, i2, _, _ in ops if t in ("replace", "delete") for i in range(i1, i2) if a.split("\n")[i].strip()]


def code_problems(r, code, marks):
    p = syntax_problems(code, r["language"])
    n = code_lines(code, r["language"])
    lo, hi = BAND_RANGE[r["band"]]
    if n > hi:
        p.append(f"{n} lines of code, but it must be {lo}-{hi} (make it shorter: leave out setup, printing and extras)")
    elif n < lo:
        p.append(f"{n} lines of code, but it must be {lo}-{hi} (make it longer with realistic input checks, error handling, logging or a helper)")
    if give_away(code):
        p.append(f"contains the give-away word '{give_away(code)}'")
    p += label_problems(r, code)
    if r["label"] == "1" and not marks:
        p.append("no line was marked with the @@ comment")
    return p


def fix_problems(r, code, fixed):
    p = syntax_problems(fixed, r["language"])
    if fixed.split() == code.split():
        p.append("fixed_code is the same as code")
    elif changed_lines(code, fixed) > 10:
        p.append(f"fixed_code changes {changed_lines(code, fixed)} lines (at most 10)")
    if give_away(fixed):
        p.append(f"fixed_code contains the give-away word '{give_away(fixed)}'")
    p += label_problems(r, code, fixed)[len(label_problems(r, code)):]
    return p


def again(text, probs):
    if not probs:
        return text
    return text + "\n\nYour previous answer had these problems. Write it again and fix them:\n" + "\n".join("- " + p for p in probs)


def best_of(make, check, label):
    """Ask up to TRIES times, telling the model what was wrong; return the first clean answer, else the one with the fewest problems."""
    best, probs = None, []
    for t in range(TRIES):
        ans = make(0.4 if t == 0 else 0.7, probs)
        probs = check(ans)
        if best is None or len(probs) < len(best[1]):
            best = (ans, probs)
        if not probs:
            break
        print(f"  {label} try {t + 1}: " + "; ".join(probs))
    return best


def do_row(r):
    model = r["generator"]

    def make_code(temp, probs):
        return take_markers(extract_code(ask(model, again(prompt(r), probs), temp)))

    (code, marks), probs = best_of(make_code, lambda a: code_problems(r, *a), "code")
    fixed, vlines = "", []
    if r["label"] == "1":
        fixed, fprobs = best_of(lambda temp, pr: take_markers(extract_code(ask(model, again(fix_prompt(r, code), pr), temp)))[0],
                                lambda f: fix_problems(r, code, f), "fix")
        probs += fprobs
        vlines = marks or diff_lines(code, fixed)
        if not marks and vlines:
            probs.append("vulnerable_lines guessed from the fix; check them")
    return code, fixed, vlines, probs


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--only", type=int, help="regenerate one row number (1-based)")
    a = ap.parse_args()
    src = read_rows(a.file)
    out_path = ROOT / "submissions" / Path(a.file).name
    out_path.parent.mkdir(exist_ok=True)
    d = read_rows(out_path) if out_path.exists() else src.copy()
    for i, r in src.iterrows():
        if a.only and i + 1 != a.only:
            continue
        if not a.only and d.at[i, "code"]:
            continue
        print(f"row {i + 1}/{len(src)} {r.sample_id} ({r.case_type}) ...", flush=True)
        try:
            code, fixed, vlines, probs = do_row(r)
        except Exception as e:  # keep going; the row stays empty and validate.py will report it
            print("  failed:", e)
            continue
        d.at[i, "code"], d.at[i, "fixed_code"] = code, fixed
        d.at[i, "vulnerable_lines"] = json.dumps(vlines) if r.label == "1" else ""
        old = [x for x in d.at[i, "notes"].split(" | ") if x and not x.startswith("AUTO-CHECK:")]
        d.at[i, "notes"] = " | ".join(old + (["AUTO-CHECK: " + "; ".join(probs)] if probs else []))
        print("\n".join(("  >" if n in vlines else "   ") + line for n, line in enumerate(numbered(code).split("\n"), 1)))
        if fixed:
            print(f"   fix changes {changed_lines(code, fixed)} lines; vulnerable_lines = {vlines}")
        print("   " + ("AUTO-CHECK problems: " + "; ".join(probs) if probs else "auto-checks passed"))
        write_rows(d, out_path)
    print("wrote", out_path, "- now check every row (lines marked > are vulnerable_lines) and run tools/validate.py on it")
