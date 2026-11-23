"""Maintainer tool: cut the plan into issue CSVs and open GitHub issues.

  python tools/make_issues.py split                       writes issues/*.csv and issues/index.csv from plan/all_rows.csv
  python tools/make_issues.py labels                      creates the labels and milestones on GitHub
  python tools/make_issues.py open --slot lla-1 --count 2 [--assignee USER]
                                                          opens the slot's next issues that are not yet on GitHub
Slots: 3 per model (lla, phi, dsk). Slot 1: all Python cells + Go CWE-89 and CWE-78.
Slot 2: all C cells + Go CWE-22. Slot 3: all C++ cells + Go CWE-338.
Each slot starts with a 5-row pilot (one row per case type); then issues of up to 10 rows, one cell each.
Needs the GitHub CLI (gh) logged in with access to the repository.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import pandas as pd

from common import FILLED, ROOT, SPEC, read_rows, write_rows
from vocab import CWE_NAME, LANG_NAME

REPO = "tarun-227/secure-code-dataset-b"
PREFIX = {"llama3.1:8b": "lla", "phi4:14b": "phi", "deepseek-coder-v2:16b": "dsk"}
SLOT_CELLS = {
    1: [("python", c) for c in ("CWE-89", "CWE-78", "CWE-22", "CWE-338")] + [("go", "CWE-89"), ("go", "CWE-78")],
    2: [("c", c) for c in ("CWE-89", "CWE-78", "CWE-22", "CWE-338")] + [("go", "CWE-22")],
    3: [("cpp", c) for c in ("CWE-89", "CWE-78", "CWE-22", "CWE-338")] + [("go", "CWE-338")],
}
CASE_ORDER = ["normal", "hard_negative", "hard_positive", "safe", "no_code"]
INDEX = ROOT / "issues" / "index.csv"


def interleave(rows: pd.DataFrame) -> pd.DataFrame:
    """Order rows so every chunk of 10 keeps the cell's case-type mix."""
    groups = [list(rows[rows.case_type == c].index) for c in CASE_ORDER]
    total = sum(len(g) for g in groups)
    out, pos = [], [0] * len(groups)
    # place each group's rows at evenly spaced fractional positions
    keyed = []
    for gi, g in enumerate(groups):
        for k, i in enumerate(g):
            keyed.append(((k + 0.5) / len(g), gi, i))
    keyed.sort()
    out = [i for _, _, i in keyed]
    assert len(out) == total
    return rows.loc[out]


def split():
    plan = pd.read_csv(ROOT / "plan" / "all_rows.csv", dtype=str, keep_default_na=False)
    (ROOT / "issues").mkdir(exist_ok=True)
    index = []
    for gen, pre in PREFIX.items():
        for slot, cells in SLOT_CELLS.items():
            sid = f"{pre}-{slot}"
            seq = 0
            for ci, (lang, cwe) in enumerate(cells):
                rows = plan[(plan.generator == gen) & (plan.language == lang) & (plan.cwe == cwe)]
                if ci == 0:  # pilot: one row per case type, preferring different bands
                    pick, bands = [], set()
                    for c in CASE_ORDER:
                        cand = rows[(rows.case_type == c) & ~rows.index.isin(pick)]
                        fresh = cand[~cand.band.isin(bands)]
                        r = (fresh if len(fresh) else cand).index[0]
                        pick.append(r)
                        bands.add(rows.at[r, "band"])
                    pilot = rows.loc[pick]
                    index.append(save(f"{sid}_00", sid, gen, cwe, lang, "pilot", pilot))
                    rows = rows.drop(pick)
                rows = interleave(rows)
                for k in range(0, len(rows), 10):
                    seq += 1
                    index.append(save(f"{sid}_{seq:02d}", sid, gen, cwe, lang, "batch", rows.iloc[k:k + 10]))
    old = pd.read_csv(INDEX, dtype=str, keep_default_na=False) if INDEX.exists() else None
    idx = pd.DataFrame(index)
    if old is not None:
        idx["gh_issue"] = idx.issue_id.map(dict(zip(old.issue_id, old.gh_issue))).fillna("")
    write_rows(idx, INDEX)
    assert idx.n_rows.astype(int).sum() == len(plan)
    print(idx.groupby(["slot", "stage"]).agg(issues=("issue_id", "size"), rows=("n_rows", lambda s: s.astype(int).sum())).to_string())


def save(issue_id, slot, gen, cwe, lang, stage, rows):
    out = rows[SPEC].copy()
    for c in FILLED:
        out[c] = ""
    write_rows(out, ROOT / "issues" / f"{issue_id}.csv")
    return dict(issue_id=issue_id, slot=slot, generator=gen, cwe=cwe, language=lang, stage=stage, n_rows=len(rows), gh_issue="")


def gh(*args, check=True):
    r = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8")
    if check and r.returncode:
        print(r.stderr.strip())
        sys.exit(1)
    return r.stdout.strip()


LABELS = {"model:llama": "5319e7", "model:phi4": "1d76db", "model:deepseek": "0e8a16",
          "cwe:89": "c5def5", "cwe:78": "c5def5", "cwe:22": "c5def5", "cwe:338": "c5def5",
          "lang:python": "fef2c0", "lang:c": "fef2c0", "lang:cpp": "fef2c0", "lang:go": "fef2c0",
          "stage:pilot": "f9d0c4", "stage:batch": "e4e669",
          "status:in-progress": "bfdadc", "status:needs-review": "fbca04", "status:changes-requested": "d93f0b", "status:accepted": "0e8a16"}
MODEL_LABEL = {"llama3.1:8b": "model:llama", "phi4:14b": "model:phi4", "deepseek-coder-v2:16b": "model:deepseek"}


def labels():
    for name, color in LABELS.items():
        gh("label", "create", name, "--color", color, "--force", "--repo", REPO)
    for m in ("Pilot", "Main"):
        gh("api", f"repos/{REPO}/milestones", "-f", f"title={m}", check=False)
    print("labels and milestones ready")


def body(row, rows: pd.DataFrame) -> str:
    link = f"https://github.com/{REPO}/blob/main/issues/{row.issue_id}.csv"
    t = ["| # | sample_id | case | task | lines | pattern | fix type | input from | shape |", "|---|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows.itertuples(), 1):
        t.append(f"| {i} | `{r.sample_id}` | {r.case_type} | {r.task_description} | {r.target_lines} ({r.band}) | {r.pattern} | {r.fix_type or '-'} | {r.source} | {r.shape} |")
    pilot = row.stage == "pilot"
    return "\n".join([
        f"**Model:** `{row.generator}`  **Weakness:** {row.cwe} ({CWE_NAME[row.cwe]})  **Language:** {LANG_NAME[row.language]}  **Rows:** {row.n_rows}",
        "",
        "This is your **pilot**: 5 rows, one of each case type. Take your time; we check it by hand before you get more." if pilot else
        "Write these rows exactly as specified. Every column except `code`, `fixed_code`, `vulnerable_lines` and `notes` is already filled in; do not change them.",
        "",
        f"**Your file:** [{row.issue_id}.csv]({link}) (download it, or use `issues/{row.issue_id}.csv` in your clone)",
        "",
        *t,
        "",
        "### Steps",
        f"1. `python tools/generate.py issues/{row.issue_id}.csv` (or `python tools/make_prompt.py issues/{row.issue_id}.csv --row N` and paste into Ollama).",
        f"2. Open `filled/{row.issue_id}.csv`, read every row, correct the code, and **recount `vulnerable_lines`** against the numbered code.",
        f"3. `python tools/validate.py filled/{row.issue_id}.csv` until it says OK.",
        "4. Upload the filled CSV here as a comment and change the label to `status:needs-review`.",
        "",
        "### Checklist",
        "- [ ] Every row does what its case type says (vulnerable rows really are exploitable; safe rows really are safe).",
        "- [ ] `fixed_code` changes as few lines as possible and keeps the function name.",
        "- [ ] `vulnerable_lines` point at the lines that build or use the dangerous value.",
        "- [ ] No comment, name or string gives away the label.",
        "- [ ] `tools/validate.py` reports no errors.",
    ])


def open_issues(slot, count, assignee):
    idx = pd.read_csv(INDEX, dtype=str, keep_default_na=False)
    todo = idx[(idx.slot == slot) & (idx.gh_issue == "")].head(count)
    if todo.empty:
        print("nothing left to open for", slot)
        return
    for i, row in todo.iterrows():
        rows = read_rows(ROOT / "issues" / f"{row.issue_id}.csv")
        title = f"[{row.issue_id}] {LANG_NAME[row.language]} {row.cwe}, {row.n_rows} rows ({row.generator})"
        lab = ",".join([MODEL_LABEL[row.generator], f"cwe:{row.cwe.split('-')[1]}", f"lang:{row.language}", f"stage:{row.stage}", "status:in-progress"])
        args = ["issue", "create", "--repo", REPO, "--title", title, "--body", body(row, rows), "--label", lab,
                "--milestone", "Pilot" if row.stage == "pilot" else "Main"]
        if assignee:
            args += ["--assignee", assignee]
        url = gh(*args)
        idx.at[i, "gh_issue"] = url.rsplit("/", 1)[-1]
        print("opened", row.issue_id, url)
    write_rows(idx, INDEX)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["split", "labels", "open"])
    ap.add_argument("--slot")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--assignee")
    a = ap.parse_args()
    {"split": split, "labels": labels, "open": lambda: open_issues(a.slot, a.count, a.assignee)}[a.mode]()
