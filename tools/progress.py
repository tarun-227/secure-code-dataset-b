"""Rebuild PROGRESS.md from the accepted files in data/accepted/.

Usage: python tools/progress.py
"""
from __future__ import annotations

import pandas as pd

from common import ROOT, read_rows

if __name__ == "__main__":
    plan = pd.read_csv(ROOT / "plan" / "all_rows.csv", dtype=str)
    files = list((ROOT / "data" / "accepted").rglob("*.csv"))
    acc = pd.concat([read_rows(f) for f in files], ignore_index=True) if files else pd.DataFrame(columns=["sample_id"])
    plan["done"] = plan.sample_id.isin(set(acc.sample_id))
    lines = ["# Progress", "", f"Accepted rows: **{int(plan.done.sum())} of {len(plan)}** ({plan.done.mean():.0%}).", ""]
    lines += ["## By model", "", "| Model | Accepted | Target |", "|---|---|---|"]
    for g, x in plan.groupby("generator"):
        lines.append(f"| `{g}` | {int(x.done.sum())} | {len(x)} |")
    lines += ["", "## By model, weakness and language", "", "| Model | Weakness | Python | C | C++ | Go |", "|---|---|---|---|---|---|"]
    for (g, c), x in plan.groupby(["generator", "cwe"]):
        cells = []
        for lang in ("python", "c", "cpp", "go"):
            y = x[x.language == lang]
            cells.append(f"{int(y.done.sum())}/{len(y)}")
        lines.append(f"| `{g}` | {c} | " + " | ".join(cells) + " |")
    lines += ["", "## By case type", "", "| Case type | Accepted | Target |", "|---|---|---|"]
    for t, x in plan.groupby("case_type"):
        lines.append(f"| `{t}` | {int(x.done.sum())} | {len(x)} |")
    (ROOT / "PROGRESS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:3]))
