"""Shared helpers: reading row files and the column lists."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SPEC = ["sample_id", "generator", "language", "cwe", "case_type", "label", "task_description", "cwe_detail", "band", "target_lines",
        "build_style", "source", "fix_type", "pattern", "suggested_sink", "shape"]
FILLED = ["code", "fixed_code", "vulnerable_lines", "notes"]
COLUMNS = SPEC + FILLED
BAND_RANGE = {"1-5": (1, 5), "6-10": (6, 10), "11-20": (11, 20), "21-40": (21, 40), "41-100": (41, 100)}


def read_rows(path) -> pd.DataFrame:
    p = Path(path)
    if p.suffix.lower() in (".xlsx", ".xls"):
        d = pd.read_excel(p, dtype=str)
    elif p.suffix.lower() == ".jsonl":
        d = pd.read_json(p, lines=True, dtype=str)
    else:
        d = pd.read_csv(p, dtype=str, keep_default_na=False)
    return d.fillna("")


def write_rows(d: pd.DataFrame, path) -> None:
    d.to_csv(path, index=False, encoding="utf-8")


def parse_lines(s: str):
    s = (s or "").strip()
    if not s:
        return []
    v = json.loads(s if s.startswith("[") else f"[{s}]")
    if not all(isinstance(x, int) for x in v):
        raise ValueError("not a list of whole numbers")
    return v


IMPORT = {
    "python": re.compile(r"^(import\s|from\s+\S+\s+import\s)"),
    "c": re.compile(r"^#\s*(include|pragma\s+once)\b"),
    "cpp": re.compile(r"^(#\s*(include|pragma\s+once)\b|using\s+namespace\s)"),
    "go": re.compile(r"^(package\s|import\s)"),
}


def code_lines(code: str, lang: str) -> int:
    """Real code lines: lines that are not blank, not only a comment, and not an import / #include / package line.
    This is what `band` and `target_lines` count."""
    n, in_block, in_go_import = 0, False, False
    for raw in code.split("\n"):
        s = raw.strip()
        if in_block:
            in_block = "*/" not in s
            continue
        if lang != "python" and s.startswith("/*"):
            in_block = "*/" not in s
            continue
        if in_go_import:
            in_go_import = s != ")"
            continue
        if lang == "go" and re.match(r"^import\s*\($", s):
            in_go_import = True
            continue
        if not s or s.startswith("#" if lang == "python" else "//") or IMPORT[lang].match(s):
            continue
        n += 1
    return n


def numbered(code: str) -> str:
    return "\n".join(f"{i:>3}| {line}" for i, line in enumerate(code.split("\n"), 1))
