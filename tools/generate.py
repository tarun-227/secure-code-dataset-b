"""Ask your local Ollama model for every row of an issue CSV and write a first draft of the filled file.

The draft is only a starting point: read every row, fix the code if needed, and recount vulnerable_lines yourself.

Usage: python tools/generate.py issues/lla-1_01.csv            -> filled/lla-1_01.csv
       python tools/generate.py issues/lla-1_01.csv --only 3   (redo row 3 only)
Needs Ollama running (ollama serve) and the row's model pulled (ollama pull <generator>).
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

from common import ROOT, numbered, read_rows, write_rows
from make_prompt import prompt

URL = "http://localhost:11434/api/generate"


def ask(model: str, text: str) -> dict:
    body = json.dumps({"model": model, "prompt": text, "stream": False, "format": "json", "options": {"temperature": 0.7}}).encode()
    req = urllib.request.Request(URL, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(json.loads(r.read())["response"])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--only", type=int, help="regenerate one row number (1-based)")
    a = ap.parse_args()
    src = read_rows(a.file)
    out_path = ROOT / "filled" / Path(a.file).name
    out_path.parent.mkdir(exist_ok=True)
    d = read_rows(out_path) if out_path.exists() else src.copy()
    for i, r in src.iterrows():
        if a.only and i + 1 != a.only:
            continue
        if not a.only and d.at[i, "code"]:
            continue
        print(f"row {i + 1}/{len(src)} {r.sample_id} ({r.case_type}) ...", flush=True)
        try:
            ans = ask(r.generator, prompt(r))
        except Exception as e:  # keep going; the row stays empty and validate.py will report it
            print("  failed:", e)
            continue
        d.at[i, "code"] = str(ans.get("code", "")).strip("\n")
        if r.label == "1":
            d.at[i, "fixed_code"] = str(ans.get("fixed_code", "")).strip("\n")
            d.at[i, "vulnerable_lines"] = json.dumps(ans.get("vulnerable_lines", []))
        print(numbered(d.at[i, "code"]))
        write_rows(d, out_path)
    print("wrote", out_path, "- now check every row and run tools/validate.py on it")
