"""Maintainer tool: regenerate docs/ROW_FORMAT.md from tools/vocab.py."""
from common import ROOT
from vocab import CASE, FIX, PATTERN, SHAPE, SOURCE

HEAD = """# Row format

Every issue CSV has the same 20 columns. The first 16 are filled in already; **do not change them**. You fill in the last four.

## Columns you must not change

| Column | Meaning | Example |
|---|---|---|
| `sample_id` | unique row ID; the prefix shows the model | `phi_22_cpp_0612` |
| `generator` | the model that must write the code | `phi4:14b` |
| `language` | `python`, `c`, `cpp` or `go` | `cpp` |
| `cwe` | the weakness | `CWE-22` |
| `case_type` | what the function must be (see below) | `hard_negative` |
| `label` | 1 vulnerable, 0 safe | `0` |
| `task_description` | what the function does | `Read a log file chosen by the caller.` |
| `cwe_detail` | the API or operation to use (for CWE-338: what the random value is for) | `fstream` |
| `band` | allowed number of lines in `code` | `11-20` |
| `target_lines` | aim for about this many lines | `14` |
| `build_style` | how the dangerous value is built (`per_pattern` for hard negatives: follow the pattern) | `path_operator` |
| `source` | where the untrusted input comes from | `web_request` |
| `fix_type` | how `fixed_code` must fix it (vulnerable rows only) | `normalize_prefix_check` |
| `pattern` | the trick for hard rows; `plain_vulnerable`, `standard_safe` or `no_dangerous_call` otherwise | `resolve_then_contain_with_separator` |
| `suggested_sink` | typical dangerous call for this weakness and language | `std::ifstream / std::filesystem` |
| `shape` | how the code is organised | `web_handler` |

## Columns you fill in

| Column | What to put | Rule |
|---|---|---|
| `code` | the complete function | line count inside `band` |
| `fixed_code` | the same function made safe | vulnerable rows only; at most 10 changed lines; same name and parameters; empty for safe rows |
| `vulnerable_lines` | line numbers in `code` that build or use the dangerous value | vulnerable rows only; like `[3, 4]`; counted from 1 including blank lines; empty for safe rows |
| `notes` | anything the reviewer should know | optional |

## Meaning of every tag
"""

if __name__ == "__main__":
    out = [HEAD]
    for title, d in (("Case types", CASE), ("Patterns", PATTERN), ("Fix types", FIX), ("Shapes", SHAPE), ("Input sources", SOURCE)):
        out.append(f"\n### {title}\n\n| Tag | Meaning |\n|---|---|")
        out += [f"| `{k}` | {v} |" for k, v in d.items()]
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "ROW_FORMAT.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print("wrote docs/ROW_FORMAT.md")
