"""Generate the 1,200 row specifications of Dataset B (plan/all_rows.csv) so that every distribution target holds exactly.

Per model: 400 rows = 16 cells (4 weaknesses x 4 languages) x 25 rows.
Per cell (75 rows over the three models): normal 25, hard_positive 12, safe 12, hard_negative 20, no_code 6.
Length bands per cell: 1-5: 7, 6-10: 19, 11-20: 22, 21-40: 19, 41-100: 8.
Fix types, patterns, input sources and shapes are spread as evenly as possible with the caps printed by --check.
Every row's task fits its pattern, fix type, input source, shape, band and file operation (rules below; see plan/tasks.py).
Bands count real code lines: no blank lines, comment-only lines, or import/#include/package lines.

Usage: python tools/build_plan.py            (writes plan/all_rows.csv and prints the check table)
"""
from __future__ import annotations

import random
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan"))
from tasks import TASKS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261123
MODELS = [("llama3.1:8b", "lla"), ("phi4:14b", "phi"), ("deepseek-coder-v2:16b", "dsk")]
CWES = ["CWE-89", "CWE-78", "CWE-22", "CWE-338"]
LANGS = ["python", "c", "cpp", "go"]
SHORT = {"CWE-89": "89", "CWE-78": "78", "CWE-22": "22", "CWE-338": "338", "python": "py", "c": "c", "cpp": "cpp", "go": "go"}
CASES = {"normal": 25, "hard_positive": 12, "safe": 12, "hard_negative": 20, "no_code": 6}
LABEL = {"normal": 1, "hard_positive": 1, "safe": 0, "hard_negative": 0, "no_code": 0}
BANDS = {"1-5": 7, "6-10": 19, "11-20": 22, "21-40": 19, "41-100": 8}
BAND_RANGE = {"1-5": (3, 5), "6-10": (6, 10), "11-20": (11, 20), "21-40": (21, 40), "41-100": (41, 70)}
SHAPES = ["plain_function", "method", "web_handler", "cli_entry", "helper_called_by_caller", "callback_or_async"]
SOURCES = ["function_argument", "web_request", "file_content", "environment", "command_line", "database_value", "network_message"]

FIX = {
    "CWE-89": ["parameterised_query", "allow_list", "type_conversion", "query_builder_orm"],
    "CWE-78": ["argv_no_shell", "quote_escape", "allow_list", "validate_format", "end_of_options"],
    "CWE-22": ["normalize_prefix_check", "basename_only", "safe_join_library", "id_to_file_map", "validate_format"],
    "CWE-338": {"python": ["secrets_module", "system_random", "os_urandom"],
                "c": ["os_random_api", "dev_urandom", "csprng_library"],
                "cpp": ["os_random_api", "dev_urandom", "csprng_library"],
                "go": ["crypto_rand_read", "crypto_rand_int", "crypto_rand_text"]},
}
HN = {  # hard negatives: (tag, task pool)
    "CWE-89": [(t, "main") for t in ["allow_listed_identifier", "generated_placeholders", "constant_fragments_only", "query_builder_bound", "integer_forced", "fstring_placeholders_only"]],
    "CWE-78": [(t, "main") for t in ["constant_shell_command", "all_args_quoted", "argv_list_user_data", "command_from_fixed_map", "strict_parser_no_shell", "end_of_options_marker"]],
    "CWE-22": [(t, "main") for t in ["resolve_then_contain_with_separator", "basename_only", "id_mapped_to_known_file", "safe_filename_fixed_folder", "library_confined_access", "allow_listed_name"]],
    "CWE-338": [("non_security_simulation", "nonsec"), ("non_security_shuffle_or_sample", "nonsec"), ("retry_jitter", "nonsec"),
                ("fixed_seed_experiment", "nonsec"), ("secure_secret_random_elsewhere", "main"), ("game_or_ui_randomness", "nonsec")],
}
HP = {
    "CWE-89": ["hand_written_escaping", "keyword_blocklist", "param_in_one_branch_only", "identifier_from_input", "second_order_stored_value"],
    "CWE-78": ["partial_metachar_filter", "quoting_wrong_context", "validates_other_variable", "validator_too_permissive", "argument_injection_dash"],
    "CWE-22": ["check_before_normalise", "prefix_without_separator", "single_pass_dotdot_strip", "misses_absolute_path", "extension_check_only"],
    "CWE-338": ["weak_generator_in_helper", "secure_sounding_name", "seeded_from_clock", "weak_value_hashed", "secure_seed_for_weak_generator"],
}
BUILD = {  # how the dangerous value is built in vulnerable or hard rows
    "CWE-89": {"python": ["f_string", "concatenation", "percent_format", "format_method"], "c": ["snprintf", "strcat", "sprintf"],
               "cpp": ["string_concatenation", "ostringstream", "std_format"], "go": ["fmt_sprintf", "string_concatenation", "strings_builder"]},
    "CWE-78": {"python": ["f_string", "concatenation", "percent_format", "join_args"], "c": ["snprintf", "strcat", "sprintf"],
               "cpp": ["string_concatenation", "ostringstream", "std_format"], "go": ["fmt_sprintf", "string_concatenation", "strings_join"]},
    "CWE-22": {"python": ["path_join", "concatenation", "pathlib_div", "f_string"], "c": ["snprintf", "strcat", "sprintf"],
               "cpp": ["path_operator", "string_concatenation", "ostringstream"], "go": ["filepath_join", "string_concatenation", "fmt_sprintf"]},
    "CWE-338": {"python": ["python_random_module"], "c": ["libc_rand"], "cpp": ["cpp_std_random", "libc_rand"], "go": ["go_math_rand"]},
}
SAFE_BUILD = {"CWE-89": "parameterised", "CWE-78": "argv", "CWE-22": "contained_path", "CWE-338": "csprng"}
DETAIL = {
    "CWE-89": {"python": ["sqlite3", "psycopg2", "mysql_connector", "sqlalchemy_text", "django_raw"], "c": ["sqlite3_c", "mysql_c", "libpq"],
               "cpp": ["sqlite3_c", "qt_qsqlquery", "mysql_connector_cpp"], "go": ["database_sql", "sqlx", "gorm_raw"]},
    "CWE-78": {"python": ["os_system", "subprocess", "os_popen"], "c": ["system", "popen", "execl_shell"],
               "cpp": ["system", "popen", "qprocess", "boost_process"], "go": ["exec_command_sh", "exec_command"]},
    "CWE-22": {"python": ["open", "pathlib", "shutil", "send_file", "archive_extract", "os_remove"], "c": ["fopen", "open", "unlink", "rename"],
               "cpp": ["fstream", "std_filesystem", "fopen"], "go": ["os_open", "os_readfile", "os_create", "http_servefile", "archive_extract", "os_remove", "os_rename"]},
    "CWE-338": {"python": ["token", "otp", "password", "session", "salt", "key"], "c": ["token", "otp", "password", "session", "salt", "key"],
                "cpp": ["token", "otp", "password", "session", "salt", "key"], "go": ["token", "otp", "password", "session", "salt", "key"]},
}
SINK = {
    "CWE-89": {"python": "cursor.execute", "c": "sqlite3_exec / mysql_query / PQexec", "cpp": "sqlite3_exec / QSqlQuery::exec", "go": "db.Query / db.Exec"},
    "CWE-78": {"python": "os.system / subprocess with shell=True", "c": "system / popen", "cpp": "system / popen", "go": "exec.Command(\"sh\", \"-c\", ...)"},
    "CWE-22": {"python": "open / send_file / os.remove", "c": "fopen / unlink", "cpp": "std::ifstream / std::filesystem", "go": "os.Open / os.ReadFile"},
    "CWE-338": {"python": "random.choice / random.randint", "c": "rand / srand", "cpp": "std::mt19937 / rand", "go": "math/rand"},
}


def split(total: int, parts: int, offset: int) -> list[int]:
    """Split `total` into `parts` near-equal integers; which parts get the extra one rotates with `offset`."""
    base, extra = divmod(total, parts)
    return [base + (1 if (i - offset) % parts < extra else 0) for i in range(parts)]


def spread(items: list, n: int, rng: random.Random) -> list:
    """n values from items, as evenly as possible, in random order."""
    out = [items[i % len(items)] for i in range(n)]
    rng.shuffle(out)
    return out


# ---------- which specification values fit together ----------

TAGS = {cwe: {pool: {t[0]: t[1] for t in items if isinstance(t, tuple)} for pool, items in pools.items()} for cwe, pools in TASKS.items()}
TEXTS = {cwe: {pool: [t[0] if isinstance(t, tuple) else t for t in items] for pool, items in pools.items()} for cwe, pools in TASKS.items()}

K89 = {"value", "number", "multi", "list", "identifier", "stored"}
K78 = {"host", "file", "text", "action", "format", "report"}
PATTERN_FITS = {  # pattern -> test on the task's tags
    "CWE-89": {
        "plain_vulnerable": lambda t: True,
        "standard_safe": lambda t: t["kind"] != "identifier",
        "allow_listed_identifier": lambda t: t["kind"] == "identifier",
        "generated_placeholders": lambda t: t["kind"] == "list",
        "constant_fragments_only": lambda t: t["kind"] == "multi",
        "query_builder_bound": lambda t: t["kind"] in ("value", "number", "multi"),
        "integer_forced": lambda t: t["kind"] == "number",
        "fstring_placeholders_only": lambda t: t["kind"] in ("value", "number", "list", "multi"),
        "hand_written_escaping": lambda t: t["kind"] == "value",
        "keyword_blocklist": lambda t: t["kind"] == "value",
        "param_in_one_branch_only": lambda t: t["kind"] == "multi",
        "identifier_from_input": lambda t: t["kind"] == "identifier",
        "second_order_stored_value": lambda t: t["kind"] == "stored",
    },
    "CWE-78": {
        "plain_vulnerable": lambda t: True,
        "standard_safe": lambda t: True,
        "constant_shell_command": lambda t: t["kind"] == "report",
        "all_args_quoted": lambda t: t["kind"] != "report",
        "argv_list_user_data": lambda t: True,
        "command_from_fixed_map": lambda t: t["kind"] == "action",
        "strict_parser_no_shell": lambda t: t["kind"] in ("host", "format"),
        "end_of_options_marker": lambda t: t["kind"] in ("file", "text", "host"),
        "partial_metachar_filter": lambda t: t["kind"] != "action",
        "quoting_wrong_context": lambda t: t["kind"] != "action",
        "validates_other_variable": lambda t: True,
        "validator_too_permissive": lambda t: t["kind"] in ("host", "format", "file"),
        "argument_injection_dash": lambda t: t["kind"] in ("file", "text", "host"),
    },
    "CWE-22": {
        "plain_vulnerable": lambda t: True,
        "standard_safe": lambda t: True,
        "resolve_then_contain_with_separator": lambda t: True,
        "library_confined_access": lambda t: True,
        "basename_only": lambda t: t["name"] == "flat",
        "id_mapped_to_known_file": lambda t: t["name"] == "choice",
        "safe_filename_fixed_folder": lambda t: t["name"] == "flat",
        "allow_listed_name": lambda t: t["name"] == "choice",
        "check_before_normalise": lambda t: t["name"] != "choice",
        "prefix_without_separator": lambda t: True,
        "single_pass_dotdot_strip": lambda t: t["name"] != "choice",
        "misses_absolute_path": lambda t: True,
        "extension_check_only": lambda t: t.get("ext", False),
    },
}
FIX_FITS = {
    "CWE-89": {"parameterised_query": lambda t: t["kind"] != "identifier", "query_builder_orm": lambda t: t["kind"] != "identifier",
               "type_conversion": lambda t: t["kind"] == "number", "allow_list": lambda t: True},
    "CWE-78": {"argv_no_shell": lambda t: True, "quote_escape": lambda t: True, "allow_list": lambda t: True,
               "validate_format": lambda t: t["kind"] in ("host", "format", "file", "action"),
               "end_of_options": lambda t: t["kind"] in ("file", "text", "host")},
    "CWE-22": {"normalize_prefix_check": lambda t: True, "basename_only": lambda t: t["name"] == "flat",
               "safe_join_library": lambda t: True, "id_to_file_map": lambda t: t["name"] == "choice",
               "validate_format": lambda t: t["name"] in ("flat", "choice")},
}
PATTERN_FIXES = {"argument_injection_dash": {"end_of_options", "validate_format", "allow_list"}}  # fixes that really fix the pattern
DETAIL_OPS = {"open": {"read", "write", "serve"}, "pathlib": {"read", "write", "delete", "serve"}, "shutil": {"rename"},
              "send_file": {"serve"}, "archive_extract": {"extract"}, "os_remove": {"delete"}, "fopen": {"read", "write", "serve"},
              "unlink": {"delete"}, "rename": {"rename"}, "fstream": {"read", "write", "serve"},
              "std_filesystem": {"delete", "rename", "read"}, "os_open": {"read", "serve"}, "os_readfile": {"read", "serve"},
              "os_create": {"write"}, "http_servefile": {"serve"}, "os_rename": {"rename"}}
SHORT_SHAPES = {"plain_function", "method", "callback_or_async"}  # shapes that fit in 1-5 real code lines
SHAPE_SOURCES = {"web_handler": {"web_request", "database_value"},
                 "cli_entry": {"command_line", "environment", "file_content", "database_value"},
                 "callback_or_async": {"network_message", "web_request", "function_argument", "database_value", "file_content"}}
HARD = ("hard_positive", "hard_negative")


def task_fits(cwe, lang, pool, text, pattern) -> bool:
    if pool != "main":
        return pool != "nonsec" or TAGS[cwe][pool][text]["pattern"] == pattern
    t = TAGS[cwe]["main"][text]
    if cwe == "CWE-22" and not any(t["op"] in DETAIL_OPS[d] for d in DETAIL[cwe][lang]):
        return False
    return PATTERN_FITS[cwe][pattern](t) if cwe in PATTERN_FITS else True


def fix_fits(cwe, text, pattern, fix) -> bool:
    if pattern in PATTERN_FIXES and fix not in PATTERN_FIXES[pattern]:
        return False
    return FIX_FITS[cwe][fix](TAGS[cwe]["main"][text]) if cwe in FIX_FITS else True


def source_fits(cwe, text, pool, shape, source) -> bool:
    if source not in SHAPE_SOURCES.get(shape, {source}):
        return False
    if cwe == "CWE-89" and pool == "main" and TAGS[cwe]["main"][text]["kind"] == "stored":
        return source == "database_value"
    return True


def band_fits(case_type, band, shape) -> bool:
    return band != "1-5" or (case_type not in HARD and shape in SHORT_SHAPES)


def fixes_for(cwe, lang):
    f = FIX[cwe][lang] if isinstance(FIX[cwe], dict) else FIX[cwe]
    if cwe == "CWE-22" and lang in ("c", "cpp"):
        f = [x for x in f if x != "safe_join_library"]  # no standard safe-join library in C/C++
    return f


def pick(rng, deck: Counter, ok):
    """Take one value from the deck that passes ok(); prefer values with many left (keeps the spread exact)."""
    c = [v for v, n in deck.items() if n > 0 and ok(v)]
    if not c:
        return None
    top = max(deck[v] for v in c)
    v = rng.choice(sorted(v for v in c if deck[v] >= top - 1))
    deck[v] -= 1
    return v


def try_cell(cwe, lang, ci, rng):
    # case types and bands per model; 1-5 only for non-hard rows
    cell = []
    band_split = {b: split(t, 3, ci + k) for k, (b, t) in enumerate(BANDS.items())}
    for m, (gen, prefix) in enumerate(MODELS):
        n = 9 if m == ci % 3 else 8
        cases = {"normal": n, "hard_positive": 4, "safe": 4, "hard_negative": 15 - n, "no_code": 2}
        rows = [dict(generator=gen, prefix=prefix, case_type=c) for c, k in cases.items() for _ in range(k)]
        bands = [b for b in BANDS for _ in range(band_split[b][m])]
        rng.shuffle(rows)
        easy = [r for r in rows if r["case_type"] not in HARD]
        short = [b for b in bands if b == "1-5"]
        rest = [b for b in bands if b != "1-5"]
        rng.shuffle(rest)
        for r in easy[:len(short)]:
            r["band"] = "1-5"
        for r in [r for r in rows if "band" not in r]:
            r["band"] = rest.pop()
        cell += rows
    # patterns
    for ct, pats in (("hard_negative", HN[cwe]), ("hard_positive", [(p, "main") for p in HP[cwe]])):
        hs = [r for r in cell if r["case_type"] == ct]
        for r, (p, pool) in zip(hs, spread(pats, len(hs), rng)):
            r["pattern"], r["pool"] = p, pool
    for r in cell:
        r.setdefault("pattern", {"normal": "plain_vulnerable", "safe": "standard_safe", "no_code": "no_dangerous_call"}.get(r["case_type"]))
        r.setdefault("pool", "no_code" if r["case_type"] == "no_code" else "main")
    # shapes: short rows first
    shapes = Counter(spread(SHAPES, len(cell), rng))
    for r in sorted(cell, key=lambda r: r["band"] != "1-5"):
        r["shape"] = pick(rng, shapes, lambda s: band_fits(r["case_type"], r["band"], s))
        if r["shape"] is None:
            return None
    # tasks, fixes and sources, most constrained rows first
    vul = [r for r in cell if LABEL[r["case_type"]] == 1]
    fixes = Counter(spread(fixes_for(cwe, lang), len(vul), rng))
    src_rows = [r for r in cell if r["case_type"] != "no_code"]
    sources = Counter(spread(SOURCES, len(src_rows), rng)) if cwe != "CWE-338" else Counter()
    used, by_model = Counter(), {}
    order = sorted(cell, key=lambda r: (r["case_type"] not in HARD, r["pattern"] in ("plain_vulnerable", "standard_safe"), rng.random()))
    for r in order:
        pool, mine = r["pool"], by_model.setdefault(r["generator"], set())

        def usable(t):
            if used[t] >= 2 or t in mine or not task_fits(cwe, lang, pool, t, r["pattern"]):
                return False
            if r in vul and not any(n > 0 and fix_fits(cwe, t, r["pattern"], f) for f, n in fixes.items()):
                return False
            if cwe != "CWE-338" and pool != "no_code" and not any(n > 0 and source_fits(cwe, t, pool, r["shape"], s) for s, n in sources.items()):
                return False
            return True

        cand = [t for t in TEXTS[cwe][pool] if usable(t)]
        if not cand:
            return None
        low = min(used[t] for t in cand)
        t = rng.choice([t for t in cand if used[t] == low])
        used[t] += 1
        mine.add(t)
        r["task_description"] = t
        r["fix_type"] = pick(rng, fixes, lambda f: fix_fits(cwe, t, r["pattern"], f)) if r in vul else ""
        if cwe == "CWE-338" or pool == "no_code":
            r["source"] = "not_applicable"
        else:
            r["source"] = pick(rng, sources, lambda s: source_fits(cwe, t, pool, r["shape"], s))
    # how the value is built, and the library / operation
    risky = [r for r in cell if r["case_type"] in ("normal", "hard_positive")]
    for r, b in zip(risky, spread(BUILD[cwe][lang], len(risky), rng)):
        r["build_style"] = b
    det = Counter()
    for r in cell:
        if r["case_type"] == "hard_negative":
            r["build_style"] = "per_pattern"
        r.setdefault("build_style", "none" if r["case_type"] == "no_code" else SAFE_BUILD[cwe])
        if r["pool"] == "no_code":
            r["cwe_detail"] = "none"
        elif r["pool"] == "nonsec":
            r["cwe_detail"] = "non_security"
        elif cwe == "CWE-338":
            r["cwe_detail"] = TAGS[cwe]["main"][r["task_description"]]["value"]
        else:
            ok = DETAIL[cwe][lang]
            if cwe == "CWE-22":
                op = TAGS[cwe]["main"][r["task_description"]]["op"]
                ok = [d for d in ok if op in DETAIL_OPS[d]]
            low = min(det[d] for d in ok)
            r["cwe_detail"] = rng.choice([d for d in ok if det[d] == low])
            det[r["cwe_detail"]] += 1
        lo, hi = BAND_RANGE[r["band"]]
        r.update(cwe=cwe, language=lang, label=LABEL[r["case_type"]], target_lines=rng.randint(lo, hi),
                 suggested_sink="" if r["case_type"] == "no_code" else SINK[cwe][lang])
    return cell


def build() -> pd.DataFrame:
    rows = []
    for ci, (cwe, lang) in enumerate([(c, l) for c in CWES for l in LANGS]):
        for attempt in range(20000):
            cell = try_cell(cwe, lang, ci, random.Random(SEED * 1000 + ci * 100003 + attempt))
            if cell:
                break
        else:
            raise SystemExit(f"could not plan {cwe} {lang}: add tasks that fit the patterns and fixes")
        rows += cell
    d = pd.DataFrame(rows)
    d = d.sort_values(["generator", "cwe", "language", "case_type"], kind="stable").reset_index(drop=True)
    d["sample_id"] = [f"{p}_{SHORT[c]}_{SHORT[l]}_{i:04d}" for i, (p, c, l) in enumerate(zip(d.prefix, d.cwe, d.language), 1)]
    cols = ["sample_id", "generator", "language", "cwe", "case_type", "label", "task_description", "cwe_detail", "band", "target_lines",
            "build_style", "source", "fix_type", "pattern", "suggested_sink", "shape"]
    return d[cols]


def fits(r) -> list:
    """Every compatibility rule, checked again on the finished plan."""
    cwe, lang, ct = r.cwe, r.language, r.case_type
    pool = "no_code" if ct == "no_code" else ("nonsec" if r.cwe_detail == "non_security" else "main")
    bad = []
    if not band_fits(ct, r.band, r.shape):
        bad.append("band/shape")
    if not task_fits(cwe, lang, pool, r.task_description, r.pattern):
        bad.append("task/pattern")
    if r.fix_type and not fix_fits(cwe, r.task_description, r.pattern, r.fix_type):
        bad.append("task/fix")
    if r.source != "not_applicable" and not source_fits(cwe, r.task_description, pool, r.shape, r.source):
        bad.append("source")
    if cwe == "CWE-22" and pool == "main" and TAGS[cwe]["main"][r.task_description]["op"] not in DETAIL_OPS[r.cwe_detail]:
        bad.append("detail/op")
    if cwe == "CWE-338" and pool == "main" and TAGS[cwe]["main"][r.task_description]["value"] != r.cwe_detail:
        bad.append("detail/value")
    return bad


def check(d: pd.DataFrame) -> bool:
    ok = True

    def need(cond, msg):
        nonlocal ok
        if not cond:
            ok = False
            print("FAIL:", msg)

    need(len(d) == 1200, f"rows {len(d)}")
    need(d.sample_id.is_unique, "sample_id unique")
    for (c, l), g in d.groupby(["cwe", "language"]):
        need(len(g) == 75, f"{c} {l} rows {len(g)}")
        need(g.case_type.value_counts().to_dict() == CASES, f"{c} {l} case types {g.case_type.value_counts().to_dict()}")
        need(g.band.value_counts().to_dict() == BANDS, f"{c} {l} bands")
        v = g[g.label == 1].fix_type.value_counts(normalize=True)
        need(len(v) >= 3 and v.max() <= 0.40, f"{c} {l} fix types {v.round(2).to_dict()}")
        h = g[g.case_type.isin(["hard_negative", "hard_positive"])]
        for ct, x in h.groupby("case_type"):
            need(x.pattern.value_counts(normalize=True).max() <= 0.25, f"{c} {l} {ct} pattern share")
        need(g["shape"].value_counts(normalize=True).max() <= 0.40 and g["shape"].nunique() >= 4, f"{c} {l} shapes")
        if c != "CWE-338":
            s = g[g.source != "not_applicable"].source.value_counts(normalize=True)
            need(len(s) >= 4 and s.max() <= 0.40, f"{c} {l} sources")
        bad = [(r.sample_id, b) for r in g.itertuples() for b in fits(r)]
        need(not bad, f"{c} {l} incompatible rows {bad[:5]}")
        need(not ((g.band == "1-5") & g.case_type.isin(HARD)).any(), f"{c} {l} hard row in 1-5 band")
        tc = g.task_description.value_counts()
        need(tc.max() <= 2, f"{c} {l} task repeats {tc.max()}")
        need(not g.duplicated(["generator", "task_description"]).any(), f"{c} {l} task repeated within a model")
        for gen, x in g.groupby("generator"):
            need(len(x) == 25, f"{c} {l} {gen} rows {len(x)}")
    for gen, x in d.groupby("generator"):
        need(len(x) == 400, f"{gen} rows {len(x)}")
    print(pd.crosstab([d.cwe, d.language], d.case_type).to_string())
    print(pd.crosstab(d.generator, d.case_type, margins=True).to_string())
    print(pd.crosstab([d.cwe], d.band).to_string())
    print("fix types:", d[d.label == 1].groupby("cwe").fix_type.value_counts().to_dict())
    print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
    return ok


if __name__ == "__main__":
    d = build()
    if not check(d):
        sys.exit(1)
    (ROOT / "plan").mkdir(exist_ok=True)
    d.to_csv(ROOT / "plan" / "all_rows.csv", index=False)
    print("wrote plan/all_rows.csv")
