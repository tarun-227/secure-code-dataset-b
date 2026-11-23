"""Generate the 1,200 row specifications of Dataset B (plan/all_rows.csv) so that every distribution target holds exactly.

Per model: 400 rows = 16 cells (4 weaknesses x 4 languages) x 25 rows.
Per cell (75 rows over the three models): normal 25, hard_positive 12, safe 12, hard_negative 20, no_code 6.
Length bands per cell: 1-5: 7, 6-10: 19, 11-20: 22, 21-40: 19, 41-100: 8.
Fix types, patterns, input sources and shapes are spread as evenly as possible with the caps printed by --check.

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
               "cpp": ["fstream", "std_filesystem", "fopen"], "go": ["os_open", "os_readfile", "os_create", "http_servefile", "archive_extract"]},
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


def build() -> pd.DataFrame:
    rng = random.Random(SEED)
    rows = []
    for ci, (cwe, lang) in enumerate([(c, l) for c in CWES for l in LANGS]):
        # case types per model: normal + hard_negative = 15 for every model; the extra normal rotates
        per_model = []
        for m in range(3):
            n = 9 if m == ci % 3 else 8
            per_model.append({"normal": n, "hard_positive": 4, "safe": 4, "hard_negative": 15 - n, "no_code": 2})
        # length bands: each band's cell total split over the models
        band_split = {b: split(t, 3, ci + k) for k, (b, t) in enumerate(BANDS.items())}
        cell = []
        for m, (gen, prefix) in enumerate(MODELS):
            cases = [c for c, k in per_model[m].items() for _ in range(k)]
            bands = [b for b in BANDS for _ in range(band_split[b][m])]
            assert len(cases) == len(bands) == 25, (cwe, lang, m)
            rng.shuffle(bands)
            # short bands are never given to no_code rows only by chance; keep the mix by sorting both lists the same way
            cell += [dict(generator=gen, prefix=prefix, case_type=c, band=b) for c, b in zip(cases, bands)]
        # attributes spread over the whole cell
        vul = [r for r in cell if LABEL[r["case_type"]] == 1]
        fixes = FIX[cwe][lang] if isinstance(FIX[cwe], dict) else FIX[cwe]
        for r, f in zip(vul, spread(fixes, len(vul), rng)):
            r["fix_type"] = f
        hn = [r for r in cell if r["case_type"] == "hard_negative"]
        for r, (p, pool) in zip(hn, spread(HN[cwe], len(hn), rng)):
            r["pattern"], r["pool"] = p, pool
        hp = [r for r in cell if r["case_type"] == "hard_positive"]
        for r, p in zip(hp, spread(HP[cwe], len(hp), rng)):
            r["pattern"] = p
        for r in cell:
            r.setdefault("pattern", {"normal": "plain_vulnerable", "safe": "standard_safe", "no_code": "no_dangerous_call"}.get(r["case_type"]))
            r.setdefault("pool", "no_code" if r["case_type"] == "no_code" else "main")
            r.setdefault("fix_type", "")
        for r, s in zip(cell, spread(SHAPES, len(cell), rng)):
            r["shape"] = s
        if cwe == "CWE-338":
            for r in cell:
                r["source"] = "not_applicable"
        else:
            src = [r for r in cell if r["case_type"] != "no_code"]
            for r, s in zip(src, spread(SOURCES, len(src), rng)):
                r["source"] = s
            for r in cell:
                r.setdefault("source", "not_applicable")
        builds = BUILD[cwe][lang]
        risky = [r for r in cell if r["case_type"] in ("normal", "hard_positive")]
        for r, b in zip(risky, spread(builds, len(risky), rng)):
            r["build_style"] = b
        for r in cell:
            if r["case_type"] == "hard_negative":
                r["build_style"] = "per_pattern"
        for r in cell:
            r.setdefault("build_style", "none" if r["case_type"] == "no_code" else SAFE_BUILD[cwe])
        for r, d in zip(cell, spread(DETAIL[cwe][lang], len(cell), rng)):
            r["cwe_detail"] = d if r["case_type"] != "no_code" else "none"
            if r["pool"] == "nonsec":
                r["cwe_detail"] = "non_security"
        # tasks: at most 2 uses per task in a cell, never twice for the same model in a cell
        for pool in ("main", "no_code", "nonsec"):
            members = [r for r in cell if r["pool"] == pool]
            if not members:
                continue
            tasks = TASKS[cwe][pool][:]
            rng.shuffle(tasks)
            used, by_model = Counter(), {}
            for r in members:
                choices = [t for t in tasks if used[t] < 2 and t not in by_model.setdefault(r["generator"], set())]
                choices.sort(key=lambda t: used[t])
                t = choices[0]
                used[t] += 1
                by_model[r["generator"]].add(t)
                r["task_description"] = t
        for r in cell:
            lo, hi = BAND_RANGE[r["band"]]
            r.update(cwe=cwe, language=lang, label=LABEL[r["case_type"]], target_lines=rng.randint(lo, hi),
                     suggested_sink="" if r["case_type"] == "no_code" else SINK[cwe][lang])
        rows += cell
    d = pd.DataFrame(rows)
    d = d.sort_values(["generator", "cwe", "language", "case_type"], kind="stable").reset_index(drop=True)
    d["sample_id"] = [f"{p}_{SHORT[c]}_{SHORT[l]}_{i:04d}" for i, (p, c, l) in enumerate(zip(d.prefix, d.cwe, d.language), 1)]
    cols = ["sample_id", "generator", "language", "cwe", "case_type", "label", "task_description", "cwe_detail", "band", "target_lines",
            "build_style", "source", "fix_type", "pattern", "suggested_sink", "shape"]
    return d[cols]


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
