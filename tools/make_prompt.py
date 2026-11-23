"""The prompts sent to the model for one row of an issue CSV.

Each row uses up to two prompts:
  1. prompt(r)              writes the code. In vulnerable rows the model ends each dangerous line with a marker
                            comment (# @@ or // @@); generate.py turns the markers into vulnerable_lines and removes them.
  2. fix_prompt(r, code)    (vulnerable rows only) rewrites that code into fixed_code, changing as few lines as possible.

Usage: python tools/make_prompt.py issues/lla-1_01.csv --row 3
       python tools/make_prompt.py issues/lla-1_01.csv --id lla_89_py_0007
tools/generate.py sends these for you; print them here if you want to paste them into `ollama run` yourself.
"""
from __future__ import annotations

import argparse

from common import BAND_RANGE, read_rows
from vocab import CASE, CWE_NAME, FIX, LANG_NAME, PATTERN, SHAPE, SHAPE_BY_LANG, SOURCE, VALUE

FENCE = {"python": "python", "c": "c", "cpp": "cpp", "go": "go"}
MARKER = {"python": "# @@", "c": "// @@", "cpp": "// @@", "go": "// @@"}
OBJECT = {"CWE-89": "SQL query", "CWE-78": "shell command", "CWE-22": "file path", "CWE-338": "random value"}

BUILD = {
    "f_string": 'a Python f-string that puts the input straight into the text, like f"... {value} ..."',
    "percent_format": 'the Python % operator on the string, like "... \'%s\' ..." % value (the % operator, NOT a driver placeholder with a separate argument)',
    "format_method": 'str.format(), like "... {} ...".format(value)',
    "string_concatenation": "string concatenation with +",
    "concatenation": "string concatenation with +",
    "sprintf": "sprintf with %s",
    "snprintf": "snprintf with %s",
    "strcat": "strcpy/strcat",
    "ostringstream": "std::ostringstream and <<",
    "std_format": "std::format (or std::string concatenation)",
    "fmt_sprintf": "fmt.Sprintf with %s",
    "strings_builder": "strings.Builder",
    "strings_join": "strings.Join",
    "join_args": "joining the arguments into one string",
    "path_join": "os.path.join with the input",
    "pathlib_div": "pathlib's / operator with the input",
    "path_operator": "std::filesystem::path and the / operator with the input",
    "filepath_join": "filepath.Join with the input",
    "libc_rand": "rand() (optionally seeded with srand)",
    "python_random_module": "the random module (random.choice, random.randint, ...)",
    "go_math_rand": "math/rand",
    "cpp_std_random": "std::mt19937 or rand()",
}
SAFE_WAY = {
    "CWE-89": "bound parameters (placeholders) for every value",
    "CWE-78": "an argument list with no shell",
    "CWE-22": "resolve the path and check it stays inside the base folder before using it",
    "CWE-338": {"python": "the secrets module", "c": "getrandom() or getentropy()", "cpp": "getrandom() or OpenSSL RAND_bytes",
                "go": "crypto/rand"},
}
AVOID = {"CWE-89": "bound parameters or placeholders", "CWE-78": "argument list without a shell", "CWE-22": "path checks"}
NAMES = {"mysql_connector": "mysql.connector", "sqlalchemy_text": "SQLAlchemy text()", "django_raw": "Django raw SQL",
         "libpq": "libpq", "mysql_c": "the MySQL C API", "sqlite3_c": "the SQLite C API", "mysql_connector_cpp": "MySQL Connector/C++",
         "qt_qsqlquery": "Qt QSqlQuery", "database_sql": "database/sql", "gorm_raw": "GORM raw SQL", "os_system": "os.system",
         "os_popen": "os.popen", "system": "system()", "popen": "popen()", "execl_shell": 'execl("/bin/sh", "sh", "-c", ...)',
         "boost_process": "Boost.Process", "qprocess": "Qt QProcess", "exec_command": "exec.Command",
         "exec_command_sh": 'exec.Command("sh", "-c", ...)', "http_servefile": "http.ServeFile", "send_file": "Flask send_file",
         "os_open": "os.Open", "os_readfile": "os.ReadFile", "os_create": "os.Create", "os_remove": "os.Remove",
         "std_filesystem": "std::filesystem", "fstream": "std::fstream", "archive_extract": "archive extraction"}


def _detail(r) -> str:
    cwe, d = r["cwe"], r["cwe_detail"]
    if d in ("none", "") or r["case_type"] == "no_code":
        return ""
    if cwe == "CWE-338":
        return "" if d == "non_security" else f"The random value is used as a {VALUE[d]}."
    name = NAMES.get(d, d.replace("_", " "))
    return {"CWE-89": f"Database library: {name}.", "CWE-78": f"Run the program using {name} (or its safe form where the code must be safe).",
            "CWE-22": f"File operation: {name}."}[cwe]


def prompt(r) -> str:
    lang, cwe, ct = LANG_NAME[r["language"]], r["cwe"], r["case_type"]
    lo, hi = BAND_RANGE[r["band"]]
    shape = SHAPE_BY_LANG.get(r["shape"], {}).get(r["language"], SHAPE[r["shape"]])
    obj = OBJECT[cwe]
    L = [f"Write {lang} code for a code dataset.", "",
         f"Task: {r['task_description']}",
         f"Write it as {shape}."]
    if _detail(r):
        L.append(_detail(r))
    if r["source"] != "not_applicable" and ct != "no_code":
        L.append(f"The input comes from {SOURCE[r['source']]}.")
    L.append(f"Length: about {r['target_lines']} lines in total, at least {lo} and at most {hi}, counting imports and blank lines.")
    if hi <= 10:
        L.append("This is short: write only what the task needs.")
    elif lo >= 41:
        L.append("This is a longer piece of code: include realistic surrounding logic such as reading and checking the input, error handling, logging and a small helper.")
    if cwe == "CWE-89" and r["shape"] != "cli_entry" and lo < 41 and ct != "no_code":
        L.append("Take an already open database connection (or cursor) as a parameter instead of connecting yourself.")
    L += ["", "What the code must be:"]
    build = BUILD.get(r["build_style"], r["build_style"].replace("_", " "))
    how = (f"Make the secret value with {build}." if cwe == "CWE-338"
           else f"Build the {obj} from the input using {build}, and pass it to {r['suggested_sink']}.")
    if ct == "normal":
        L.append(f"- It is open to {CWE_NAME[cwe]} ({cwe}). {how}")
        if cwe != "CWE-338":
            L.append(f"- Do NOT protect it in any way: no {AVOID[cwe]}, no checks, no escaping.")
    elif ct == "hard_positive":
        L.append(f"- It is open to {CWE_NAME[cwe]} ({cwe}), but it looks protected: {PATTERN[r['pattern']]}.")
        L.append(f"- {how} The protection must NOT really work.")
    elif ct == "safe":
        way = SAFE_WAY[cwe][r["language"]] if cwe == "CWE-338" else SAFE_WAY[cwe]
        L.append(f"- It is safe from {CWE_NAME[cwe]}, written the standard way: use {way}.")
    elif ct == "hard_negative":
        L.append(f"- It is completely safe from {CWE_NAME[cwe]}, although it looks risky: {PATTERN[r['pattern']]}.")
    else:
        L.append(f"- {CASE['no_code'].capitalize()}: {PATTERN['no_dangerous_call']}.")
    L += ["", "Rules:",
          f"- One complete {lang} file: every import{' and #include' if r['language'] in ('c', 'cpp') else ''} at the top"
          + (", starting with a package line" if r["language"] == "go" else "") + ".",
          "- No example usage, no tests" + ("" if r["shape"] == "cli_entry" else ", no main function") + ", no explanation.",
          "- No comment, name or string may hint whether the code is safe or not (avoid words like vulnerable, unsafe, sanitize, fixed, attack, injection, exploit).",
          "- Keep each statement on its own line."]
    if r["label"] == "1":
        L.append(f"- Put the comment {MARKER[r['language']]} at the end of every line that builds or uses the dangerous {obj}.")
    L += ["", f"Reply with only one ```{FENCE[r['language']]} code block."]
    return "\n".join(L)


def fix_prompt(r, code: str) -> str:
    lang, cwe = LANG_NAME[r["language"]], r["cwe"]
    return "\n".join([
        f"Here is {lang} code:", "", f"```{FENCE[r['language']]}", code, "```", "",
        f"Change it so it is no longer open to {CWE_NAME[cwe]} ({cwe}). Do it this way: {FIX[r['fix_type']]}.", "",
        "Rules:",
        "- Change as few lines as possible (at most 10). Every other line stays exactly the same.",
        "- Keep the same function names, parameters and structure. Add an import only if the change needs it.",
        "- Do not add comments about the change. No word like vulnerable, unsafe, sanitize, fixed, attack or injection.", "",
        f"Reply with only the complete new code in one ```{FENCE[r['language']]} code block."])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--row", type=int)
    ap.add_argument("--id")
    a = ap.parse_args()
    d = read_rows(a.file)
    r = d[d.sample_id == a.id].iloc[0] if a.id else d.iloc[(a.row or 1) - 1]
    print(prompt(r))
    if r["label"] == "1":
        print("\n----- then, for the fix (paste the code from the first answer, without the @@ markers, where CODE is) -----\n")
        print(fix_prompt(r, "CODE"))
