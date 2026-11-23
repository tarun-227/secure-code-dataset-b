"""Automatic checks shared by generate.py (to retry bad drafts) and validate.py (to report problems).

- syntax_problems: does the code parse / compile, and are imports present?
- flagged: a rough pattern check for the dangerous form of each weakness. It is a heuristic, used only where
  the answer is clear: plain vulnerable rows must be flagged, safe rows and fixes that remove the dangerous
  call must not be. Hard rows are never judged by it.
- take_markers: turns the model's end-of-line markers into vulnerable_lines.
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import tempfile

HINT = re.compile(r"(?i)vulnerab|insecure|\bunsafe\b|sanitiz|sanitis|exploit|inject|\bcwe[-_ ]?\d|\bfix(ed|es)?\b|attack|malicious|\bhack|\bsecure version\b|\bsafe version\b|\bbad\b.*\binput\b")
MARK = re.compile(r"[ \t]*(?:#|//)[ \t]*@@[ \t]*$")
FENCE = re.compile(r"```[A-Za-z0-9+#_-]*[ \t]*\n(.*?)```", re.S)

# fixes after which the dangerous call itself is gone, so the fixed code must not be flagged
REMOVES = {"parameterised_query", "query_builder_orm", "argv_no_shell", "end_of_options", "secrets_module", "system_random",
           "os_urandom", "os_random_api", "dev_urandom", "csprng_library", "crypto_rand_read", "crypto_rand_int",
           "crypto_rand_text", "normalize_prefix_check", "basename_only", "safe_join_library"}


# ---------- reading the model's answer ----------

def extract_code(text: str) -> str:
    """The first fenced code block, or the whole answer if there is none."""
    m = FENCE.search(text)
    code = m.group(1) if m else text
    return code.strip("\n").rstrip()


def take_markers(code: str):
    """Remove '# @@' / '// @@' end-of-line markers; return (clean code, marked line numbers)."""
    out, marked = [], []
    for i, line in enumerate(code.split("\n"), 1):
        if MARK.search(line):
            marked.append(i)
            line = MARK.sub("", line)
        out.append(line.rstrip())
    return "\n".join(out), marked


def give_away(text: str):
    words = re.sub(r"([a-z])([A-Z])", r"\1 \2", text).replace("_", " ")
    m = HINT.search(words)
    return m.group(0) if m else None


# ---------- does it parse / compile ----------

def _python(code):
    try:
        tree = ast.parse(code)
    except SyntaxError as x:
        return [f"not valid Python: line {x.lineno}: {x.msg}"]
    try:
        from pyflakes import checker
    except ImportError:
        return []
    out = []
    for m in checker.Checker(tree, filename="row.py").messages:
        if type(m).__name__ in ("UndefinedName", "UndefinedExport", "UndefinedLocal"):
            out.append(f"line {m.lineno}: {m.message % m.message_args} (missing import?)")
    return out


def _run(cmd, suffix, code):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(code)
    try:
        p = subprocess.run(cmd + [path], capture_output=True, text=True, timeout=60)
        return p.returncode, (p.stderr or "") + (p.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        return None, ""
    finally:
        os.remove(path)


def _c_like(code, lang):
    cc = shutil.which("gcc" if lang == "c" else "g++") or shutil.which("clang" if lang == "c" else "clang++")
    if not cc:
        return []
    flags = ["-fsyntax-only"] + (["-Werror=implicit-function-declaration"] if lang == "c" else ["-std=c++17"])
    rc, err = _run([cc] + flags, ".c" if lang == "c" else ".cpp", code)
    if rc in (0, None):
        return []
    if re.search(r"fatal error: .*: No such file or directory", err):
        return []  # a library header (sqlite3.h, libpq-fe.h, ...) is not installed here; cannot check further
    errs = [re.sub(r"^.*?:(\d+):\d+: ", r"line \1: ", l) for l in err.splitlines() if " error: " in l]
    return errs[:3] or ["does not compile"]


GO_PKG = re.compile(r"\b(fmt|os|exec|sql|rand|strings|filepath|path|strconv|http|io|ioutil|bufio|log|time|errors|context|json|hex|base64|big|bytes|url|sync|regexp|sort|gorm|sqlx|binary|subtle|mathrand|crand)\.[A-Z]\w*")


def _go(code):
    out = []
    src = code if re.search(r"^package\s+\w+", code, re.M) else "package p\n\n" + code
    gofmt = shutil.which("gofmt")
    if gofmt:
        rc, err = _run([gofmt, "-e", "-l"], ".go", src)
        if rc not in (0, None):
            out += [re.sub(r"^.*?:(\d+):\d+: ", r"line \1: ", l) for l in err.splitlines() if l.strip()][:3]
    imports = re.findall(r'^\s*(?:import\s+)?(\w+\s+)?"([\w./-]+)"', code, re.M)
    names = set()
    for alias, path in imports:
        parts = path.rstrip("/").split("/")
        names.add(alias.strip() if alias.strip() else (parts[-2] if parts[-1] == "v2" and len(parts) > 1 else parts[-1]))
    for pkg in sorted(set(GO_PKG.findall(code)) - names):
        out.append(f"uses {pkg}. but does not import it")
    return out


def syntax_problems(code: str, lang: str):
    if not code.strip():
        return ["code is empty"]
    probs = []
    if max(len(l) for l in code.split("\n")) > 220:
        probs.append("a line is longer than 220 characters (code squashed onto one line?)")
    probs += {"python": _python, "go": _go}.get(lang, lambda c: _c_like(c, lang))(code)
    return probs


# ---------- rough check for the dangerous form ----------

SQL = r"(?i)\b(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where\s|order\s+by|values\s*\(|like\s)"
STR = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`[^`]*`)'


def _strings(line):
    return re.findall(STR, line)


def _89(code, lang):
    for line in code.split("\n"):
        s = " ".join(_strings(line))
        has_sql = re.search(SQL, s) or re.search(r"""['"]\s*\w*\s*=\s*'['"]""", line)  # ... name = '" + x
        if lang == "python":
            if re.search(r"""\b[fF][rR]?("[^"]*\{|'[^']*\{)""", line) and re.search(SQL, line):
                return True
            if has_sql and re.search(r"""["']\s*%\s*[\w(]|\.format\(|["']\s*\+\s*\w|\w\s*\+\s*["']""", line):
                return True
        else:
            if has_sql and re.search(r"""["`]\s*\+\s*\w|\w\s*\+\s*["`]|printf\s*\(|Sprintf\(|<<\s*\w|std::format|format\(|\.arg\(""", line):
                return True
        if re.search(r"\b(strn?cat|WriteString|append)\s*\(\s*\w+\s*,\s*[A-Za-z_][\w.\[\]>-]*\s*\)", line) and re.search(SQL, code):
            return True
    return False


SHELL_CALL = {
    "python": r"\bos\.system\(|\bos\.popen\(|shell\s*=\s*True|\bgetoutput\(|\bgetstatusoutput\(",
    "c": r"\bsystem\s*\(|\bpopen\s*\(|\bexecl\w*\s*\(\s*\"/bin/(ba)?sh\"",
    "cpp": r"\bsystem\s*\(|\bpopen\s*\(|\bexecl\w*\s*\(\s*\"/bin/(ba)?sh\"|bp::system\(|boost::process::system\(",
    "go": r"exec\.Command(Context)?\([^)]*\"(/bin/)?(ba)?sh\"\s*,\s*\"-c\"",
}


def _78(code, lang):
    lines = code.split("\n")
    for i, line in enumerate(lines):
        if not re.search(SHELL_CALL[lang], line):
            continue
        if lang == "go":
            tail = re.split(r"\"-c\"\s*,", line, 1)[-1]
            if not re.match(r"\s*\"(?:\\.|[^\"\\])*\"\s*\)", tail):
                return True
            continue
        # constant command: the whole argument is one string literal
        if re.search(r"""(system|popen)\s*\(\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*[,)]""", line) and "+" not in line and "%" not in line:
            continue
        if lang == "python" and re.search(r"""run\(|call\(|Popen\(|check_output\(|check_call\(""", line) and \
                re.search(r"""\(\s*\[""", line):
            continue
        return True
    return False


FILE_OP = {
    "python": r"\bopen\(|send_file\(|send_from_directory\(|os\.remove\(|os\.unlink\(|os\.rename\(|shutil\.\w+\(|\.read_(text|bytes)\(|\.write_(text|bytes)\(|\.unlink\(|extractall\(",
    "c": r"\bfopen\s*\(|\bunlink\s*\(|\brename\s*\(|\bremove\s*\(|\bopen\s*\(",
    "cpp": r"\bifstream\b|\bofstream\b|\bfstream\b|std::filesystem::(remove|rename|copy\w*)\(|fs::(remove|rename|copy\w*)\(|\bfopen\s*\(",
    "go": r"os\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|Rename)\(|ioutil\.ReadFile\(|http\.ServeFile\(",
}
GUARD_22 = r"realpath|abspath|commonpath|is_relative_to|relative_to\(|basename|secure_filename|safe_join|send_from_directory|\.name\b|filepath\.Base|filepath\.Rel|filepath\.IsLocal|OpenInRoot|os\.Root|weakly_canonical|canonical\(|lexically_normal|strstr\([^)]*\"\.\.\"|\.find\(\s*\"\.\.\"|strings\.Contains\([^)]*\"\.\.\""


def _22(code, lang):
    return bool(re.search(FILE_OP[lang], code)) and not re.search(GUARD_22, code)


WEAK_338 = {
    "python": r"(?<![\w.])random\.(choice|choices|randint|randrange|random|getrandbits|sample|shuffle|uniform)\(|^\s*from\s+random\s+import",
    "c": r"\b(rand|random|srand|srandom|drand48|lrand48|rand_r)\s*\(",
    "cpp": r"\bmt19937(_64)?\b|\bminstd_rand0?\b|\bdefault_random_engine\b|\b(rand|srand)\s*\(",
    "go": r"\"math/rand(/v2)?\"",
}


def _338(code, lang):
    return bool(re.search(WEAK_338[lang], code, re.M))


def flagged(code: str, lang: str, cwe: str) -> bool:
    return {"CWE-89": _89, "CWE-78": _78, "CWE-22": _22, "CWE-338": _338}[cwe](code, lang)


# hard rows whose pattern makes the rough check clear-cut
HARD_NEG_CLEAN = {"query_builder_bound", "argv_list_user_data", "strict_parser_no_shell", "end_of_options_marker",
                  "command_from_fixed_map", "resolve_then_contain_with_separator", "basename_only", "safe_filename_fixed_folder"}
HARD_POS_FLAGGED_CWE = {"CWE-89", "CWE-338"}


def label_problems(r, code: str, fixed: str = ""):
    """Problems where the rough check clearly disagrees with the row's case type and pattern."""
    out, ct, cwe, lang = [], r["case_type"], r["cwe"], r["language"]
    must_flag = ct == "normal" or (ct == "hard_positive" and cwe in HARD_POS_FLAGGED_CWE)
    if must_flag and not flagged(code, lang, cwe):
        out.append(f"the code does not seem to contain the dangerous form; a '{ct}' row must really be vulnerable")
    if ct == "hard_negative" and r["pattern"] in HARD_NEG_CLEAN and flagged(code, lang, cwe):
        out.append("the code seems to contain the dangerous form; a 'hard_negative' row must be completely safe")
    if ct == "safe" and flagged(code, lang, cwe):
        out.append("the code seems to contain the dangerous form; a 'safe' row must be safe")
    if fixed and r["fix_type"] in REMOVES and flagged(fixed, lang, cwe):
        out.append("fixed_code still seems to contain the dangerous form")
    return out
