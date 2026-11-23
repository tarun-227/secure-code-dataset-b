"""Writes examples/example_rows.csv: 10 complete rows (Python CWE-89 and C CWE-78, one per case type)."""
import json
from pathlib import Path

import pandas as pd
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from common import code_lines  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

PY = {
"normal": ('''def find_user(conn, username):
    cur = conn.cursor()
    query = f"SELECT id, email FROM users WHERE username = '{username}'"
    cur.execute(query)
    return cur.fetchone()''', '''def find_user(conn, username):
    cur = conn.cursor()
    query = "SELECT id, email FROM users WHERE username = ?"
    cur.execute(query, (username,))
    return cur.fetchone()''', [3, 4]),
"hard_positive": ('''BLOCKED = ("--", ";", "drop ", "union ")


def search_products(conn, term):
    lowered = term.lower()
    for word in BLOCKED:
        if word in lowered:
            raise ValueError("invalid search term")
    sql = "SELECT name, price FROM products WHERE name LIKE '%" + term + "%'"
    return conn.execute(sql).fetchall()''', '''BLOCKED = ("--", ";", "drop ", "union ")


def search_products(conn, term):
    lowered = term.lower()
    for word in BLOCKED:
        if word in lowered:
            raise ValueError("invalid search term")
    sql = "SELECT name, price FROM products WHERE name LIKE ?"
    return conn.execute(sql, ("%" + term + "%",)).fetchall()''', [9, 10]),
"safe": ('''def orders_since(conn, customer_id, since):
    rows = conn.execute(
        "SELECT id, total FROM orders WHERE customer_id = ? AND created >= ?",
        (customer_id, since),
    )
    return rows.fetchall()''', "", []),
"hard_negative": ('''SORT_COLUMNS = {"date": "created_at", "title": "title", "views": "view_count"}


def latest_posts(conn, category, sort_by):
    column = SORT_COLUMNS.get(sort_by, "created_at")
    sql = f"SELECT id, title FROM posts WHERE category = ? ORDER BY {column} DESC LIMIT 20"
    return conn.execute(sql, (category,)).fetchall()''', "", []),
"no_code": ('''def orders_to_csv(orders):
    lines = ["id,total,status"]
    for order in orders:
        lines.append(f"{order['id']},{order['total']:.2f},{order['status']}")
    return "\\n".join(lines)''', "", []),
}

C = {
"normal": ('''#include <stdio.h>
#include <stdlib.h>

int ping_host(const char *host) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ping -c 3 %s", host);
    return system(cmd);
}''', '''#include <unistd.h>
#include <sys/wait.h>

int ping_host(const char *host) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("ping", "ping", "-c", "3", "--", host, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}''', [6, 7]),
"hard_positive": ('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int count_lines(const char *path) {
    if (strpbrk(path, ";&|") != NULL)
        return -1;
    char cmd[512];
    snprintf(cmd, sizeof cmd, "wc -l %s", path);
    return system(cmd);
}''', '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int count_lines(const char *path) {
    if (path[0] == '-' || strspn(path, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/") != strlen(path))
        return -1;
    char cmd[512];
    snprintf(cmd, sizeof cmd, "wc -l %s", path);
    return system(cmd);
}''', [6, 9, 10]),
"safe": ('''#include <unistd.h>
#include <sys/wait.h>

int show_disk_usage(const char *folder) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("du", "du", "-sh", "--", folder, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}''', "", []),
"hard_negative": ('''#include <stdlib.h>
#include <string.h>

int restart_service(const char *name) {
    static const char *commands[][2] = {
        {"web", "systemctl restart nginx"},
        {"db", "systemctl restart postgresql"},
        {"cache", "systemctl restart redis"},
    };
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++) {
        if (strcmp(name, commands[i][0]) == 0)
            return system(commands[i][1]);
    }
    return -1;
}''', "", []),
"no_code": ('''#include <stdio.h>

void format_size(unsigned long long bytes, char *out, size_t len) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = (double)bytes;
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        unit++;
    }
    snprintf(out, len, "%.1f %s", value, units[unit]);
}''', "", []),
}

SPEC = {
("python", "normal"): dict(task_description="Look up a user's profile by username.", cwe_detail="sqlite3", build_style="f_string", source="function_argument", fix_type="parameterised_query", pattern="plain_vulnerable", shape="plain_function"),
("python", "hard_positive"): dict(task_description="Search products whose name contains a search term.", cwe_detail="sqlite3", build_style="concatenation", source="web_request", fix_type="parameterised_query", pattern="keyword_blocklist", shape="plain_function"),
("python", "safe"): dict(task_description="Return all orders placed by a customer after a given date.", cwe_detail="sqlite3", build_style="parameterised", source="function_argument", fix_type="", pattern="standard_safe", shape="plain_function"),
("python", "hard_negative"): dict(task_description="List the newest posts in a category, sorted by a chosen column.", cwe_detail="sqlite3", build_style="per_pattern", source="web_request", fix_type="", pattern="allow_listed_identifier", shape="plain_function"),
("python", "no_code"): dict(task_description="Format a list of order records as CSV text.", cwe_detail="none", build_style="none", source="not_applicable", fix_type="", pattern="no_dangerous_call", shape="plain_function"),
("c", "normal"): dict(task_description="Ping a host given by the user and return the output.", cwe_detail="system", build_style="snprintf", source="function_argument", fix_type="argv_no_shell", pattern="plain_vulnerable", shape="plain_function"),
("c", "hard_positive"): dict(task_description="Count the lines in a file using a system tool.", cwe_detail="system", build_style="snprintf", source="command_line", fix_type="validate_format", pattern="partial_metachar_filter", shape="plain_function"),
("c", "safe"): dict(task_description="Check the disk usage of a folder.", cwe_detail="execl_shell", build_style="argv", source="function_argument", fix_type="", pattern="standard_safe", shape="plain_function"),
("c", "hard_negative"): dict(task_description="Restart a named system service.", cwe_detail="system", build_style="per_pattern", source="web_request", fix_type="", pattern="command_from_fixed_map", shape="plain_function"),
("c", "no_code"): dict(task_description="Format a byte count as a human-readable size.", cwe_detail="none", build_style="none", source="not_applicable", fix_type="", pattern="no_dangerous_call", shape="plain_function"),
}
SINK = {"python": "cursor.execute", "c": "system / popen"}
BANDS = [("1-5", 1, 5), ("6-10", 6, 10), ("11-20", 11, 20), ("21-40", 21, 40), ("41-100", 41, 100)]

rows = []
for lang, cwe, table in (("python", "CWE-89", PY), ("c", "CWE-78", C)):
    for i, (case, (code, fixed, vl)) in enumerate(table.items(), 1):
        n = code_lines(code, lang)
        band = next(b for b, lo, hi in BANDS if lo <= n <= hi)
        rows.append(dict(sample_id=f"ex_{cwe.split('-')[1]}_{lang}_{i:02d}", generator="example", language=lang, cwe=cwe, case_type=case,
                         label=1 if case in ("normal", "hard_positive") else 0, band=band, target_lines=n,
                         suggested_sink="" if case == "no_code" else SINK[lang], **SPEC[(lang, case)],
                         code=code, fixed_code=fixed, vulnerable_lines=json.dumps(vl) if vl else "", notes=""))
cols = ["sample_id", "generator", "language", "cwe", "case_type", "label", "task_description", "cwe_detail", "band", "target_lines",
        "build_style", "source", "fix_type", "pattern", "suggested_sink", "shape", "code", "fixed_code", "vulnerable_lines", "notes"]
pd.DataFrame(rows)[cols].to_csv(ROOT / "examples" / "example_rows.csv", index=False)
print("wrote", len(rows), "rows")
