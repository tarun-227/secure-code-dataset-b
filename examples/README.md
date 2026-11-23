# Worked examples

[example_rows.csv](example_rows.csv) has 10 complete rows: one of each case type for **Python SQL injection (CWE-89)** and **C command injection (CWE-78)**. Open it next to this page.

## Python, CWE-89

| Row | Case type | Why the label is right | Vulnerable lines |
|---|---|---|---|
| `ex_89_python_01` | `normal` | The username is pasted into the SQL text with an f-string, so `' OR '1'='1` changes the query. The fix binds it as a parameter. | 3 (builds the query), 4 (runs it) |
| `ex_89_python_02` | `hard_positive` | A blocklist rejects `--`, `;`, `drop ` and `union `, which looks careful, but `x' OR '1'='1` contains none of them and still breaks out. The fix binds the term. | 9, 10 |
| `ex_89_python_03` | `safe` | Both values are passed as bound parameters. | - |
| `ex_89_python_04` | `hard_negative` | It uses an f-string inside SQL, which looks dangerous, but the inserted column always comes from a fixed dictionary and the category is bound. | - |
| `ex_89_python_05` | `no_code` | Formats order records as CSV; no database call at all. | - |

## C, CWE-78

| Row | Case type | Why the label is right | Vulnerable lines |
|---|---|---|---|
| `ex_78_c_01` | `normal` | The host is formatted into a shell command run by `system`, so `x; touch /tmp/pwned` runs a second command. The fix runs `ping` directly with `execlp`, no shell, and `--` before the host. | 6 (builds the command), 7 (runs it) |
| `ex_78_c_02` | `hard_positive` | It rejects `;`, `&` and `\|`, but `$(...)`, backticks and newlines still work in the shell. The fix accepts only a strict set of characters and rejects a leading dash. | 6, 9, 10 |
| `ex_78_c_03` | `safe` | `du` is run with an argument list and no shell, with `--` before the folder. | - |
| `ex_78_c_04` | `hard_negative` | It calls `system`, which looks dangerous, but the command string always comes from a fixed table; the input only selects the key. | - |
| `ex_78_c_05` | `no_code` | Formats a byte count; no command execution at all. | - |

## What to notice

- No comment or name says "safe", "vulnerable" or "fixed".
- `fixed_code` changes only the lines that matter and keeps the function's name and parameters.
- `vulnerable_lines` points at the lines that **build** and **use** the dangerous value, not at the whole function.
- Line numbers count every line from 1, including blank lines and `#include` lines.
