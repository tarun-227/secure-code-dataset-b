# Secure Code Dataset B

We are building **1,200 short functions** for training a detector that finds security flaws in code, locates the faulty line, and names the weakness. Each function is written by one of three open-source code models running on your own computer. Some functions are vulnerable, some are safe, and many are deliberately tricky.

**Your job:** for every row in your issue, get the model to write the function exactly as the row describes, check it, and hand it back. Everything else about the row (weakness, language, task, length, pattern, fix type, and so on) is already decided for you, so the dataset ends up balanced.

## Who uses which model

| Team | Model | Ollama name | Memory needed (4-bit) |
|---|---|---|---|
| Llama team (3 people) | Llama 3.1 8B Instruct (Meta) | `llama3.1:8b` | about 6 GB |
| Phi team (3 people) | Phi-4 14B (Microsoft) | `phi4:14b` | about 9 GB |
| DeepSeek team (3 people) | DeepSeek-Coder-V2-Lite-Instruct 16B (DeepSeek) | `deepseek-coder-v2:16b` | about 10 GB |

Your team and your cells are listed in [docs/ASSIGNMENTS.md](docs/ASSIGNMENTS.md). A GPU with 12 GB or more is comfortable; the models also run on the CPU, only slower.

## The four weaknesses

| ID | Weakness | Vulnerable when |
|---|---|---|
| CWE-89 | SQL injection | untrusted input becomes part of the text of an SQL statement |
| CWE-78 | OS command injection | untrusted input can change which command or shell syntax runs |
| CWE-22 | Path traversal | untrusted input can make a file operation reach outside the intended folder |
| CWE-338 | Weak random generator | a non-cryptographic random generator produces a security value (token, password, OTP, key, session ID, salt) |

## The five case types

| `case_type` | `label` | What the function must be | You fill in |
|---|---|---|---|
| `normal` | 1 | plainly vulnerable | `code`, `fixed_code`, `vulnerable_lines` |
| `hard_positive` | 1 | vulnerable even though it looks protected | `code`, `fixed_code`, `vulnerable_lines` |
| `safe` | 0 | safe, written the standard way | `code` |
| `hard_negative` | 0 | safe, even though it uses the dangerous call or looks vulnerable | `code` |
| `no_code` | 0 | ordinary code with no dangerous call for this weakness | `code` |

`hard_positive` and `hard_negative` rows matter most: they are exactly where detectors fail. The `pattern` column tells you which trick to use; every tag is explained in [docs/ROW_FORMAT.md](docs/ROW_FORMAT.md).

## Setup (once)

1. Install Python 3.10 or newer, then: `pip install -r requirements.txt`
2. Install Ollama from https://ollama.com and download your team's model, for example `ollama pull phi4:14b`
3. Clone this repository: `git clone https://github.com/tarun-227/secure-code-dataset-b.git`
4. Read the 10 worked examples in [examples/](examples/README.md).

## Workflow for each issue

1. **Open your issue.** It lists the rows and links to its CSV, for example `issues/phi-2_03.csv`. Pull the repository so you have the file.
2. **Generate a draft:** `python tools/generate.py issues/phi-2_03.csv`
   This asks your local model for every row and writes `filled/phi-2_03.csv`. If you prefer, print one prompt with `python tools/make_prompt.py issues/phi-2_03.csv --row 3` and paste it into `ollama run <model>` yourself.
3. **Check every row by hand.** Open `filled/phi-2_03.csv` (Excel, LibreOffice or VS Code).
   - Does the code really do what the case type says? A `safe` row must be safe; a `normal` row must really be exploitable.
   - Is `fixed_code` the same function with only the needed lines changed?
   - **Recount `vulnerable_lines`.** Models often get line numbers wrong. Count from 1, including blank lines.
   - If a row is wrong, fix it by hand or regenerate it: `python tools/generate.py issues/phi-2_03.csv --only 3`
4. **Validate:** `python tools/validate.py filled/phi-2_03.csv` and fix every ERROR.
5. **Hand in:** attach `filled/phi-2_03.csv` to a comment on the issue and change the label to `status:needs-review`.

You only ever edit `code`, `fixed_code`, `vulnerable_lines` and `notes`. Never change the other columns; the validator compares them with the original.

## Rules

- **Use only your team's model** for the code. Small manual corrections are fine; rewriting a row entirely by hand is not. If the model cannot do a row after three tries, say so in `notes` and in the issue.
- **No give-away words** in comments, names or strings: vulnerable, insecure, unsafe, sanitize, exploit, inject, attack, fixed, CWE, and so on.
- **Keep the length inside the band.** `target_lines` is a target; the line count must stay within `band`.
- **`fixed_code` changes at most 10 lines** and keeps the function name and parameters.
- **One function per row**, complete and self-contained (imports or `#include`s at the top are fine; a small helper is fine when the shape asks for one).
- **Never run attacks against real systems.** You do not need to run any attack at all; the reviewer does the security checks.

## Your first issue is a pilot

Your first issue has **5 rows**, one of each case type. The reviewer checks it line by line and replies with comments. Once it is accepted you receive issues of **10 rows**, two at a time.

## Labels

| Label | Meaning |
|---|---|
| `status:in-progress` | you are working on it |
| `status:needs-review` | you uploaded the file; waiting for the reviewer |
| `status:changes-requested` | see the reviewer's comment, fix, upload again |
| `status:accepted` | done; the file is merged into `data/accepted/` |

## Questions

Open an issue with the **Question** template, or comment on your issue. Progress is tracked in [PROGRESS.md](PROGRESS.md).

## Repository layout

```
README.md               this file
docs/ROW_FORMAT.md      every column and every tag explained
docs/ASSIGNMENTS.md     who works on which model and cells
examples/               10 complete, annotated example rows
issues/                 one CSV per issue (do not edit; your work goes in filled/)
filled/                 your drafts (not committed)
tools/                  generate, make_prompt, validate (for you); build_plan, make_issues, progress (for the reviewer)
plan/                   the full plan of all 1,200 rows
data/accepted/          files the reviewer accepted
PROGRESS.md             accepted rows against the targets
```
