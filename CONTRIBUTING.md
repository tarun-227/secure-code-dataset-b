# How to contribute

This page takes you from zero to your first finished issue. Read it top to bottom once. It takes about 15 minutes to set up, and each issue then takes about an hour.

## 1. Get access

1. Make a GitHub account if you do not have one, and send your username to the project lead.
2. You will get an email invitation to this repository. Accept it.
3. The lead tells you your **team** (Llama, Phi-4 or DeepSeek) and your **slot** (for example `phi-2`). Your slot is listed in [docs/ASSIGNMENTS.md](docs/ASSIGNMENTS.md).

## 2. Install the tools (once)

You need three things on your computer.

**Python 3.10 or newer**
- Windows: install from https://www.python.org and tick "Add Python to PATH".
- Mac: `brew install python`, or install from python.org.
- Check it works: open a terminal and type `python --version` (on some Macs: `python3 --version`).

**Git**
- Install from https://git-scm.com. Check: `git --version`.

**Ollama** (runs the AI model on your computer)
- Install from https://ollama.com.
- Download your team's model. Only download the one for your team:

| Team | Command | Download size |
|---|---|---|
| Llama | `ollama pull llama3.1:8b` | about 5 GB |
| Phi-4 | `ollama pull phi4:14b` | about 9 GB |
| DeepSeek | `ollama pull deepseek-coder-v2:16b` | about 9 GB |

- Check it works: `ollama run phi4:14b "Say hello"` (use your team's model name). Type `/bye` to leave.

A graphics card with 12 GB or more makes it fast. Without one it still works, only slower.

## 3. Get the project (once)

Open a terminal and run:

```
git clone https://github.com/tarun-227/secure-code-dataset-b.git
cd secure-code-dataset-b
pip install -r requirements.txt
```

## 4. Learn what a good row looks like (once)

1. Read [README.md](README.md): what we are building and the five case types.
2. Open [examples/README.md](examples/README.md) and [examples/example_rows.csv](examples/example_rows.csv). They show ten finished rows and explain why each label is right.
3. Keep [docs/ROW_FORMAT.md](docs/ROW_FORMAT.md) open while you work. It explains every column and every tag such as `keyword_blocklist`.

## 5. Do your first issue

Your first issue is a **pilot** with only 5 rows. The lead checks it carefully and tells you what to change. That is normal.

**Step 1. Find your issue.**
Go to the **Issues** tab. Click **Assignee** and choose yourself. Open the issue.

**Step 2. Mark that you started.**
Leave a comment "Starting". Keep the label `status:in-progress`.

**Step 3. Update your copy of the project.**
New issue files are added over time, so always run this first:
```
git pull
```

**Step 4. Let the model write a draft.**
The issue names its file, for example `issues/phi-2_00.csv`. Run:
```
python tools/generate.py issues/phi-2_00.csv
```
This sends each row's prompt (you can read them inside the issue) to your model and saves a draft in `filled/phi-2_00.csv`. It prints each answer with line numbers.

**Step 5. Check every row yourself.**
Open `filled/phi-2_00.csv` in Excel, LibreOffice or VS Code. For each row ask:
- **Does the code match the case type?** A `safe` row must really be safe. A `normal` or `hard_positive` row must really be vulnerable.
- **Does it follow the row's other columns?** Language, task, pattern, shape, length.
- **Is `fixed_code` the same function with only a few lines changed?** (vulnerable rows only)
- **Are `vulnerable_lines` right?** Count lines from 1, including empty lines. Models often get this wrong, so always recount.
- **Is there no give-away word?** No "vulnerable", "unsafe", "sanitize", "fixed", "attack" and similar words in comments, names or strings.

If a row is wrong, you can:
- fix small things by hand, or
- ask the model again for that row only: `python tools/generate.py issues/phi-2_00.csv --only 3` (row 3).

Do not rewrite a whole row by hand. If the model fails three times, write that in the row's `notes` column and in the issue.

**Step 6. Run the checker.**
```
python tools/validate.py filled/phi-2_00.csv
```
Fix every line that says `ERROR` and run it again until it says `OK - you can upload this file`. Read the `WARNING` lines too.

**Step 7. Hand it in.**
1. In the issue, write a comment and drag `filled/phi-2_00.csv` into the comment box. Post it.
2. Change the label from `status:in-progress` to `status:needs-review`.

**Step 8. Wait for the review.**
- `status:changes-requested`: read the lead's comment, fix the rows, run the checker, upload the new file, and set `status:needs-review` again.
- `status:accepted`: done. You will get your next issues (10 rows each).

## Rules in one place

- Use **only your team's model**. Do not use ChatGPT, Gemini, Claude or another model for these rows.
- Change only `code`, `fixed_code`, `vulnerable_lines` and `notes`. Never edit the other columns.
- Keep each function within its `band` (number of lines).
- `fixed_code` changes at most 10 lines and keeps the same function name.
- Never test an attack against a real website, server or anyone's data. You do not need to run any attack at all.
- Do not share the files outside this repository.

## Common problems

| Problem | What to do |
|---|---|
| `python` not found | Try `python3`, or reinstall Python with "Add to PATH" ticked |
| `generate.py` says it cannot connect | Start Ollama (open the Ollama app, or run `ollama serve`) |
| `generate.py` says the model is not found | Run the `ollama pull` command for your team |
| Generation is very slow | Normal without a big graphics card. Let it run; it saves after every row |
| The model writes an explanation instead of code | Run that row again with `--only N` |
| Excel breaks the code's line breaks | Use LibreOffice or VS Code, or a text editor that handles CSV |
| `git pull` complains about your changes | Your drafts live in `filled/`, which git ignores; if it still complains, ask in a Question issue |

## Need help?

Open a new issue with the **Question** template, or comment on your issue and mention the project lead. No question is too small.
