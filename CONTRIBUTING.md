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

**Step 3. Make a new branch for this issue.**
Every issue gets its own branch. Use the issue's ID (it is in the issue title, for example `phi-2_00`):
```
git checkout main
git pull
git checkout -b issue/phi-2_00
```
`git pull` also brings you any new issue files. Never work directly on `main`.

**Step 4. Let the model write a draft.**
The issue names its file, for example `issues/phi-2_00.csv`. Run:
```
python tools/generate.py issues/phi-2_00.csv
```
This sends each row's prompt (you can read them inside the issue) to your model and saves a draft in `submissions/phi-2_00.csv`. For vulnerable rows it also asks the model for the fix. It then:
- checks every answer by itself (the code parses, imports are there, the length fits, no give-away words, the case type looks right, the fix is small) and asks the model again, up to 3 times, if something is wrong;
- fills `vulnerable_lines` from the lines the model marked, and prints the code with those lines marked `>`;
- writes any problem it could not solve into the row's `notes`, starting with `AUTO-CHECK:`. Fix those rows (by hand or with `--only`), then delete that note.

**Step 5. Check every row yourself.**
Open `submissions/phi-2_00.csv` in LibreOffice, VS Code or Excel. For each row ask:
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
python tools/validate.py submissions/phi-2_00.csv
```
Fix every line that says `ERROR` and run it again until it says `OK - you can commit and push this file`. Read the `WARNING` lines too.

**Step 7. Save your work to GitHub.**
```
git add submissions/phi-2_00.csv
git commit -m "Rows for phi-2_00"
git push -u origin issue/phi-2_00
```
Only add your one `submissions/...csv` file.

**Step 8. Open a pull request.**
1. After `git push`, GitHub prints a link. Open it (or go to the repository page and click **Compare & pull request**).
2. Check that it goes from `issue/phi-2_00` into `main`.
3. In the description, write `Closes #5` (use your issue's number) and tick the checklist.
4. Click **Create pull request**.
5. On your issue, change the label from `status:in-progress` to `status:needs-review`.

**Step 9. Wait for the review.**
- If the lead asks for changes: stay on the same branch, fix the rows, run the checker, then `git add`, `git commit` and `git push` again. The pull request updates by itself.
- Do not press **Merge** yourself, even though GitHub shows the button. Only the lead merges.
- When the lead merges the pull request, the issue closes and your rows are accepted. You will get your next issues (10 rows each).

**Next issue:** start again from Step 3 with a new branch named after the new issue.

## Rules in one place

- **Never merge a pull request and never push to `main`.** Only the project lead merges, including your own pull request. You work only on your `issue/<id>` branch.
- Use **only your team's model**. Do not use ChatGPT, Gemini, Claude or another model for these rows.
- Change only `code`, `fixed_code`, `vulnerable_lines` and `notes`. Never edit the other columns.
- Keep the code within its `band`. Only real code lines count: not blank lines, comment-only lines or imports.
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
| `notes` says `AUTO-CHECK: ...` | The model failed that check 3 times. Fix it by hand or run `--only N` again, then delete the note |
| Excel breaks the code's line breaks | Use LibreOffice or VS Code, or a text editor that handles CSV |
| `git pull` or `git checkout` complains about your changes | Commit them on your issue branch first (`git add`, `git commit`), then try again |
| You worked on `main` by mistake | Run `git checkout -b issue/<id>` now; your changes move to the new branch. Then commit there |

## Need help?

Open a new issue with the **Question** template, or comment on your issue and mention the project lead. No question is too small.
