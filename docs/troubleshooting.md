# Troubleshooting without leaking anything

`output/` and `.env` describe your real tenant. This page is how to get help, from an AI on the
same machine or from a person outside it, without any of that leaving the server.

## 1. Read the setup check first

Every run starts with it. `[OK]` is fine, `[ X]` needs a fix and says exactly what to click,
`[ !]` is optional or a least-privilege note. Fix the `[ X]` lines, run again. Most problems
end here.

If a pull failed later in the run, `output/<name>-ERROR.json` holds the service's own reason
(HTTP status, error code, message). The matching check in `output/assessment-report.md` reads
**Not checked** and quotes it. The "Common issues" list in [AGENTS.md](../AGENTS.md) maps the
usual ones to their fix.

## 2. Keep a log of the run

```powershell
./run-audit.ps1 -Log
```

writes everything the run printed to `output/run-log.txt` (git-ignored like the rest of
`output/`). The diagnostics file in step 4 is built from it.

## 3. Ask an AI on the same machine

Open Claude Code, Kimi, Codex or any similar tool **in the repo folder on the same machine**
and paste this. It can read the real files there, which is fine: nothing leaves the machine
unless the tool itself sends it, and the prompt forbids that.

```text
You are helping me run d365-security-audit (this folder) against a production tenant.
Read AGENTS.md first and follow it. The two rules that matter most: the tool only reads,
and output/ and .env hold real tenant data that must never leave this machine.

Ground rules for this session:
- Work only with local files. Do not call any API or web service with anything from
  output/ or .env, and do not put their contents into a web search.
- Never print, quote or summarize the client secret or any token. Never show me .env.
- The audit is read-only and runs with ./run-audit.ps1. Do not add anything that writes
  outside output/. Never run testdata/*.ps1 or any interactive sign-in here.
- Use the one-liners in AGENTS.md instead of opening large files; check file sizes first.

What I want from you:
1. If the setup check shows [ X] lines, or the run has WARNING lines, explain each one in
   plain words and give me the exact click-path or command that fixes it (docs/permissions.md
   has them). For every output/*-ERROR.json say whether it is a permission gap, a licence
   gap, a scope problem, or a bug in the tool, and which check numbers it affects.
2. If the run worked, read output/assessment-report.md and then output/FINDINGS-summary.json
   and give me ranked next steps, the way AGENTS.md describes.
3. When I say "make a shareable diagnostic", run ./scripts/share-diagnostics.ps1, then show
   me output/diagnostics-redacted.md and nothing else, so I can paste it to someone outside
   this machine. Do not add names, URLs or IDs to it.

Style: short, plain English, no em dashes.
```

## 4. Ask someone outside the machine

```powershell
./scripts/share-diagnostics.ps1
```

writes `output/diagnostics-redacted.md`. Read it once, then paste **that file only**. It holds:

- the tool version, PowerShell and OS versions
- the scope as counts (how many subscriptions and environments, never which)
- the setup check lines and the warnings from `run-log.txt`
- the list of evidence files with sizes and row counts
- every failed pull as HTTP status, error code and message
- how many findings per severity and area
- the status of each of the 29 checks

It never holds finding text, evidence text, or the names of people, apps, servers,
environments, subscriptions or resource groups. Environment and subscription names that the
tool cannot avoid (file names, warnings) become `<env-1>`, `<sub-1>`; URLs, IPs, GUIDs, emails
and your tenant domain become `<host>`, `<ip>`, `<guid>`, `<email>`, `<domain>`. The masking is
pattern-based, so look the file over before you send it.

With that file, the person helping you can tell which step failed, why the service refused,
and which fix applies, without seeing anything about your tenant. If they need more, they will
ask for one specific `*-ERROR.json` message or one setup-check line, never for the raw files.

## 5. What not to share

- Nothing from `output/*.json`: every file describes your tenant.
- Not the console findings table: every line names a resource or an account.
- Not `.env`, not a token, not a screenshot of either.
- Not `output/ai-analysis-prompt.md` or `output/ai-analysis.md` (they hold the findings).
