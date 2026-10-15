# Reviewing a run with an AI assistant on the audit machine

Use this after a run, when you want an AI coding assistant on the same machine (for example
Claude Code) to go through the results with you and turn them into a plan to lock things down.
The assistant reads the local files. Nothing has to leave the machine.

Before you start:

1. Run the audit for the scope you are authorized to read (see the README). For example, one
   Dataverse environment and nothing else:
   `./run-audit.ps1 -Log -SkipGraph -SkipAzure -SkipPowerPlatform -Environments https://<org>.crm.dynamics.com`
2. Open `output/security-assessment.html` yourself first. It is the report for people: every
   issue with why it matters, the steps to fix it, and links to Microsoft's documentation.
3. Start the assistant in the repository folder, and only use one your organization allows for
   this data. It reads your real configuration.

## Prompt: review the results and write a lockdown plan

Paste this as is:

```
You are helping me review a read-only security assessment of our Microsoft cloud (Entra ID,
Dynamics 365 and Power Platform, Azure). The tool is in this folder and its results are in
output/. Read AGENTS.md first and follow it.

Rules:
1. Read-only. Change nothing in our tenant and run nothing that could: no az CLI, no Graph or
   Azure write calls, no module that signs in, nothing in testdata/. No interactive sign-in.
2. Local files only. Send no content or name from output/ or .env to a website, an API, a
   ticket or a chat outside this session. Do not open .env.
3. Ground every statement in a file and name it. Anything not read (a Not checked row, an
   *-ERROR.json file) is "unknown", never "fine".
4. Quote the minimum: counts and names, not whole records.

Tasks:
A. Tell me in two lines which tool version ran (git log -1 --oneline) and what the run covered
   (output/scope-effective.json, the banner).
B. Read output/assessment-report.md and output/FINDINGS-summary.json in full.
C. Check every HIGH and MEDIUM finding against its raw evidence file with a read-only query
   (the one-liners in AGENTS.md, or similar). Mark each one confirmed, or say what the evidence
   shows instead. Do not change the tool; just report a finding the evidence does not support.
D. Write output/lockdown-plan.md: a ranked plan in three parts, "This week", "This month" and
   "This quarter", ordered as in "Helping the user decide what to fix first" in AGENTS.md. For
   each item: what it is, why it matters (one sentence), the fix, who should own it, the effort
   (a quick change or a project), and how to confirm it is fixed (what to rerun). Take the fix
   steps and the Microsoft links from scripts/finding-catalog.json for that finding's Key; do
   not invent portal paths or links. Put a "check first" step in front of anything that could
   break a running process.
E. List what this run could not see (Not checked rows, *-ERROR.json files) and the one change
   that would let the next run read each.
F. Stop and ask me which item to go deeper on.
```

## Prompt: double-check one finding

When a finding looks wrong to you, paste this with the finding's text:

```
Read AGENTS.md. This finding is in output/FINDINGS-summary.json: <paste the finding>.
Find the rule in scripts/analyze.ps1 that produced it (its Key names it in
scripts/finding-catalog.json), show me which evidence file and which fields it used, and query
those fields read-only. Tell me whether the finding is right for our data, and if not, why.
Do not change any file and do not send anything outside this session.
```

If the finding is wrong, `scripts/share-diagnostics.ps1` writes a file that is safe to share
with the maintainer (see [troubleshooting.md](troubleshooting.md)); describe the finding in
words instead of pasting it, since the finding text holds your names.
