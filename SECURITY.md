# Security Policy

## Reporting a vulnerability

If you find a security issue in this **tool** (not a finding in your own tenant), please report it privately instead of opening a public issue.

- Preferred: open a private [GitHub Security Advisory](https://github.com/erv718/d365-security-audit/security/advisories/new).
- We aim to acknowledge reports within a few days.

Please do not include real tenant data, secrets, or `output/` contents in a report.

## What this tool does with your data

- **Read-only.** It never changes your tenant.
- **No telemetry.** It calls only your own Microsoft endpoints (Graph, Dataverse, Azure, Power Platform). It contacts no third party, including the maintainers. The one exception is opt-in: `AI_ANALYSIS=api` in `.env` sends the findings summary to the AI endpoint you configure; it is off by default and cannot be turned on from the environment.
- **Your data stays local.** All output is written to `output/`, which is git-ignored. You decide what happens to it.
- Treat `output/` as sensitive: it describes your security posture.

## Using it safely

- Get written authorization before pointing it at any tenant you do not own.
- Keep the client secret short-lived (90 days or less), store it only in `.env`, delete or rotate it when you are done, and delete one-time apps. (Certificate authentication is not implemented.)
- Never commit `.env`. It is git-ignored by default; keep it that way.

## Supported versions

The latest tagged release on `main`.
