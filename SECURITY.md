# Security Policy

## Reporting a vulnerability

If you find a security issue in this **tool** (not a finding in your own tenant), please report it privately instead of opening a public issue.

- Preferred: open a private [GitHub Security Advisory](https://github.com/erv718/d365-security-audit/security/advisories/new).
- We aim to acknowledge reports within a few days.

Please do not include real tenant data, secrets, or `output/` contents in a report.

## What this tool does with your data

- **Read-only.** It never changes your tenant.
- **No telemetry.** It calls only your own Microsoft endpoints (Graph, Dataverse, Azure). It contacts no third party, including the maintainers.
- **Your data stays local.** All output is written to `output/`, which is git-ignored. You decide what happens to it.
- Treat `output/` as sensitive: it describes your security posture.

## Using it safely

- Get written authorization before pointing it at any tenant you do not own.
- Prefer running as yourself (`az login`) or a certificate over a stored client secret. If you use a secret, rotate it when you are done and delete one-time apps.
- Never commit `.env`. It is git-ignored by default; keep it that way.

## Supported versions

The latest tagged release on `main`.
