# D365 / Power Platform Security Audit (read-only)

A small PowerShell toolkit that reads the actual security configuration of a Dynamics 365 / Power Platform / Azure environment and reports what is exposed. It queries your own tenant through Microsoft's admin APIs, saves the raw evidence, and prints a plain-language findings summary.

It is **read-only**. It does not change anything in your tenant.

## Data privacy

This runs entirely under your control. It reads your own tenant and writes the results to your own disk. Nothing is sent anywhere.

- **No telemetry, no phone-home.** The only calls it makes are to your own Microsoft endpoints (Graph, Dataverse, Azure). There is no analytics, and it contacts no third party, including us.
- **Your data stays local.** All output lands in `output/`, which is git-ignored. You decide what happens to it.
- **Read-only.** It never writes to your tenant: GET reads only, apart from two documented read-only POSTs (the token sign-in request, and Power Platform's listTenantSettings, which returns settings).
- **Auditable.** It is a few hundred lines of PowerShell under MIT. Read every line before you run it, or have your security team do it.
- **Least privilege.** It needs only the seven read-only Graph scopes in docs/permissions.md, and it signs in only as the app registration you create - never as a person, never with your account.
- **One explicit exception.** The optional AI analysis (`AI_ANALYSIS=api` in `.env`, OFF by default) sends the scoped findings summary to an AI endpoint you choose. The default (`off`) and `local` mode send nothing. The default `redacted` scope masks emails, IPs, GUIDs, tenant domains and the names the report prints, on a best-effort pattern basis; `named` and `full` send more.

Treat the `output/` folder as sensitive. It describes your security posture, so keep it where your tenant data belongs.

## Why this exists

Most "security assessments" are interviews. Someone asks how things are configured, writes down the answers, and hands back a report based on what they were told. That misses whatever the person answering did not know, mis-remembered, or never checked.

This tool reads the configuration directly, so the findings are based on the live state of the environment instead of a conversation. It is meant for the person who owns the infrastructure and wants ground truth.

## What it checks

**Identity (Microsoft Graph)**
- App registrations and expired / expiring client secrets and certificates
- Service principals and which apps hold high-privilege tenant-wide permissions (all-mail, directory write, etc.)
- Directory roles and how many hold Global Administrator; PIM eligible (just-in-time) versus standing admin access
- Conditional Access policies (how many exist, how many are enabled, whether any enforce MFA or a compliant device), security defaults, the authentication methods policy, named locations
- Intune device compliance policies and the managed-device overview
- Guest accounts: tenant-wide count and concentration by home domain
- A sign-in sample: legacy/basic-auth protocols that bypass MFA (IMAP, POP, SMTP, Exchange ActiveSync, "other clients"), and MFA that a federated IdP performs but Entra does not record

**Power Platform (admin API)**
- Every environment: type, region, whether it has a Dataverse database, whether a security group restricts access, whether it is a Managed Environment
- DLP (connector data) policies, and whether the default environment is covered by one
- Tenant settings (for example default environment routing)

**Data platform (Dataverse, per environment)**
- Whether auditing is turned on (org level, user-access auditing, read-log auditing, retention) and per table
- Security roles, and whether any custom roles exist or everything defaults to built-in ones
- Solution inventory (managed vs unmanaged, and what sits in production)
- Field security profiles and field permissions
- Email server profiles, mailboxes and queues (the server-side sync surface)

**Cloud infrastructure (Azure ARM, per subscription)**
- Role assignments, and how many hold Owner / User Access Administrator at subscription scope
- SQL servers: public network access, minimum TLS version, and "allow all Azure IPs" firewall rules
- Synapse workspaces: firewall rules
- Key Vaults: RBAC vs legacy access policies, and public network access
- Network security groups: RDP/SSH rules open to the internet
- Defender for Cloud plans (Standard vs Free), Log Analytics workspaces and Sentinel onboarding, activity-log diagnostic settings, Logic Apps

**The assessment report**

`output/assessment-report.md` maps the evidence to Microsoft's Power Platform and Dynamics 365 Security Review: 8 domains, 29 checks (28 unique; 2.5 is a template duplicate of 2.4). Every verdict is tied to an evidence file in `output/`. If that file is missing, the check reads **Not checked** and names the access that would unlock it; the tool never guesses. Checks no API can answer (incident response plan, Customer Lockbox, sensitivity labels, residency adequacy) are marked **MANUAL** with the exact portal path to confirm them.

**Beyond the checklist**, the report and the findings add: Managed Environments coverage, default-environment DLP coverage, legacy/basic-auth detection in the sign-in sample, guest concentration by home domain, Defender for Cloud plan status, and PIM standing versus eligible admin access.

## Quick start

```powershell
# 1. get the code
git clone https://github.com/erv718/d365-security-audit.git ; cd d365-security-audit

# 2. configure  (macOS/Linux shells: cp .env.example .env)
Copy-Item .env.example .env
#    fill in TENANT_ID / CLIENT_ID / CLIENT_SECRET for your read-only app
#    (docs/permissions.md lists the exact permissions)

# 3. run
./run-audit.ps1
```

The audit runs entirely on that one read-only credential. **There is no interactive
sign-in of any kind**: the tool never signs in as a person, never opens a browser
prompt, and never shows a device code. On every run it first checks your app's setup
and prints the exact fix for anything missing (you can also run the check alone with
`pwsh ./scripts/check-setup.ps1`). If `.env` is empty, it stops with setup
instructions instead of falling back to your account.

Output lands in `./output` (git-ignored):
- `*.json` - the raw evidence for each area
- `FINDINGS-summary.json` - the ranked summary, also printed to the console
- `assessment-report.md` - the pulls mapped to Microsoft's 8-domain / 29-check review, every verdict tied to its evidence file

Run a single area with `-SkipGraph`, `-SkipDataverse`, `-SkipAzure`, or `-SkipPowerPlatform`.

## Requirements

- PowerShell 7+ (or Windows PowerShell 5.1)
- A read-only app registration. This is the only way the tool authenticates - no Azure CLI, no interactive sign-in.
- Read-only permissions per [docs/permissions.md](docs/permissions.md)

## Use it responsibly

- **Get written authorization first.** This reads your organization's security configuration. Only run it against environments you are authorized to audit.
- **Read-only, but still sensitive.** The `output/` folder contains your real tenant configuration. Do not commit it or share it casually.
- **Rotate the secret** if you used a client secret, and delete a one-time app when you are done.
- **Never commit `.env`.** It is git-ignored by default - keep it that way.

## How to read the findings

Two questions cover almost everything the tool reports:

1. **Is access broader than it needs to be?** (open firewalls, exposed RDP, too many admins, no least-privilege roles, over-permissioned apps)
2. **Can you see what is happening?** (auditing off, MFA the platform cannot observe, no monitoring)

A finding does not mean you were breached. It means that if something happened, you might not be able to see it or reconstruct it. Fix the "can't see" items first - they are usually configuration, not projects.

## Status and roadmap

`main` carries the full assessment: the four evidence planes (Graph, Power Platform, Dataverse, Azure) plus the 8-domain / 29-check report (28 unique) mapped to Microsoft's Power Platform & Dynamics 365 Security Review, every verdict tied to its evidence file in `output/`.

Later:
- Purview / sensitivity-label coverage
- HTML report output
- Optional cross-check against a saved baseline

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) to add checks, and [SECURITY.md](SECURITY.md) to report an issue in the tool. The one hard rule: it stays read-only.

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

Provided as-is, with no warranty. You are responsible for how and where you run it. It is a read-only reporting tool, not a remediation tool, and not a substitute for a formal security program.
