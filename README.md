# D365 / Power Platform Security Audit (read-only)

A small PowerShell toolkit that reads the actual security configuration of a Dynamics 365 / Power Platform / Azure environment and reports what is exposed. It queries your own tenant through Microsoft's admin APIs, saves the raw evidence, and prints a plain-language findings summary.

It is **read-only**. It does not change anything in your tenant.

## Why this exists

Most "security assessments" are interviews. Someone asks how things are configured, writes down the answers, and hands back a report based on what they were told. That misses whatever the person answering did not know, mis-remembered, or never checked.

This tool reads the configuration directly, so the findings are based on the live state of the environment instead of a conversation. It is meant for the person who owns the infrastructure and wants ground truth.

## What it checks

**Identity (Microsoft Graph)**
- App registrations and expired / expiring client secrets and certificates
- Service principals and which apps hold high-privilege tenant-wide permissions (all-mail, directory write, etc.)
- Directory roles and how many hold Global Administrator
- Conditional Access policies (how many exist, how many are enabled, whether any enforce MFA)
- Guest account count (tenant-wide)
- A sign-in sample (to spot MFA that a federated IdP performs but Entra does not record)

**Data platform (Dataverse, per environment)**
- Whether auditing is turned on (org level and per table)
- Security roles, and whether any custom roles exist or everything defaults to built-in ones
- Solution inventory (managed vs unmanaged, and what sits in production)
- Field security profiles

**Cloud infrastructure (Azure ARM, per subscription)**
- Role assignments, and how many hold Owner / User Access Administrator at subscription scope
- SQL servers: public network access and "allow all Azure IPs" firewall rules
- Synapse workspaces: firewall rules
- Key Vaults: RBAC vs legacy access policies, and public network access
- Network security groups: RDP/SSH rules open to the internet

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

Run a single area with `-SkipGraph`, `-SkipDataverse`, or `-SkipAzure`.

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

## Roadmap

- Purview / sensitivity-label coverage
- HTML report output
- Optional cross-check against a saved baseline

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

Provided as-is, with no warranty. You are responsible for how and where you run it. It is a read-only reporting tool, not a remediation tool, and not a substitute for a formal security program.
