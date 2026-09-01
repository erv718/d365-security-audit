# CLAUDE.md

Guidance for Claude Code (and any AI assistant) working in this repository.

## What this project is

A read-only security audit tool for Microsoft Dynamics 365, Power Platform, and Azure.
It reads the live security configuration of a tenant through Microsoft's admin APIs,
saves the raw evidence to `./output`, and prints a plain-language findings summary plus
an assessment report. It exists so the person who owns the infrastructure can get ground
truth from the actual configuration instead of an interview-based assessment.

## The golden rule: this tool only reads

Everything here is **read-only**, and it must stay that way.

- Never add code, commands, or steps that write to, change, or delete anything in a tenant.
  No config changes, no role or policy edits, no mutating POST/PATCH/PUT/DELETE. The scripts
  issue GET and read-only list/count calls only. If you edit a script, keep it read-only.
- If the user asks you to "fix" a finding, explain the remediation and where they would change
  it, but do not make the change against their tenant from here. This is a reporting tool, not
  a remediation tool.
- Authorization comes first. Do not run, or advise running, a real audit against a tenant the
  user is not clearly authorized to audit.

## How to run it

```powershell
copy .env.example .env    # then fill it in (see Authentication below)
./run-audit.ps1
```

Output lands in `./output` (git-ignored): `*.json` raw evidence, `FINDINGS-summary.json`
(also printed to the console), and `assessment-report.md`. Run a single area with
`-SkipGraph`, `-SkipDataverse`, `-SkipAzure`, or `-SkipPowerPlatform`.

## Authentication (help the user pick and set up)

**Option A - read-only app registration (recommended).** Set `TENANT_ID`, `CLIENT_ID`,
`CLIENT_SECRET` in `.env`. The app's own token covers all four planes, so the run is fully
unattended: no Azure CLI, nothing interactive. The app needs these, all read-only:

- Microsoft Graph application permissions (grant, then admin consent): `Application.Read.All`,
  `RoleManagement.Read.Directory`, `User.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`,
  `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`
- Azure: the `Reader` role at each subscription scope
- Dataverse: an Application User with a read-only security role in each environment
- Power Platform admin API: register the app with `New-PowerAppManagementApp`

Full details and per-permission reasoning are in [docs/permissions.md](docs/permissions.md).

**Option B - run as yourself (no app).** Leave `CLIENT_ID` / `CLIENT_SECRET` blank. Graph uses
an interactive device-code sign-in (no app, no secret, no module). Azure, Dataverse, and Power
Platform use your Azure CLI token, so run `az login` first. That is two sign-ins with the same
account. The Graph `.Read.All` scopes need a one-time admin consent to the app
"Microsoft Graph Command Line Tools" before a Global Reader can sign in.

## Reading the output

- `FINDINGS-summary.json` - ranked findings, also printed to the console.
- `assessment-report.md` - the pulls mapped to an 8-domain / 29-check assessment.
- `*-ERROR.json` - an endpoint that could not be read (see Common issues). Not fatal; the rest
  of the audit still ran.

Two questions cover most findings: is access broader than it needs to be, and can you see what
is happening (auditing, MFA, logs). A finding is not proof of a breach; it means that if
something happened, the user might not be able to see or reconstruct it.

## Common issues

- **403 Forbidden on a Graph identity check** (auth methods, security defaults, PIM, Intune):
  the token lacks that scope. On the app path, grant the matching permission above and admin
  consent. On the no-app path, the Azure CLI token does not carry these scopes, which is the
  whole reason Option A exists.
- **400 Bad Request on a Dataverse query**: a `$select` field the table does not have. It is a
  query bug, not a permission problem (permission problems return 403). Fix the field list.
- **Device-code sign-in blocked**: some tenants block the device-code flow via Conditional
  Access. Use Option A (app registration) instead.
- **Dataverse 403 on some environments**: the identity has no security role there. Expected for
  dev / trial environments; scope `DATAVERSE_ENVIRONMENTS` to the ones the user owns.

## Privacy

- `./output` and `.env` are git-ignored and hold real tenant data and secrets. Never commit
  them, never paste their contents anywhere they would leave the user's machine, and never send
  them to an external service. The point of this tool is that nothing leaves the tenant.
- If a client secret was used, remind the user to rotate it and to delete a one-time app when
  the audit is done.

## Scripts (all read-only)

- `scripts/_common.ps1` - config, token sources (app / device-code / az CLI), paging, JSON output.
- `scripts/graph-sweep.ps1`, `scripts/graph-identity-plus.ps1` - Entra ID identity plane.
- `scripts/powerplatform-sweep.ps1` - Power Platform admin (environments, DLP, tenant settings).
- `scripts/dataverse-sweep.ps1`, `scripts/dataverse-plus.ps1` - per-environment Dataverse config.
- `scripts/azure-sweep.ps1`, `scripts/azure-plus.ps1` - Azure ARM (RBAC, SQL, Synapse, Key Vault, NSGs).
- `scripts/analyze.ps1`, `scripts/assessment-report.ps1` - build the summary and the 29-check report.
