# AGENTS.md

Guidance for AI assistants (coding agents and chat assistants) working in this repository.
This is the canonical file. `CLAUDE.md` only points here.

## What this project is

A read-only security audit tool for Microsoft Dynamics 365, Power Platform, and Azure.
It reads the live security configuration of a tenant through Microsoft's admin APIs,
saves the raw evidence to `./output`, and prints a plain-language findings summary plus
an assessment report. It exists so the person who owns the infrastructure can get ground
truth from the actual configuration instead of an interview-based assessment.

**How this is meant to be used:** the user runs the CLI to produce the findings, then talks
to their AI assistant to ask what the findings mean and what to do next. Being genuinely
helpful in that "what do I fix first?" conversation is a first-class job of this file, second
only to keeping the tool read-only. See "Helping the user decide what to fix first" and
"Analyzing the output with an AI assistant" below.

## The golden rule: this tool only reads

Everything here is **read-only**, and it must stay that way.

- Never add code, commands, or steps that write to, change, or delete anything in a tenant.
  No config changes, no role or policy edits, no mutating POST/PATCH/PUT/DELETE. The scripts
  issue GET and read-only list/count calls only. The two POSTs that exist are the OAuth token
  request and the Power Platform `listTenantSettings` call, which reads settings. If you edit
  a script, keep it read-only.
- If the user asks you to "fix" a finding, explain the remediation and where they would change
  it, but do not make the change against their tenant from here. This is a reporting tool, not
  a remediation tool.
- Authorization comes first. Do not run, or advise running, a real audit against a tenant the
  user is not clearly authorized to audit.

## How to run it

```powershell
Copy-Item .env.example .env    # then fill it in (see Authentication below)
./run-audit.ps1
```

Output lands in `./output` (git-ignored): `*.json` raw evidence, `FINDINGS-summary.json`
(also printed to the console), `assessment-report.md` and `assessment-report.json`. Run a
single area with `-SkipGraph`, `-SkipDataverse`, `-SkipAzure`, or `-SkipPowerPlatform`.
`scripts/analyze.ps1` and `scripts/assessment-report.ps1` only read `./output`; they can be
re-run on their own after a sweep without touching the tenant.

## Authentication (app registration ONLY, by design)

**The read-only app registration is the only way this tool authenticates.** This is a
deliberate security decision by the project. The tool never performs an interactive sign-in,
never shows a device code, and never uses a person's account or CLI session. **Do not add an
interactive sign-in path or any auth fallback.** The reasons, so the rule survives a
well-meaning refactor:

- An admin can run it without ever putting their own token in play. A delegated token carries
  everything that person can do; the app token carries seven read-only permissions that were
  reviewed and consented once.
- The permission set is fixed and auditable. With a fallback, nobody can say which identity a
  given `output/` folder was produced with, or why a call returned 403.
- The run is unattended and repeatable: no browser prompt to automate, no device code that
  could be phished.
- The repo's own history shows the cost of a fallback: the first real run happened through an
  Azure CLI user token and produced 403s that looked like endpoint bugs. They were consent
  gaps. That fallback was removed on purpose.

Set `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` in `.env`. The app's own token covers all four
planes, so the run is fully unattended. The app needs these, all read-only:

- Microsoft Graph application permissions (grant, then admin consent): `Application.Read.All`,
  `RoleManagement.Read.Directory`, `User.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`,
  `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`
- Azure: the `Reader` role at each subscription scope
- Dataverse: an Application User with a read-only security role in each environment
- Power Platform admin API: register the app with `New-PowerAppManagementApp`

Full details and per-permission reasoning are in [docs/permissions.md](docs/permissions.md).

Every run starts with `scripts/check-setup.ps1`, a read-only preflight that probes each
permission and prints the exact fix for anything missing. If `.env` is empty or the app cannot
sign in, the run stops with setup instructions. Point the user at that checklist first when
something fails.

## Reading the output

- `assessment-report.md` (and `.json`): the pulls mapped to Microsoft's Power Platform and
  Dynamics 365 Security Review, 8 domains and 29 checks. 28 are unique: 2.5 is a duplicate of
  2.4 in Microsoft's template, so it mirrors 2.4 and is left out of the tally.
  - Every verdict is tied to an evidence file in `output/`. If that file is missing, the check
    reads **Not checked** and the evidence column names the access that unlocks it. The tool
    never guesses a Gap or an Aligned.
  - **MANUAL** means no API can answer it. The evidence column carries the exact portal
    click-path where a human confirms it.
  - 1.1 (Entra is the identity provider) and 3.1 (encryption) are platform facts. Their
    evidence says so and lists what was verified on top of the fact.
  - The "beyond the checklist" section adds Managed Environments coverage,
    default-environment DLP coverage, guest concentration by home domain, and the ranked
    technical findings, including legacy/basic-auth sign-ins.
- `FINDINGS-summary.json`: ranked HIGH / MEDIUM / LOW findings, also printed to the console.
- `*-ERROR.json`: an endpoint that could not be read. Holds the HTTP status and the service's
  own error body, which names the missing permission, the bad `$select` column, or the
  licence gap. Not fatal; the rest of the audit still ran.

Status meanings: **Aligned** (good), **Partial** (okay, needs work), **Gap** (fix),
**Not in use**, **Not checked** (evidence file missing), **MANUAL** (a human confirms it).

Two questions cover most findings: is access broader than it needs to be, and can you see what
is happening (auditing, MFA, logs). A finding is not proof of a breach; it means that if
something happened, the user might not be able to see or reconstruct it.

## Helping the user decide what to fix first

After a run, the user will usually ask "what are my next steps?" or "what do I fix first?"
This is the main reason this file exists. Give them a short, ranked, plain-language plan, not
a dump of the JSON.

Rank findings in this order:

1. **Things that blind you.** Auditing turned off, no log retention, MFA performed by a
   federated identity provider that Entra never records, legacy protocols that never see MFA.
   Fix these first: you cannot investigate anything else if you cannot see what happened.
2. **Internet-exposed or high-blast-radius access.** RDP/SSH open to the world, SQL/Synapse
   firewalls set to "allow all Azure IPs" or public, too many Global Administrators or
   subscription Owners, standing (non-PIM) admin access, an expired or expiring credential on
   a privileged app.
3. **Over-permissioned identities.** Apps holding tenant-wide permissions they do not need
   (read all mail, write to the directory), no Conditional Access or no MFA enforcement,
   guests with broad access, no DLP between connectors, environments without a security group.
4. **Least privilege and hygiene.** Everything defaulting to built-in admin roles instead of
   scoped ones, no field-level security, stale accounts, unmanaged solutions in production,
   environments not enrolled as Managed Environments.

For each item you recommend, give the user four things:

- **What** it is, in one plain sentence.
- **Why** it matters (what an attacker, or an auditor, would do with it).
- **The fix**, concretely: the exact Microsoft setting or admin-center path, with a doc link
  when it helps. The report's evidence column already carries the path for many checks.
- **Effort**: a quick config change, or a real project. Say which.

Then stop and offer to go deeper on any one. Do not walk them through all 29 checks at once.

Rules while advising:

- Explain the remediation. Do not perform it against their tenant from here. This tool reads
  and reports; the human makes the change.
- Say "if X happened you might not see it," not "you were breached." A finding is a gap, not an
  incident.
- Prefer the smallest change that closes the gap. Least privilege applies to the fix too.
- Tie findings back to the 8-domain / 29-check assessment in `assessment-report.md`, so the
  user can hand a stakeholder something structured.
- Treat **Not checked** as "unknown", never as "fine". If a whole plane is Not checked, the
  first fix is the access gap named in the evidence column.

## Analyzing the output with an AI assistant - token-efficient workflow

The evidence files are big and most of their content is noise for any single question. Work
from the summaries down, and pull single facts out of the raw files with a query instead of
loading them.

### Reading order (strict)

1. `output/assessment-report.md`. A few KB. Verdicts, evidence, and click-paths for all 29
   checks plus the beyond-the-checklist section. Read the whole file.
2. `output/FINDINGS-summary.json`. A few KB. The ranked technical findings. Read the whole file.
3. Only then, targeted queries against the raw evidence (one-liners below), and only for the
   question actually being asked.

### Size warnings

| File | Typical size | Rule |
|---|---|---|
| `servicePrincipals.json` | can exceed 1.5 MB | never load; query for one principal or a count |
| `appRoleDefinitions-graph.json` | 300 KB or more | never load; it is a Microsoft catalogue, not tenant data |
| `signins-sample.json` | several hundred KB | query; group or filter, never dump |
| `pp-environments.json` | 250 to 300 KB | query per environment or per property |
| `applications.json` | 200 KB or more | query for expiring credentials or one app |
| `arm-*-rbac.json`, `arm-*-nsgs.json` | 100 to 200 KB each | query |

Rule of thumb: anything over about 50 KB is extracted with jq or PowerShell, never opened in
full. Check sizes first:

```powershell
Get-ChildItem output | Sort-Object Length -Descending | Select-Object -First 15 Name, Length
```

```bash
ls -lS output | head -15
```

### One-liners for the questions users actually ask

Run from the repo root. PowerShell versions work in Windows PowerShell 5.1 and PowerShell 7;
jq versions need jq 1.6 or later (macOS, Linux, or Git Bash on Windows). Field names come
from the files themselves: the report rows have `No`, `Domain`, `Check`, `Status`, `Evidence`;
the findings have `Severity`, `Area`, `Finding`.

**Which checks are Gap or Not checked, and why**

```powershell
(Get-Content output/assessment-report.json -Raw | ConvertFrom-Json) | Where-Object { $_.Status -in 'Gap','Not checked' } | Format-Table No, Status, Check, Evidence -Wrap
```

```bash
jq -r '.[] | select(.Status=="Gap" or .Status=="Not checked") | "\(.No)\t\(.Status)\t\(.Check)\t\(.Evidence)"' output/assessment-report.json
```

**Only the HIGH findings**

```powershell
(Get-Content output/FINDINGS-summary.json -Raw | ConvertFrom-Json) | Where-Object { $_.Severity -eq 'HIGH' } | Format-Table Area, Finding -Wrap
```

```bash
jq -r '.[] | select(.Severity=="HIGH") | "\(.Area)\t\(.Finding)"' output/FINDINGS-summary.json
```

**Every endpoint that failed, with the service's reason**

```powershell
Get-ChildItem output -Filter '*-ERROR.json' | ForEach-Object { "$($_.Name): $((Get-Content $_.FullName -Raw | ConvertFrom-Json).error)" }
```

```bash
for f in output/*-ERROR.json; do printf '%s\t%s\n' "$(basename "$f")" "$(jq -r '.error' "$f")"; done
```

**Which Conditional Access policies are enabled, and which of those enforce MFA**

```powershell
(Get-Content output/ca-policies.json -Raw | ConvertFrom-Json) | Where-Object { $_.state -eq 'enabled' } | Select-Object displayName, @{n='mfa';e={ $_.grantControls.builtInControls -contains 'mfa' }}
```

```bash
jq -r '.[] | select(.state=="enabled") | "\(.displayName)\tmfa=\((.grantControls.builtInControls // []) | index("mfa") != null)"' output/ca-policies.json
```

**Which apps have a secret or certificate expiring within 90 days**

```powershell
$limit = (Get-Date).AddDays(90); (Get-Content output/applications.json -Raw | ConvertFrom-Json) | ForEach-Object { $a = $_; @($a.passwordCredentials) + @($a.keyCredentials) | Where-Object { $_.endDateTime -and [datetime]$_.endDateTime -lt $limit } | ForEach-Object { [pscustomobject]@{ app = $a.displayName; expires = $_.endDateTime } } } | Sort-Object expires
```

```bash
# GNU date shown; on macOS use: limit=$(date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)
limit=$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ); jq -r --arg limit "$limit" '.[] | .displayName as $app | ((.passwordCredentials // []) + (.keyCredentials // []))[] | select(.endDateTime != null and .endDateTime < $limit) | "\(.endDateTime)\t\($app)"' output/applications.json | sort
```

**Which environments lack a security group** (Default, Developer and Teams environments
cannot have one, so they are excluded)

```powershell
(Get-Content output/pp-environments.json -Raw | ConvertFrom-Json) | Where-Object { $_.properties.linkedEnvironmentMetadata -and $_.properties.environmentSku -notin 'Default','Developer','Teams' -and -not $_.properties.linkedEnvironmentMetadata.securityGroupId } | Select-Object @{n='name';e={$_.properties.displayName}}, @{n='type';e={$_.properties.environmentSku}}
```

```bash
jq -r '.[] | select(.properties.linkedEnvironmentMetadata != null and ((.properties.environmentSku | IN("Default","Developer","Teams")) | not) and ((.properties.linkedEnvironmentMetadata.securityGroupId // "") == "")) | "\(.properties.displayName)\t\(.properties.environmentSku)"' output/pp-environments.json
```

**Guest count and the top home domains**

```powershell
$g = Get-Content output/guests-by-domain.json -Raw | ConvertFrom-Json; $g.total; $g.byDomain | Select-Object -First 10
```

```bash
jq -r '.total, (.byDomain[:10][] | "\(.count)\t\(.domain)")' output/guests-by-domain.json
```

**Which Defender for Cloud plans are on the Standard tier, per subscription**

```powershell
Get-ChildItem output -Filter 'arm-*-defender-pricings.json' | ForEach-Object { $f = $_.Name; (Get-Content $_.FullName -Raw | ConvertFrom-Json) | Where-Object { $_.properties.pricingTier -eq 'Standard' } | ForEach-Object { "$f : $($_.name)" } }
```

```bash
for f in output/arm-*-defender-pricings.json; do jq -r --arg f "$(basename "$f")" '.[] | select(.properties.pricingTier=="Standard") | "\($f)\t\(.name)"' "$f"; done
```

**Which environments have Dataverse auditing off** (both sweeps' org files)

```powershell
Get-ChildItem output -Filter '*org*.json' | Where-Object { $_.Name -match '^(dv-.*-org|dvplus-.*-org-settings)\.json$' } | ForEach-Object { $o = (Get-Content $_.FullName -Raw | ConvertFrom-Json) | Select-Object -First 1; if ($o.isauditenabled -eq $false) { $_.Name } }
```

```bash
for f in output/dv-*-org.json output/dvplus-*-org-settings.json; do [ -f "$f" ] && jq -r --arg f "$(basename "$f")" '(if type=="array" then .[0] else . end) | select(.isauditenabled==false) | $f' "$f"; done
```

**Which client apps appear in the sign-in sample** (legacy protocols show by name:
IMAP4, POP3, Exchange ActiveSync, Authenticated SMTP, Other clients)

```powershell
(Get-Content output/signins-sample.json -Raw | ConvertFrom-Json) | Group-Object clientAppUsed | Sort-Object Count -Descending | Select-Object Count, Name
```

```bash
jq -r 'group_by(.clientAppUsed) | map("\(length)\t\(.[0].clientAppUsed)") | .[]' output/signins-sample.json
```

**Who holds Global Administrator**

```powershell
(Get-Content output/directoryRoles.json -Raw | ConvertFrom-Json) | Where-Object { $_.role -eq 'Global Administrator' } | Select-Object memberCount, members
```

```bash
jq -r '.[] | select(.role=="Global Administrator") | "\(.memberCount) members", .members[]' output/directoryRoles.json
```

**PIM: eligible (just-in-time) versus permanent active admin assignments**

```powershell
@((Get-Content output/pim-eligible.json -Raw | ConvertFrom-Json)).Count; @((Get-Content output/pim-active.json -Raw | ConvertFrom-Json) | Where-Object { $_.assignmentType -eq 'Assigned' -and -not $_.endDateTime }).Count
```

```bash
jq 'length' output/pim-eligible.json; jq '[.[] | select(.assignmentType=="Assigned" and .endDateTime==null)] | length' output/pim-active.json
```

### Privacy rules for the analysis itself

- `output/` and `.env` hold real tenant data and secrets. Never commit them. Never paste their
  contents into any external service, chat, ticket, or document that leaves the user's machine.
- Analysis must happen with an assistant the user is authorized to use with that data, under
  their organization's rules for it. If in doubt, work from `assessment-report.md` only, which
  carries verdicts and counts rather than records.
- Quote the minimum: a count, a name, a status. Do not echo whole files or record lists into a
  conversation when a one-liner answers the question.
- Do not upload `output/` to a hosted tool or copy it off the machine to analyze it elsewhere.

## Common issues

- **403 Forbidden on a Graph identity check** (auth methods policy, security defaults, PIM,
  Intune): the app is missing that permission or its admin consent. Run
  `scripts/check-setup.ps1` to see exactly which one, then grant it and click "Grant admin
  consent". The `*-ERROR.json` note names the permission. Intune calls also need an Intune
  licence in the tenant; a PIM error body citing a licence (AadPremiumLicenseRequired) means
  no Entra ID P2, so PIM is not in use and all admin access is standing.
- **400 Bad Request on a Dataverse query**: a `$select` column the table does not have. It is a
  query bug, not a permission problem (permission problems return 403). The `*-ERROR.json`
  carries the OData message naming the column; fix the column list in the script. All current
  columns are verified against the Dataverse table references.
- **Dataverse 403 on some environments**: the app is not an Application User with a role there.
  Expected for environments the user does not own or care about. `dataverse-plus` audits every
  environment it auto-discovers from `output/pp-environment-urls.json`, so narrowing
  `DATAVERSE_ENVIRONMENTS` only limits the basic `dataverse-sweep`; to silence the extra
  `dvplus-*-ERROR.json` files, run with `-SkipPowerPlatform` and delete that URL file.
- **Dataverse 404 on some environments**: the table does not exist in that environment type
  (Dataverse for Teams and Power Pages developer environments have a reduced schema).
  Expected; ignore.
- **`pp-dlp-policies.json` is `[]`**: a real result, not an error. The tenant has no connector
  data policy, and 5.3 reads Gap. A `pp-dlp-policies-ERROR.json` instead means the app is not
  registered as a Power Platform management application.
- **Roles, solutions and per-table audit flags all Not checked**: `DATAVERSE_ENVIRONMENTS` is
  blank, so the basic `dataverse-sweep` did not run. The auto-discovered URL list only feeds
  `dataverse-plus`. Set the variable to the environments that matter.
- **Every Power Platform check Not checked**: the BAP token failed. Register the app with
  `New-PowerAppManagementApp` (see docs/permissions.md).

## Privacy

- `./output` and `.env` are git-ignored and hold real tenant data and secrets. Never commit
  them, never paste their contents anywhere they would leave the user's machine, and never send
  them to an external service. The point of this tool is that nothing leaves the tenant.
- If a client secret was used, remind the user to rotate it and to delete a one-time app when
  the audit is done.
- For development and testing, use a clean-room tenant you own rather than an employer's
  tenant. The recipe is in [docs/dev-tenant-setup.md](docs/dev-tenant-setup.md).

## Scripts (all read-only)

- `scripts/_common.ps1` - config, the app-registration token (the only auth), paging, JSON
  output, and `Get-ErrorText` (captures the service's error body for the `*-ERROR.json` files).
- `scripts/check-setup.ps1` - preflight doctor: probes every permission, prints the fix for gaps.
- `scripts/graph-sweep.ps1`, `scripts/graph-identity-plus.ps1` - Entra ID identity plane
  (apps, service principals, roles, Conditional Access, sign-ins; auth methods, security
  defaults, PIM, Intune, named locations, guests by domain).
- `scripts/powerplatform-sweep.ps1` - Power Platform admin (environments with security group
  and Managed Environment state, DLP policies, tenant settings).
- `scripts/dataverse-sweep.ps1`, `scripts/dataverse-plus.ps1` - per-environment Dataverse
  config (auditing, roles, solutions, field security; org settings, email profiles, mailboxes,
  queues, field permissions).
- `scripts/azure-sweep.ps1`, `scripts/azure-plus.ps1` - Azure ARM (RBAC, SQL, Synapse, Key
  Vault, NSGs; Defender plans, Log Analytics and Sentinel, diagnostic settings, Logic Apps).
- `scripts/analyze.ps1`, `scripts/assessment-report.ps1` - build the ranked findings and the
  29-check report from `./output`. Local processing only, no network calls.

The coverage map in [docs/full-assessment-roadmap.md](docs/full-assessment-roadmap.md) lists,
for every check, the evidence file it reads and the script that produces it.
