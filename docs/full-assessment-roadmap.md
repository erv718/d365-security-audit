# Assessment coverage map

How `scripts/assessment-report.ps1` turns the raw pulls in `output/` into the 8-domain /
29-check report, check by check: the evidence file each verdict reads, the script that
produces that file, and the verdict rule. Use it to trace where a verdict came from, to add
a check, or to see what is deliberately left manual.

The report covers 29 checks, 28 of them unique. 2.5 is a duplicate of 2.4 in Microsoft's
template, so it mirrors 2.4's verdict and is left out of the tally.

## Rules that apply to every check

- A verdict is only ever computed from a file in `output/`. If the file is missing because
  the pull failed or was skipped, or it is empty or cannot be parsed, the check is
  **Not checked** and the evidence column names the access that unlocks it. A file holding
  `[]` is a real zero result and gets the zero verdict. The tool never guesses a Gap or an
  Aligned.
- **MANUAL** means no API can answer it. The evidence column gives the exact portal path.
- 1.1 and 3.1 are platform facts (Entra is the only identity provider for D365 online;
  Dataverse encrypts at rest and in transit). Their evidence says so and lists what was
  verified on top of the fact.
- A failed pull leaves a `*-ERROR.json` next to where the file would have been, holding the
  HTTP status and the service's own error body.
- Script names below are the files in `scripts/` without the `.ps1` suffix.

## The 29 checks

| # | Check | Evidence file(s) in `output/` | Produced by | Verdict rule |
|---|---|---|---|---|
| 1.1 | Entra integrated with D365 | `pp-environments.json`, `signins-sample.json`, `dv-*` | powerplatform-sweep, graph-sweep, dataverse-sweep | Platform fact. Aligned when the environment inventory was read, or for the Dataverse environments the run read (tagged to that scope); Not checked otherwise |
| 1.2 | Roles least privilege | `dv-*-roles.json`, `dv-*-users.json`, `dv-*-orginfo.json` | dataverse-sweep | More than 3 people holding System Administrator in a Production environment = Gap (type from the inventory, else the environment's own report; an unknown type is named, not guessed); else 0 custom roles = Gap, any = Partial |
| 1.3 | Security group restricts environment access | `pp-environments.json` (`linkedEnvironmentMetadata.securityGroupId`) | powerplatform-sweep | Counted over eligible environments (has Dataverse; not Default, Developer or Teams). All bound = Aligned; some = Partial; none = Gap |
| 1.4 | Conditional Access | `ca-policies.json`, `security-defaults.json` | graph-sweep, graph-identity-plus | An enabled policy enforcing MFA = Aligned; none = Gap; security defaults on with no MFA policy = Partial |
| 1.5 | Intune device management | `intune-compliance-policies.json`, `intune-device-overview.json` | graph-identity-plus | Policies present = Partial; 0 = Gap; Intune not provisioned in the tenant (error 'Request not applicable to target tenant') = Gap |
| 1.6 | Device compliance enforced for D365 | `intune-compliance-policies.json`, `ca-policies.json` (`compliantDevice` control) | graph-identity-plus, graph-sweep | As 1.5; the evidence adds how many enabled CA policies require a compliant device |
| 2.1 | Service-to-service app access | `applications.json`, `servicePrincipals.json`, `FINDINGS-summary.json` | graph-sweep, analyze | High-privilege app findings present = Partial; none = Aligned. The evidence counts subscriptions and environments read, and a scoped run tags every narrowed plane |
| 2.2 | App/user access inventory | `applications.json`, `servicePrincipals.json`, `appRoleAssignments-*.json`, `directoryRoles.json`, `guest-count.json` | graph-sweep | Inventory produced = Partial (whether anyone reviews it is a process, not readable) |
| 2.3 | PIM / segregation of duties | `pim-eligible.json`, `pim-active.json` | graph-identity-plus | Eligible assignments > 0 = Aligned; 0 = Gap (all admin access is standing); no Entra ID P2 (error AadPremiumLicenseRequired) = Gap |
| 2.4 | Security groups restrict environment access | as 1.3 | powerplatform-sweep | Same evidence and verdict as 1.3 |
| 2.5 | Security groups (Microsoft template duplicate of 2.4) | as 1.3 | powerplatform-sweep | Mirrors 2.4; excluded from the tally |
| 3.1 | Encryption at rest / in transit | `pp-environments.json`, `arm-*-sql.json` (`minimalTlsVersion`), `arm-*-storage.json`, `arm-*-appservice.json` | powerplatform-sweep, azure-sweep, azure-exposure | Platform fact. Nothing read = Not checked; any SQL server, storage account or app accepting TLS below 1.2 or plain HTTP = Partial; else Aligned. Customer-managed keys always listed as not verified |
| 3.2 | Customer Lockbox + consent | none | | MANUAL: PPAC > Manage > Tenant settings > Customer Lockbox |
| 3.3 | PII / sensitivity labels | none | | MANUAL: Purview portal > Information Protection |
| 3.4 | Data retention | `dv-*-org.json`, `dvplus-*-org-settings.json` (`auditretentionperiodv2`) | dataverse-sweep, dataverse-plus | Audit-log retention set in any environment = Partial; none = Gap. Business-data retention (Dataverse long-term retention, Purview) is stated as not verified |
| 3.5 | Record sync / Outlook | `dvplus-*-emailprofiles.json` | dataverse-plus | Profiles found = Partial; 0 = Not in use |
| 3.6 | Mailbox / queue integration | `dvplus-*-emailprofiles.json`, `dvplus-*-mailboxes.json`, `dvplus-*-queues.json` | dataverse-plus | Only the default profile per environment = Not in use; more = Partial |
| 4.1 | D365 auditing enabled | `dv-*-org.json`, `dvplus-*-org-settings.json` (`isauditenabled`), `dv-*-entities.json` (`IsAuditEnabled`) | dataverse-sweep, dataverse-plus | On everywhere = Aligned; some = Partial; nowhere = Gap. Org auditing on but a key table (account, contact, systemuser, role, team, businessunit, fieldsecurityprofile) off = Partial |
| 4.2 | Events / user activity logged | same files (`isuseraccessauditenabled`, `isreadauditenabled`) | dataverse-sweep, dataverse-plus | Follows 4.1; Partial when auditing is on anywhere |
| 4.3 | SIEM / monitoring over Power Platform | `arm-*-sentinel.json`, `arm-*-diagnostic-settings.json`, `arm-*-loganalytics.json` | azure-plus | Sentinel on any workspace = Partial; none = Gap. Evidence adds activity-log export destinations (Event Hub, Log Analytics, storage) and workspace retention |
| 4.4 | Purview / Sentinel integration | `arm-*-sentinel.json` | azure-plus | Sentinel on = Partial; otherwise Not checked (Purview audit is manual) |
| 5.1 | Security role design | `dv-*-roles.json` | dataverse-sweep | As 1.2 |
| 5.2 | Field-level / record / BU security | `dvplus-*-fieldpermissions.json`, `dv-*-fieldsec.json` | dataverse-plus, dataverse-sweep | Any field permission, or a field security profile other than the built-in System Administrator one, = Partial; none = Gap. Counted per environment |
| 5.3 | DLP / IRM / classification | `pp-dlp-policies.json`, `pp-environments.json` | powerplatform-sweep | 0 policies = Gap; default environment covered = Aligned; otherwise Partial |
| 6.1 | External integration security | `arm-*-logicapps.json`, `arm-*-appservice.json`, `arm-*-apiconnections.json`, `arm-*-automation.json` | azure-plus, azure-exposure | Inventory produced = Partial; the evidence counts Logic Apps open to any caller, HTTP functions that need no key, API connections signed in as a named account and retired Run As connections |
| 6.2 | API keys / credentials / tokens | `applications.json` | graph-sweep | An expired credential still present = Gap; else Partial |
| 7.1 | Incident response plan | none | | MANUAL (a document and a process) |
| 7.2 | Vulnerability scanning / pen testing | `arm-*-defender-pricings.json` | azure-plus | Any documented Defender plan on Standard = Partial; else MANUAL |
| 8.1 | Data sovereignty / residency | `pp-environments.json` (`azureRegion`) | powerplatform-sweep | MANUAL; the regions are listed, adequacy is a legal call |

Both Dataverse sweeps cover the same environments: the selection (`-Environments`,
`scope.json`, `DATAVERSE_ENVIRONMENTS`) or, with none, every environment the Power Platform
sweep discovered. `dv-*-org.json` and `dvplus-*-org-settings.json` describe the same
environment; the report merges them into one record per environment (the plus sweep adds
read-log auditing and plugin tracing). The environment type (Production, Sandbox, ...) comes
from `pp-environments.json`, or without the admin API from `dv-*-orginfo.json`, the
environment's own OrganizationType.

## Beyond the checklist

| Item | Evidence file(s) | Produced by |
|---|---|---|
| Managed Environments coverage | `pp-environments.json` (`governanceConfiguration.protectionLevel` = Standard) | powerplatform-sweep |
| Default environment: DLP coverage, Managed flag, default environment routing | `pp-environments.json`, `pp-dlp-policies.json`, `pp-tenant-settings.json` | powerplatform-sweep |
| Guest concentration by home domain | `guests-by-domain.json` | graph-identity-plus |
| Ranked technical findings | `FINDINGS-summary.json` | analyze |

The technical findings cover: expired and expiring app credentials; apps holding high-privilege
tenant-wide Graph or Exchange Online permissions; Conditional Access and MFA enforcement;
legacy/basic-auth sign-ins in the sample; the guest count; the Global Administrator count;
dormant accounts (90+ days) and dormant accounts holding a directory role or Dataverse System
Administrator (`users-signin-activity.json`); Dataverse auditing off per environment and per key
table; zero custom security roles; who holds System Administrator, including the organisation's
own application users (`dv-*-users.json`); unmanaged solutions in Production environments; SQL
servers and Synapse workspaces with public access or an allow-all-Azure rule; every allowlist
(SQL, Synapse, storage, NSG sources, App Service, Logic Apps, the Dataverse IP firewall) graded
by breadth; Owner sprawl and service principals holding Owner (`arm-*-rbac.json`); NSG rules
open to the internet graded by port; VMs with a public IP, and those with no NSG at all;
storage accounts open to all networks, with anonymous blob access, plain HTTP, old TLS or
shared keys; App Service and Function Apps without HTTPS Only, on old TLS, with plain FTP or
remote debugging, open to any IP, or with HTTP functions that need no key; Logic Apps open to
any caller; retired Automation Run As connections; API connections signed in as a named or
dormant account; the Dataverse IP firewall off or in audit-only mode; Key Vaults on access
policies or with public access. The report also lists which resource types in the inventory a
security rule checks, and `inventory-check.ps1` cross-checks a portal export.

When a pull fails, every **Not checked** row it feeds quotes the service's own error from the
matching `*-ERROR.json` (HTTP status, error code, message).

## What cannot be automated, and why

- **7.1 Incident response plan.** A document and a process. No API exposes whether one exists,
  who owns it, or when it was last exercised. The evidence points at the Defender portal only
  to check that alerts are being worked.
- **3.2 Customer Lockbox.** The setting is not exposed to an application token through any
  admin API this tool can use. It also only applies to Managed Environments, which the report
  does count.
- **3.3 Sensitivity labels / PII classification.** Label definitions and auto-labeling policies
  live in Purview, and Dataverse column labels are applied through Purview Data Map. Reading
  them needs Purview permissions and scan state outside this tool's scope.
- **8.1 Residency verdict.** The tool lists the Azure region of every environment. Whether that
  satisfies a legal or contractual obligation is a judgement, not a setting.
- **7.2 is half automated.** Defender for Cloud plan tiers are a proxy for vulnerability
  scanning; a penetration-testing program is a process.

## Future

- Flows running under interactive identities: needs the Power Automate admin API (flow owners
  and the connections they run under), which this tool does not call yet.
- Purview detail: retention policies, label usage and audit-log coverage for Dataverse; needs
  Purview permissions.
- HTML report output and a comparison against a saved baseline (see the README roadmap).

## Validation

Live validation is the user's own run of `./run-audit.ps1` against a tenant they are
authorized to audit; `output/` never leaves that machine. `scripts/check-setup.ps1` pinpoints
consent gaps before the sweeps run, and the `*-ERROR.json` files carry the service's own error
text for anything that still fails. For developing and validating without company data, use
the clean-room tenant recipe in [dev-tenant-setup.md](dev-tenant-setup.md).
