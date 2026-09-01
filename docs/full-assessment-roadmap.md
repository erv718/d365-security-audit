# Full Assessment - roadmap and handoff (branch: feature/full-assessment)

Goal: grow this tool from a technical config auditor into a fully automated assessment that
covers all 8 domains / 29 checks of the Microsoft Power Platform & D365 Security Review,
runnable from just `.env.local`. This doc is the spec, so the work can be finished from any
session with tenant access (validation can't be done without a live tenant).

## Status

- `main`: validated, public. Covers identity, Dataverse security config, and Azure network. It works.
- `feature/full-assessment` (this branch): adds the modules below. NOT validated against a live tenant yet. Do not merge to `main` until `run-audit.ps1` runs clean.

## New modules to add (all read-only, all follow the `_common.ps1` conventions)

Each script dot-sources `_common.ps1` and uses `Get-Token`, `Invoke-Paged`, `Save-Json`. Every API area is wrapped in try/catch and writes a `*-ERROR.json` on failure instead of stopping, because several of these endpoints vary by tenant and license.

### scripts/graph-identity-plus.ps1  (token: https://graph.microsoft.com, base v1.0)
- Auth methods policy: `GET /policies/authenticationMethodsPolicy`
- Security defaults: `GET /policies/identitySecurityDefaultsEnforcementPolicy`
- PIM eligible: `GET /roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition($select=displayName)` (empty/403 implies PIM not used)
- PIM active: `GET /roleManagement/directory/roleAssignmentScheduleInstances?$expand=roleDefinition($select=displayName)`
- Intune compliance policies: `GET /deviceManagement/deviceCompliancePolicies`
- Intune device overview: `GET /deviceManagement/managedDeviceOverview`
- Named locations: `GET /identity/conditionalAccess/namedLocations`
- Guests by home domain: `GET /users?$filter=userType eq 'Guest'&$select=userPrincipalName` (ConsistencyLevel: eventual), group by home domain

### scripts/powerplatform-sweep.ps1  (token: https://api.bap.microsoft.com  - needs the app registered as a PP management app)
- Environments: `GET https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01` (capture azureRegion, environmentSku, linkedEnvironmentMetadata.instanceUrl). Also write the instanceUrl list to `pp-environment-urls.json` for auto-discovery.
- DLP: `GET .../providers/PowerPlatform.Governance/v2/policies?api-version=2019-05-01` (fallback v1 / 2016-11-01)
- Tenant settings: `POST .../providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2020-10-01`

### scripts/dataverse-plus.ps1  (per env; read URLs from DATAVERSE_ENVIRONMENTS and/or output/pp-environment-urls.json)
- Org settings: `GET organizations?$select=name,isauditenabled,isuseraccessauditenabled,auditretentionperiodv2,plugintracelogsetting`
- Email server profiles: `GET emailserverprofiles?$select=name,type`
- Queues: `GET queues?$select=name&$top=5&$count=true`
- Mailboxes: `GET mailboxes?$select=name,statecode&$top=5&$count=true`
- Field permissions (field-level security in use): `GET fieldpermissions?$select=attributelogicalname,fieldsecurityprofileid`

### scripts/azure-plus.ps1  (token: https://management.azure.com, per subscription)
- Defender for Cloud: `GET {base}/providers/Microsoft.Security/pricings?api-version=2023-01-01`
- Log Analytics: `GET {base}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01`; then Sentinel: `GET {workspaceId}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01` (200 = enabled)
- Diagnostic settings: `GET {base}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview`
- Logic Apps: `GET {base}/providers/Microsoft.Logic/workflows?api-version=2016-06-01`

### scripts/assessment-report.ps1  (the mapper - keep this one careful and consistent)
Reads everything in `output/` and walks all 8 domains / 29 checks. For each check, emit a status of `Aligned` / `Gap` / `Partial` / `Not checked`, or **`MANUAL: confirm X`** where no API can answer it. Output `assessment-report.json` plus a readable console table. This is the piece that makes it "cover the full scope."

## Cannot be automated (comes out as MANUAL line items)

- 7.1 Incident response plan (a document)
- 7.2 Vulnerability scanning / pen-test program (a process; Defender status is a partial proxy)
- 8.1 Data residency adequacy (a legal call - the tool reports the region, not whether it satisfies an obligation)
- IRM / rights-management specifics

## To finish and validate (from a session with tenant access)

1. Grant the app these read-only permissions and admin-consent them:
   - Graph (application): `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, and optionally `InformationProtectionPolicy.Read.All` (labels)
   - Azure: `Reader` on each subscription
   - Dataverse: application user + read role in each environment
   - Power Platform: register as a management app so the BAP endpoints work:
     `Add-PowerAppsAccount` then `New-PowerAppManagementApp -ApplicationId <clientId>`
2. Fill `.env.local` (TENANT_ID, CLIENT_ID, CLIENT_SECRET). Leave `DATAVERSE_ENVIRONMENTS` blank - `powerplatform-sweep` auto-discovers the environment URLs.
3. Run `./run-audit.ps1`.
4. Check `output/` for `*-ERROR.json`. The DLP and tenant-settings endpoints vary by tenant; if they errored, adjust the api-version/endpoint in `powerplatform-sweep.ps1` and rerun.
5. When it runs clean, `assessment-report.ps1` produces the 29-check report.
6. Merge `feature/full-assessment` into `main`.

## Ground rules (unchanged)

Read-only. Get written authorization first. Rotate the secret when done. Never commit `.env`.
