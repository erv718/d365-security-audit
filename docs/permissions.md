# Permissions

The tool never writes to your tenant, and it authenticates ONLY as a read-only app
registration that you create. There is no interactive sign-in, no device code, and no CLI
fallback - by design. Sections 1 to 4 grant read access only. Section 5 is optional and is the
one exception: read it before you do it.

Every run starts with a setup check that probes each item below and prints the exact fix
for anything missing. You can also run it alone: `pwsh ./scripts/check-setup.ps1`

## 1. Create the app (2 minutes)

Quick note on Entra terms: you create an **App Registration** (where the client secret and
API permissions live). That automatically creates a matching **Enterprise Application**
(the service principal), which is what you assign the Azure role to. There is no Entra
group involved: the app's access comes from Graph API permissions (with admin consent),
an Azure **Reader** role, and a Dataverse **security role** as an application user.

1. Go to **entra.microsoft.com** and sign in as an admin.
2. **App registrations** > **New registration**.
3. Name it (for example `SecAudit-ReadOnly`). Leave everything else default. **Register**.
4. On its **Overview** page, copy the **Application (client) ID** and the
   **Directory (tenant) ID**. These go in `.env` as `CLIENT_ID` and `TENANT_ID`.
5. **Certificates & secrets** > **New client secret** > pick a short expiry (90 days) >
   **Add**. Copy the **Value** column immediately (it hides after you leave the page).
   This goes in `.env` as `CLIENT_SECRET`.

## 2. Microsoft Graph (identity plane)

| Application permission | Why |
|---|---|
| `Application.Read.All` | App registrations, service principals, credential expiry, app permissions |
| `RoleManagement.Read.Directory` | Directory roles + members, PIM eligible/active assignments |
| `User.Read.All` | Guest counts, the names behind role members, per-user sign-in activity (dormant accounts) |
| `Policy.Read.All` | Conditional Access, named locations, auth methods policy, security defaults |
| `AuditLog.Read.All` | Sign-in sample and per-user last sign-in for dormant-account detection (needs Entra ID P1) |
| `DeviceManagementConfiguration.Read.All` | Intune device compliance policies |
| `DeviceManagementManagedDevices.Read.All` | Intune managed-device overview |

How to add them:

1. App registrations > your app > **API permissions** > **Add a permission**.
2. Choose **Microsoft Graph** > **Application permissions** (not Delegated).
3. Search for each name above and tick it. After all 7, click **Add permissions**.
4. Back on the API permissions page, click **Grant admin consent for (your org)** > Yes.
   The Status column must show green check marks. Without consent, every call returns 403.

**Optional tightening.** Two of the seven are broader than the single call that needs them,
and Microsoft publishes narrower alternatives for those calls:

| Broad permission | Narrower alternative | Covers only |
|---|---|---|
| `Policy.Read.All` | `Policy.Read.AuthenticationMethod` | the authentication methods policy pull |
| `RoleManagement.Read.Directory` | `RoleEligibilitySchedule.Read.Directory` + `RoleAssignmentSchedule.Read.Directory` | the two PIM pulls |

The broad permissions are still required by other pulls in the same script (`Policy.Read.All`
for Conditional Access, named locations and security defaults; `RoleManagement.Read.Directory`
for directory roles and their members), so the list above is already the practical minimum.
The alternatives are listed for admins who audit what each individual call needs.

**Nothing more.** The setup check lists every application permission the app holds and names
any the audit never uses (for example `Mail.Read`). Take those away: on the API permissions
page, on each such row, **...** > **Revoke admin consent**, then **...** > **Remove permission**.

## 3. Azure subscriptions (ARM)

The app needs the **Reader** role on each subscription you want audited. Reader covers every
Azure read the audit makes: role assignments, SQL and Synapse firewalls, Key Vaults, NSGs, VMs
and their network interfaces and public IPs, storage accounts, App Service and Function Apps
(web config and function list), Logic Apps, Automation accounts, API connections and the
resource inventory. It never asks for keys, app settings or connection secrets, which Reader
cannot read anyway.

1. Go to **portal.azure.com** > **Subscriptions** > click a subscription.
2. While here, copy the **Subscription ID** (goes in `.env` under `AZURE_SUBSCRIPTIONS`).
3. **Access control (IAM)** > **Add** > **Add role assignment**.
4. On the Role tab pick **Reader** (under "Job function roles") > **Next**.
5. **Select members** > search your app's name > select it > **Select**.
6. **Review + assign**. Repeat for each subscription.

## 4. Dataverse (per environment)

The app must exist inside each environment as an **Application User** with a read-only
security role.

1. Go to **admin.powerplatform.microsoft.com** > **Environments** > click an environment.
2. **Settings** > **Users + permissions** > **Security roles** > **+ New role**. Name it (for
   example `SecAudit - Read Only`) and keep the default business unit. Turn off **Include App
   Opener privileges for running Model-Driven apps**: it copies in the privileges for opening
   apps, which the audit never does. **Save**.
3. In the new role, set **Read** to **Organization** on each table below and nothing else (no
   Create, Write, Delete, Append, Append To, Assign or Share). Find each one with the role
   editor's search box. **Save**.
4. **Settings** > **Users + permissions** > **Application users** > **+ New app user** >
   **Add an app** > pick your app > **Add**. **Business unit**: the default one it offers.
   **Security roles**: only the role from step 2. **Create**.
5. Repeat in every environment you audit. Roles are per environment, so create the role in
   each one too.

| Table (as the role editor names it) | Why the audit reads it |
|---|---|
| Organization | audit settings and audit-log retention (3.4, 4.1, 4.2) |
| Security Role | custom vs built-in roles, and the role each user holds (1.2, 5.1) |
| User | who holds System Administrator, people and application users (1.2, 5.1) |
| Solution | unmanaged solutions in Production |
| Publisher | the solution read includes each solution's publisher, and Dataverse rejects the whole solution read without it |
| Field Security Profile | column-level security in use (5.2) |
| Email Server Profile | server-side sync profiles (3.5) |
| Mailbox | mailbox records (3.6) |
| Queue | queues (3.6) |

Team and Business Unit are not needed (harmless if already ticked).

You do not have to get this right by hand: on every run the setup check reads one row through
each of the audit's Dataverse queries and names any table the role is still missing (it also
shows the role the app user holds and the environment type, Production or Sandbox). If it
names a table that is not in the list above, add Read (Organization) on that one the same way.
Never give the app user `System Administrator` or `System Customizer`: both can change the
environment, and the setup check flags them.

**Automated alternative:** `testdata/add-dataverse-app-user.ps1 -ClientId <your CLIENT_ID> -RoleName 'SecAudit - Read Only'`
discovers every Dataverse environment in the tenant and does the same two changes (app
user + role binding) over REST, with a plan table first and `-Force` to apply. Always pass
`-RoleName` with your read-only role: without it the script binds System Customizer, which
this section tells you never to use. It asks you to sign in as a tenant admin (device code)
once for the admin API and once per environment. It is a throwaway-tenant helper; review the
script first, it writes exactly those records and nothing else.

## 5. Power Platform admin API (optional: environment list, DLP, tenant settings)

This is the one step that is **not read-only**, so it is optional.

Microsoft offers exactly one way for an app to read the environment list, DLP (connector data)
policies and tenant settings: registering it as a Power Platform management application. A
registered app is treated like a user holding the Power Platform Administrator role, and
Microsoft states that granular roles "can't be assigned to limit their capabilities". The
newer read-only "Power Platform reader" role (preview) does not cover listing environments, so
it is no alternative yet. The audit itself still only reads; the point is what the credential
could do while the registration exists.

Choose one:

- **Skip it.** Name the environments yourself, for example
  `./run-audit.ps1 -Environments https://<org>.crm.dynamics.com` (or `scope.json`, or
  `DATAVERSE_ENVIRONMENTS`). Every Dataverse check runs, and each environment reports its own
  type (Production or Sandbox). Checks 1.3 and 2.4 (environment security groups) and 5.3 (DLP)
  read Not checked: confirm those by hand in the Power Platform admin center.
- **Register it for the run only.** Register right before the run, remove it right after, and
  delete the client secret when you are done (see "After you run it").

Signed in as a Power Platform admin:

```powershell
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
Add-PowerAppsAccount
New-PowerAppManagementApp -ApplicationId <your CLIENT_ID>
# ...run the audit, then:
Remove-PowerAppManagementApp -ApplicationId <your CLIENT_ID>
```

**Run this from Windows PowerShell 5.1** (the `powershell.exe` that ships with Windows). The
module is built on .NET Framework: it does not load in PowerShell 7 and does not work on
macOS or Linux. It is tenant-level configuration, so one run from any Windows machine covers
audits run later from anywhere, including macOS and Linux. The audit itself has no such
limitation; it is pure REST and runs on PowerShell 5.1 and 7 on any OS.

If `Install-Module` warns that it cannot resolve the package source, the gallery registration
is broken on that machine. Re-register it, then retry:

```powershell
Register-PSRepository -Default
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```

Note on the token audience, for troubleshooting only: the tool requests its Power Platform
admin token for the audience `https://api.bap.microsoft.com` (verified working against a real
tenant). Microsoft's own `Microsoft.PowerApps.Administration.PowerShell` module requests
`https://service.powerapps.com` for the same endpoints. Both are accepted. If the environments
or DLP pull ever returns 401 while the registration above is in place, this is the place to look.

## After you run it

- If you registered the management app (section 5), remove it:
  `Remove-PowerAppManagementApp -ApplicationId <your CLIENT_ID>`.
- **Delete or rotate the client secret** when the audit is done, and delete the app if it was
  one-time. Treat `output/` as sensitive - it contains your real tenant configuration.

## Before you run it

Get written authorization. This reads your organization's security configuration across
identity, data platform, and cloud infrastructure. Run it only against environments you
are authorized to audit.
