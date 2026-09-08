# Permissions

All read-only. The tool never writes to your tenant, and it authenticates ONLY as a
read-only app registration that you create. There is no interactive sign-in, no device
code, and no CLI fallback - by design.

Every run starts with a setup check that probes each item below and prints the exact fix
for anything missing. You can also run it alone: `pwsh ./scripts/check-setup.ps1`

## 1. Create the app (2 minutes)

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
| `User.Read.All` | Guest counts and the names behind role members |
| `Policy.Read.All` | Conditional Access, named locations, auth methods policy, security defaults |
| `AuditLog.Read.All` | Sign-in sample + MFA registration report (needs Entra ID P1) |
| `DeviceManagementConfiguration.Read.All` | Intune device compliance policies |
| `DeviceManagementManagedDevices.Read.All` | Intune managed-device overview |

How to add them:

1. App registrations > your app > **API permissions** > **Add a permission**.
2. Choose **Microsoft Graph** > **Application permissions** (not Delegated).
3. Search for each name above and tick it. After all 7, click **Add permissions**.
4. Back on the API permissions page, click **Grant admin consent for (your org)** > Yes.
   The Status column must show green check marks. Without consent, every call returns 403.

## 3. Azure subscriptions (ARM)

The app needs the **Reader** role on each subscription you want audited.

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
2. **Settings** > **Users + permissions** > **Application users**.
3. **+ New app user** > **Add an app** > pick your app > **Add**.
4. **Business unit**: pick the default one it offers.
5. Under **Security roles**, add a read-only role, then **Create**.
6. Repeat for every environment listed in `DATAVERSE_ENVIRONMENTS`.

About the role: a custom role with Read at Organization scope on Solution, Security Role,
and Field Security Profile, plus Entity/Attribute read, is enough. `System Customizer`
works as a quick alternative but grants more than read - prefer the custom read-only role.

## 5. Power Platform admin API (environments, DLP, tenant settings)

Register the app as a Power Platform management application. One time, from any machine
with PowerShell, signed in as a Power Platform admin:

```powershell
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
Add-PowerAppsAccount
New-PowerAppManagementApp -ApplicationId <your CLIENT_ID>
```

## After you run it

**Rotate the client secret** when the audit is done, and delete the app if it was
one-time. Treat `output/` as sensitive - it contains your real tenant configuration.

## Before you run it

Get written authorization. This reads your organization's security configuration across
identity, data platform, and cloud infrastructure. Run it only against environments you
are authorized to audit.
