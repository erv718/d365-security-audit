# Setup

Two ways to run this. Pick one. Everything the tool needs is **read-only**.

Quick note on Entra terms: you create an **App Registration** (this is where the client secret and API permissions live). Creating it automatically creates a matching **Enterprise Application** (the service principal), which is what you assign the Azure role to. There is no Entra **group** to add the app to. Its access comes from three places: Graph API permissions (with admin consent), an Azure **Reader** role, and a Dataverse **security role** as an application user.

---

## Option A - run as yourself (easiest, nothing to create)

If you already hold read access, you don't need an app at all.

1. Install the Azure CLI and run `az login`.
2. Leave `CLIENT_ID` and `CLIENT_SECRET` blank in `.env`.
3. Run `./run-audit.ps1`.

The scripts use your own delegated token. The first run may ask you to consent the Azure CLI to Microsoft Graph.

You need, as yourself: Global Reader or Security Reader in Entra, Reader on the subscriptions, and a read security role in each Dataverse environment. If you are a Dataverse System Administrator and an Entra admin, you already have all of this.

---

## Option B - a dedicated app registration (best for repeat or scheduled runs)

### 1. Create the app registration
Entra admin center (entra.microsoft.com) > **Identity > App registrations > + New registration**.
Name it e.g. `d365-security-audit`, single tenant, **Register**.
From the **Overview** page, copy the **Application (client) ID** and **Directory (tenant) ID**.

### 2. Add API permissions and grant admin consent
On the app > **API permissions > + Add a permission > Microsoft Graph > Application permissions**. Add:

- `Application.Read.All`
- `Directory.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`

Then click **Grant admin consent for <tenant>** (needs Global Administrator or Privileged Role Administrator).

For the **full assessment** (the `feature/full-assessment` branch) also add: `RoleManagement.Read.Directory`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, and optionally `InformationProtectionPolicy.Read.All`.

### 3. Create a client secret
On the app > **Certificates & secrets > + New client secret** > set a short expiry (6 months) > **copy the Value immediately** (it is shown once). A certificate is more secure if you would rather upload one.

### 4. Grant Azure Reader
Azure portal > each **Subscription > Access control (IAM) > + Add role assignment > Reader** > assign it to the app (search its name). Do this for every subscription you want to audit.

### 5. Add it as a Dataverse application user (per environment)
Power Platform admin center (admin.powerplatform.microsoft.com) > **Environments** > pick one > **Settings > Users + permissions > Application users > + New app user > + Add an app** > select your app > pick the root **Business unit** > add a **security role**.

A custom read-only role is cleanest; **System Customizer** works as a quick alternative (it can read metadata, roles, and solutions). Repeat for every environment you want to audit. This security role is the "role the account gets" - in Dataverse it is a security role, not an Entra group.

### 6. (Full assessment only) register it as a Power Platform management app
So the Power Platform admin endpoints (environments, DLP, tenant settings) work:

```powershell
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser
Add-PowerAppsAccount
New-PowerAppManagementApp -ApplicationId <client-id>
```

### 7. Fill .env and run
Copy `.env.example` to `.env`, set `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`. Leave `DATAVERSE_ENVIRONMENTS` blank on the full-assessment branch (it auto-discovers), or list your environment URLs on `main`. Then `./run-audit.ps1`.

---

## When you are done

- **Rotate the secret** if you used one, and delete a one-time app.
- Treat the `output/` folder as sensitive. It describes your security posture.
- **Never commit `.env`.** It is git-ignored by default.
- Get written authorization before pointing this at any tenant you do not own.
