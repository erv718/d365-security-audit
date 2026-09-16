# Developing and validating in a clean-room tenant

Developing this tool against an employer's tenant mixes real personal data (names, sign-ins,
guest email addresses, environment names) into a public project's working folder and into
every debugging conversation about it. A throwaway tenant that you own removes that problem
entirely: every finding the tool can produce is reproducible on demand, nothing in `output/`
belongs to anyone else, and you can delete the whole thing when you are done. This is the
recipe. Everything in it was free or trial-based at the time of writing (2026). Offers change,
so check the current terms before relying on any of them.

One rule for the whole recipe: turn off recurring billing on every trial the day you create
it, and keep the Azure spending limit on. Nothing here should ever charge a card.

## Automated version

Two scripts in `testdata/` do steps 5 and 6 for you. Both WRITE to the tenant, which is why
they live outside `scripts/` and carry the same warning: dev/test tenants you own only, never
anything else. They are not part of the audit tool and `run-audit.ps1` never calls them.

1. `testdata/bootstrap-audit-app.ps1`: signs you in with a device code as the dev tenant's
   Global Administrator, creates the read-only audit app with its seven Graph application
   permissions, grants admin consent, adds a client secret, assigns Reader on the
   subscriptions you pick, and prints the `.env` block. The Power Platform management-app
   registration stays manual (it is printed at the end).
2. `testdata/seed-dev-tenant.ps1 -GuestEmail you@example.com`: plants the fixture table
   below: test users, a guest invitation, an app with secrets expiring in 30 days and in 1 day,
   a Conditional Access policy requiring MFA (with you excluded), a PIM eligible assignment,
   and the Azure SQL server, NSG and Key Vault misconfigurations. Re-running reuses what
   already exists.

Run bootstrap first, then seed, then `./run-audit.ps1`. Steps 1 to 4 (tenant, trials,
Dataverse environment, Azure account) cannot be scripted and stay manual. The table in step 6
remains the reference for what each fixture is and why it fires.

## 1. Identity plane: a Microsoft 365 tenant

**Option A, try this first.** The Microsoft 365 Developer Program E5 sandbox
(developer.microsoft.com/microsoft-365/dev-program): a renewable E5 tenant with sample users,
Entra ID P2 included. Eligibility is restricted these days (mainly Visual Studio Enterprise
subscribers and some partner programs), so it may not be open to you.

**Option B, the fallback.** A Microsoft 365 Business Premium one-month trial, the plan
version WITHOUT Copilot. Start it from the Business Premium product page on microsoft.com
("Try free for one month") using a new email address you control. This creates a brand-new
tenant with you as Global Administrator. Business Premium includes Entra ID P1 (Conditional
Access, sign-in logs) and Intune.

Then add the free Microsoft Entra ID P2 trial so the PIM APIs return data instead of a
licence error: Microsoft 365 admin center (admin.microsoft.com) > Billing > Purchase
services > search "Microsoft Entra ID P2" > Start free trial. Open PIM once in the Entra
admin center (entra.microsoft.com > Identity governance > Privileged Identity Management)
and make one role assignment eligible instead of active, so `pim-eligible.json` has an entry.

## 2. Turn off recurring billing, today

admin.microsoft.com > Billing > Your products > select the trial > Billing settings >
turn recurring billing off. Repeat for every trial you add (Business Premium, Entra ID P2,
and any Power Apps or Dynamics 365 trial). A trial with recurring billing off simply expires.

## 3. Power Platform: a free Dataverse environment

Sign up for the Power Apps Developer Plan with a user from the dev tenant. The eligibility
rules and the sign-up link are on learn.microsoft.com under "Power Apps Developer Plan"
(power-apps/maker/developer-plan). It creates a Developer environment with a Dataverse
database at no cost.

Two things to know:

- Developer environments cannot have a security group (Microsoft rule), so check 1.3 does not
  count them. To exercise 1.3 you need a Sandbox, Production or Trial environment with
  Dataverse. Cheapest route: start a Power Apps Premium 30-day trial for the same user
  (admin.microsoft.com > Billing > Purchase services > Power Apps Premium > Start free
  trial, recurring billing off), then in the Power Platform admin center
  (admin.powerplatform.microsoft.com) > Manage > Environments > New > Type: Trial, with a
  Dataverse database. A Dynamics 365 Sales 30-day trial works too and gives you a Trial
  environment with a real D365 app in it.
- The default environment is created automatically with the tenant and normally has a
  Dataverse database. It is the one the report singles out for DLP coverage.

## 4. Azure: a free account plus a budget

Create an Azure free account (azure.microsoft.com/free) with the dev tenant user. It comes
with a spending limit that stops all charges when the credit is used up. Leave it on, and do
not upgrade the subscription to pay-as-you-go.

Immediately create a budget with an email alert so a forgotten resource cannot surprise you:
portal.azure.com > Cost Management + Billing > Cost Management > Budgets > Add. Monthly,
amount 15 (in your billing currency), alerts at 50%, 90% and 100% of actual cost, sent to
your email.

## 5. Create the read-only app registration

Follow [permissions.md](permissions.md) exactly: create the app, add the seven Graph
application permissions and grant admin consent, give it Reader on the free subscription, add
it as an Application User with a read-only role in each Dataverse environment, and register it
as a Power Platform management application with `New-PowerAppManagementApp`. Run that last
step from Windows PowerShell 5.1; the module uses .NET Framework and does not load in
PowerShell 7. Put `TENANT_ID`, `CLIENT_ID` and `CLIENT_SECRET` in `.env`, list the Trial and
Developer environment URLs in `DATAVERSE_ENVIRONMENTS`, and run `pwsh ./scripts/check-setup.ps1`
until every line reads `[OK]`.

## 6. Plant fixtures so every finding type fires

Deliberate misconfigurations in a tenant nobody uses. Each one maps to a finding or a check
verdict, so you can confirm the tool reports what it should.

| Fixture | Where | What fires |
|---|---|---|
| A second app registration with a client secret expiring in 30 days | entra.microsoft.com > App registrations > New registration; then Certificates & secrets > New client secret > Expires: Custom, 30 days out | analyze: credentials expiring within 60 days (LOW); 6.2 evidence |
| An already-expired secret | Secrets cannot be created with a past date. Create one with a custom expiry of tomorrow and run the audit the day after | analyze: expired credentials (MEDIUM); 6.2 = Gap |
| No Conditional Access policy | Do nothing; a new tenant has none. If security defaults are on, 1.4 reads Partial; turn them off (entra.microsoft.com > Overview > Properties > Manage security defaults) to see the Gap. Later add one policy requiring MFA for all users, state On, to see Aligned | 1.4 Gap / Partial / Aligned; analyze CA finding (HIGH while no policy enforces MFA) |
| Azure SQL logical server that allows Azure services | portal.azure.com > Create a resource > SQL server (the logical server alone, no database, no cost) > Networking > Public access: Selected networks, and tick "Allow Azure services and resources to access this server" | analyze: public network access (HIGH) and allows all Azure IPs 0.0.0.0 (HIGH) |
| NSG with RDP open to the internet | Create a resource > Network security group (free, no VM needed) > Inbound security rules > Add: Source Any, Destination port 3389, Action Allow | analyze: NSG opens port 3389 to the internet (HIGH) |
| Key Vault on access policies with public access | Create a resource > Key vault > Access configuration: Vault access policy; Networking: public access enabled. An unused standard vault costs nothing measurable | analyze: legacy access policies (MEDIUM), public network access (MEDIUM) |
| Dataverse auditing off in one environment | admin.powerplatform.microsoft.com > Manage > Environments > (env) > Settings > Audit and logs > Audit settings > leave "Start auditing" unchecked in one environment | 4.1 Gap or Partial; analyze auditing OFF (HIGH, for environments in DATAVERSE_ENVIRONMENTS) |
| No custom security roles | A fresh environment has none | 1.2 and 5.1 Gap; analyze zero custom roles (MEDIUM) |
| One guest account | entra.microsoft.com > Users > New user > Invite external user, to an email address you control | analyze guest count (MEDIUM); guest domains in the report |
| No environment security group | Leave the Trial environment without one | 1.3 and 2.4 Gap |
| No DLP policy | Do nothing | 5.3 Gap; default environment "NOT covered" |
| All Defender for Cloud plans on Free | Do nothing; a free account starts with every plan Free | 7.2 MANUAL with "all plans Free" |
| A legacy-auth sign-in (optional) | Connect an IMAP client with basic authentication to the test mailbox. Exchange Online blocks basic auth by default, so this may not work; if it does, the sample shows IMAP4 | analyze legacy auth (HIGH) |

Everything else the report needs (an environment inventory, a sign-in sample, PIM data, Intune
data) exists in the tenant as soon as you have signed in a few times and assigned the licences
above.

## 7. Run it

```powershell
./run-audit.ps1
```

Compare `output/assessment-report.md` and `output/FINDINGS-summary.json` with the fixture
table. Every planted item should appear. Then remove one fixture at a time and re-run to
confirm the verdict moves the way you expect.

## 8. Tear down

- Delete the Azure resource group(s) holding the SQL server, NSG and Key Vault.
- Delete or expire the client secrets and, if the app was one-time, the app registration.
- Leave recurring billing off; the trials expire on their own, and Microsoft deletes the
  tenant after the trial lapses and the retention period ends.
- `output/` from this tenant holds only fixture data, but treat it like any other run: do not
  commit it.
