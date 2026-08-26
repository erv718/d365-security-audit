# Permissions

All read-only. The tool never writes to your tenant.

## Option A - a dedicated app registration (recommended for repeat runs)

Create an app registration and grant these **application** permissions.

### Microsoft Graph (identity plane)
| Permission | Why | Needs admin consent |
|---|---|---|
| `Application.Read.All` | App registrations + credential expiry | Yes |
| `Directory.Read.All` | Users, groups, directory roles, guests | Yes |
| `Policy.Read.All` | Conditional Access policies | Yes |
| `AuditLog.Read.All` | Sign-in sample (needs Entra ID P1) | Yes |

### Azure resources (ARM)
- **Reader** role on each subscription you want to audit (Access control / IAM).

### Dataverse (per environment)
- Add the app as an **Application User** in each environment with a read-only security role.
- A custom role with Read (Organization scope) on Solution, Security Role, Field Security Profile, plus Entity/Attribute read is enough. `System Customizer` works as a quick alternative but grants more than read.

## Option B - run as yourself

Skip the app registration. Run `az login` and leave `CLIENT_ID`/`CLIENT_SECRET` blank. The scripts use your delegated token. You need to already hold the equivalent read access (e.g. a Global Reader / Security Reader in Entra, Reader on the subscriptions, and a read role in each Dataverse environment).

## After you run it

If you used a client secret, **rotate it** when the audit is done, and delete the app if it was one-time. Treat `output/` as sensitive - it contains your real tenant configuration.

## Before you run it

Get written authorization. This reads your organization's security configuration across identity, data platform, and cloud infrastructure. Run it only against environments you are authorized to audit.
