# Contributing

Thanks for helping. This is a read-only security audit tool, so there's one rule that matters more than any style preference: **it never writes to a tenant.**

## The rules

- **Read-only.** Every API call is a GET or a paged read. No `POST`/`PATCH`/`PUT`/`DELETE` that changes state (the only exception is a read-only `POST` like a `list*` action that returns data). A PR that mutates a tenant will be rejected.
- **Fail soft.** Wrap each API area in its own `try/catch`. On failure, `Write-Warning` and save a `<name>-ERROR.json`, then keep going. Missing endpoints, licenses, and permissions are normal and must never stop the run.
- **No secrets or tenant data in the repo.** Config comes from `.env`, which is git-ignored. Never commit real IDs, secrets, or anything from `output/`.

## Adding a check or a module

1. Dot-source `_common.ps1` first and reuse its helpers: `Get-Token`, `Invoke-Paged`, `Save-Json`, `Get-Conf`, `Get-OutDir`. Don't re-implement auth or paging.
2. Save raw evidence to `output/<name>.json`.
3. New sweep? Add a `Step 'scripts/<name>.ps1'` line to `run-audit.ps1`.
4. Maps to a Microsoft assessment check? Add the logic to `scripts/assessment-report.ps1`.
5. Standalone technical finding? Add it to `scripts/analyze.ps1`.
6. New permission needed? Document it in `docs/permissions.md` and `docs/setup.md`, and use the least-privilege read scope.

## Before you open a PR

Parse-check every script (no live tenant needed):

```powershell
Get-ChildItem scripts -Filter *.ps1 | ForEach-Object {
  $e = $null
  [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$e) | Out-Null
  if ($e) { Write-Host "PARSE ERRORS in $($_.Name)"; $e }
}
```

Then confirm it stays read-only, fails soft, and keeps the existing console style (cyan progress, yellow counts, green done line).

## Style

Plain PowerShell, cross-platform (PowerShell 7 on Windows, macOS, Linux). No Windows-only cmdlets. Keep it readable over clever.
