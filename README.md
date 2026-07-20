# reco-splunk-TA

Splunk Technology Add-on for [Reco](https://reco.ai) — a full-lifecycle SaaS
security platform. It pulls posture findings, threat alerts, accounts,
discovered apps, identities, and audit/system logs from your Reco tenant into
Splunk.

## Version 2.0

2.0 migrates every input off Reco's old internal table API
(`policy-subsystem/alert-inbox/table`, `asset-management/query`) onto Reco's
public [External API](https://readme.reco.ai). This is the same tenant and
the same API key you already have configured — only the wire format and a
couple of incremental-filter fields changed. See **"Upgrading from 1.x"**
below before you upgrade an existing installation; several output fields are
renamed or reshaped and any saved searches/dashboards built on 1.x field
names will need to be updated.

## Requirements

- A Reco tenant URL (e.g. `your-tenant.us.reco.ai`)
- A Reco API key with read access to the resources you want to collect
  (Posture, Alerts, Accounts, App Discovery, Identities, Audit Logs)
- Splunk 9.x, Python 3 (this TA is Python 3 only)

## Configuration

Set the tenant URL and API key once, globally, under the add-on's
**Configuration** page (or `local/ta_reco_settings.conf`):

| Setting | Description |
|---|---|
| `tenant_url` | Your Reco tenant hostname, without scheme (e.g. `your-tenant.us.reco.ai`) |
| `api_key` | Reco API key, sent as `Authorization: Bearer <api_key>` on every request |

Then enable the inputs you need under **Inputs**:

| Input | Reco resource | Default interval | Default `limit` (page size) | Other args |
|---|---|---|---|---|
| `reco_posture` | Posture issues/findings | 3600s | 1000 | `status` (unused, see Known limitations) |
| `reco_alerts` | Threat alerts | 30s | 1000 | `alert_status` (unused, see Known limitations) |
| `reco_accounts` | Enriched accounts | 43200s | 1000 | — |
| `reco_discovery` | Discovered apps (Shadow IT / SaaS discovery) | 43200s | 1000 | — |
| `reco_identities` | Identities | 43200s | 1000 | — |
| `reco_system_logs` | Audit logs | 30s | 1000 | — |

`limit` controls the External API page size per request (max 10000); every
input now pages through **all** matching results, not just the first page
(see "Behavior changes" below).

## Incremental polling

Three inputs track a checkpoint so repeat polls only fetch new data:

- **`reco_posture`** filters on `currentStatusSince` — the one posture-issue
  timestamp that's genuinely change-conditioned. `updatedAt`/`createdAt` are
  both re-stamped by Reco's hourly posture rescan even when nothing about a
  finding changed, so they would cause duplicate re-sends; this is the fix
  for that. **Known limitation:** a finding whose score/risk/other fields
  change without a status transition will not be re-sent under this filter.
- **`reco_alerts`** filters on `createdAt`. Alerts are event-driven (one row
  per detected violation) rather than a periodically-rescanned checklist, so
  `createdAt` is stable here and won't cause duplicates.
- **`reco_system_logs`** filters on `timestamp` (unchanged from 1.x — this
  was already the one 1.x input with working incremental logic).

`reco_accounts`, `reco_discovery`, and `reco_identities` do a full re-pull on
every poll — unchanged from 1.x, where the incremental-checkpoint code for
these three was unreachable dead code, so this was already their effective
behavior.

## Known limitations (carried forward from 1.x, unchanged)

- The `status` arg on `reco_posture` and `alert_status` on `reco_alerts` are
  **not applied** — both are hardcoded off in the input code. If you've set
  these in `inputs.conf`, they currently have no effect on what's fetched.
- `source`/data-source filtering is not available on any input; no input
  declares a `source` argument.

## Upgrading from 1.x

This is a breaking change for anything built on the raw event JSON (saved
searches, dashboards, alerts). The bundled dashboards
(`reco__posture`, `reco__posture__details`, `reco__alerts`,
`reco__alert__history`, `reco__accounts`, `reco__discovery`, `reco__users`)
reference 1.x field names and **will need to be updated** to the 2.0 field
names before they render correctly — this was not done as part of the 2.0
release and should be tracked as a follow-up.

At a high level:
- Every event is now plain JSON with camelCase keys — no more base64-encoded
  cell values.
- Enum fields (status, severity, risk level, etc.) are now returned as
  **string enum names** (e.g. `"ALERT_STATUS_TO_REVIEW"`) instead of raw
  integer codes (e.g. `5`).
- Several fields were renamed or reshaped into nested objects (e.g. a flat
  `instance_id` is now `instance.id` / `checkedInstance.id`).

See [`CHANGELOG_v2.0.md`](CHANGELOG_v2.0.md) for the exact field-by-field
diff per input.

## Development

`bin/reco_external_api.py` is the shared External API client (pagination,
auth headers, checkpoint formatting) used by every `input_module_reco_*.py`.
Each input module still follows the Splunk Add-on Builder convention: don't
edit `reco_*.py` (auto-generated wrapper) — only edit `input_module_reco_*.py`.
