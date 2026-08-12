# reco-splunk-TA

Splunk Technology Add-on for [Reco](https://reco.ai), the solution trusted by
modern enterprises to secure SaaS AI, applications, and agents. Reco's SaaS &
AI Security platform provides complete visibility and control across your
entire SaaS ecosystem — from core SaaS applications to the latest AI agents —
enabling security teams to keep pace with the speed of AI adoption while
maintaining airtight security and reducing risk.

This add-on pulls posture findings, threat alerts, accounts, discovered apps,
identities, and audit/system logs from your Reco tenant into Splunk.

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
| `reco_posture` | Posture issues/findings | 3600s | 0 (no limit) | `status` (unused, see Known limitations) |
| `reco_alerts` | Threat alerts | 30s | 0 (no limit) | `alert_status` (unused, see Known limitations) |
| `reco_accounts` | Enriched accounts | 43200s | 0 (no limit) | — |
| `reco_discovery` | Discovered apps (Shadow IT / SaaS discovery) | 43200s | 0 (no limit) | — |
| `reco_identities` | Identities | 43200s | 0 (no limit) | — |
| `reco_system_logs` | Audit logs | 30s | 0 (no limit) | — |

`limit` controls the External API page size per request (max 10000); every
input pages through **all** matching results regardless of `limit` (see
`CHANGELOG_v2.0.md`'s "Cross-cutting changes" for why), so `limit` only
affects how many items are requested per HTTP call, not how much data is
collected. `0` (the default) or unset means "no limit" — the TA uses the
largest page size (10000) to minimize round trips. Set it lower only if you
need smaller per-request payloads (e.g. for a slow/constrained network path
to the tenant).

## Incremental polling

Every input now tracks a checkpoint so repeat polls only fetch new/changed data:

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
- **`reco_accounts`, `reco_discovery`, `reco_identities`** filter on
  `lastSeen` — an aggregate of real vendor/event timestamps (last activity,
  login, or usage, depending on the entity), verified to be genuinely
  change-conditioned and not touched by any periodic recompute regardless of
  real change (unlike `updatedAt`/`createdAt` on these same entities, which
  *are* unconditionally re-stamped on their periodic enrichment recompute —
  the same trap posture's `updatedAt` was). 1.x never applied a filter here
  at all (the checkpoint code was dead), so this is new in 2.0.
  **Known limitation:** `reco_discovery`'s backing data
  (`app_discovery_v4`) is a ClickHouse materialized view refreshed wholesale
  every 3 hours — polling more frequently than that won't surface anything
  new between refreshes, regardless of filter.

## Known limitations (carried forward from 1.x, unchanged)

- The `status` arg on `reco_posture` and `alert_status` on `reco_alerts` are
  **not applied** — both are hardcoded off in the input code. If you've set
  these in `inputs.conf`, they currently have no effect on what's fetched.
- `source`/data-source filtering is not available on any input; no input
  declares a `source` argument.

## Upgrading from 1.x

This is a breaking change for anything built on the raw event JSON (saved
searches, dashboards, alerts). The bundled dashboards that shipped with 1.x
(`reco__posture`, `reco__posture__details`, `reco__alerts`,
`reco__alert__history`, `reco__accounts`, `reco__discovery`, `reco__users`)
referenced 1.x field names and would not have rendered correctly against 2.0
data, so **they were removed in 2.0** rather than updated. If you relied on
any of them, rebuild the equivalent view/dashboard yourself against the 2.0
field names in [`CHANGELOG_v2.0.md`](CHANGELOG_v2.0.md) — the app's nav now
only shows Inputs, Configuration, and Search.

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

### Rebuilding (UCC framework)

As of the UCC 6.5.3 migration, `globalConfig.json` + `package/` at repo root
are the source of truth for the Configuration/Inputs UI schema, REST
handlers, and conf file generation — `default/`, `appserver/`, `bin/`
(excluding the `input_module_reco_*.py`/`reco_external_api.py` files, which
live in `package/bin/` and are just copied through), `metadata/`, `static/`,
and `lib/` at repo root are all *build output*, not hand-edited directly.

To rebuild after changing `globalConfig.json` or anything under `package/`:

```bash
pip install splunk-add-on-ucc-framework
ucc-gen build --ta-version 2.0.0 -o /tmp/ucc-out
rsync -a --delete /tmp/ucc-out/TA-reco/ ./  # review the diff before committing
```

`package/lib/requirements.txt` pins `solnlib<8.0.0` deliberately — solnlib
8.0+ pulls in grpcio/opentelemetry/protobuf for tracing this add-on doesn't
use, and grpcio ships a platform-compiled `.so` that would only work on
whatever machine ran the build. Don't remove that pin without checking what
it drags in.
