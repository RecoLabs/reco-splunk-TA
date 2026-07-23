# reco-splunk-TA 2.0 — Field & Behavior Changes

Full property diff between 1.x (internal table API) and 2.0 (Reco External
API), for release notes. Old "field" = the base64-cell `key` in the 1.x
table-API response; new "field" = the JSON key in the 2.0 External API
response. Everything here was confirmed directly against source (Go
mappers, proto/OpenAPI spec, and the ClickHouse/Postgres view definitions
backing each endpoint) — nothing is guessed.

## Cross-cutting changes (all 6 inputs)

- **Transport**: `PUT` with a JSON `getTableRequest` body → `GET` with query
  params (`startIndex`, `count`, `filters`, `sortBy`, `sortOrder`).
- **Response envelope**: `getTableResponse.data.rows[].cells[{key,value}]`
  (base64-encoded values, decode required) → plain JSON objects, camelCase
  keys, no encoding. `totalNumberOfResults` (separate `/count` call, only on
  accounts/discovery/identities/system_logs) → `totalResults`/`itemsPerPage`
  returned inline on every page (no separate count call needed).
- **Pagination**: posture/alerts previously fetched a single page capped at
  `limit` with no next-page handling — results beyond `limit` in one poll
  were silently dropped. accounts/discovery/identities/system_logs already
  paginated fully. **2.0 pages through all results on every input** — this
  is a behavior change for posture/alerts specifically (fixes a latent data
  loss bug; `limit` now controls page size, not a hard cap).
- **Enums**: raw integer codes (e.g. `status=5`, `risk_level=30`) → string
  enum names (e.g. `checkStatus="ALERT_STATUS_TO_REVIEW"`,
  `severity="HIGH"`). Any saved search/dashboard filtering on the old
  numeric codes will need updating.
- **Auth**: unchanged — `Authorization: Bearer <api_key>`, same tenant host.

## Posture Issues (`reco_posture`)

Old: `POSTURE_CHECKLIST` via `alert-inbox/table`. New: `GET /api/v1/external-api/posture-issues/list`.

**Incremental filter changed**: `created_at` (1.x, but disabled by a bug —
see below) → `currentStatusSince` (2.0). `updated_at`/`created_at` are both
re-stamped by Reco's hourly posture rescan even when nothing changed, so
they cause duplicate re-sends; `currentStatusSince` only advances on a real
status transition. **Known limitation**: a finding whose score/risk/other
fields change without a status transition won't be re-sent under this
filter.

| 1.x field | 2.0 field | Change |
|---|---|---|
| `alert_id` | `id` | renamed; no longer double-base64-encoded |
| `title` | `name` | renamed |
| `alert_description` | `description` | renamed |
| `how_to_remediate` | `remediationInstructions` | renamed |
| `tags` | `securityDomains` | renamed |
| `creation_source` ("Sanity"/"Github"/"UI" strings) | `type` | renamed + revalued to enum (`POSTURE_ISSUE_TYPE_BUILTIN`/`_CUSTOM`/`_UNSPECIFIED`) |
| `compliance_frameworks_text` | `relatedComplianceFrameworks` | renamed |
| `compliance_framework_ids` | `relatedComplianceFrameworkIds` | renamed |
| `score` | `score` | unchanged |
| `risk_level_table` (as computed "maxScore") | `maxScore` | renamed |
| `score_percentage` | `scorePercentage` | renamed |
| `risk_level_table` (int 10/20/30/40) | `severity` | now enum string `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` |
| `status` (int 5/6/7/8/9/11/12/13) | `checkStatus` | now enum string (`ALERT_STATUS_TO_REVIEW`, etc.) |
| `policy_id` | `postureCheckId` | renamed |
| `instance_id` | `checkedInstance.id` | renamed + nested |
| `instance_name` | `checkedInstance.appName` | renamed + nested |
| `updated_at` | `updatedAt` | renamed only — still unsafe for incremental use |
| `last_scanned_time` | `lastScanned` | renamed |
| — | `url` | **new** — direct link to the check in the Reco UI |
| `comments` | `commentsCount` | renamed |
| `has_ticket` | `hasTicket` | unchanged |
| `status_override_filter` | `statusOverrideFilter` | renamed |
| `business_unit_names` | `businessUnits` | renamed |
| `rescan_status` | `rescanStatus` | renamed |
| `severity_source` | `severitySource` | renamed |
| `extraction_sources` | `extractionSources` | renamed |
| — | `currentStatusSince` | **new** — the 2.0 incremental filter target |
| `all_policy` (TA-injected, always `null` in 1.x) | — | removed (was dead weight) |
| `ticket_id`, `ticket_url`, `tickets`, `has_notifications`, `policy_status`, `alert_status_alt`, `checklist_status`, `label_ids`, `labels_json`, `related_policies`, `risk_accepted`, `status_override`, `pre_disable_notification_time`, `status_override_disable_time` | — | **dropped** — no External API equivalent yet |

## Alerts (`reco_alerts`)

Old: `ALERT_VIEW_WITH_SHARED_STATUS` (list) + `alert-inbox/{id}` (detail).
New: `GET /api/v1/external-api/alerts/list` (list) + `GET /api/v1/external-api/alert-details/{id}` (detail).

**Incremental filter changed**: `updated_at` (1.x) → `createdAt` (2.0), per
request — alerts are event-driven (one row per detected violation, not a
periodically-rescanned checklist), so `createdAt` is stable here; confirmed
structurally (DB-default set once at insert, no upsert path that resets it),
not yet independently measured live.

The 1.x list-stub fields were mostly discarded client-side (only `id` was
extracted before fetching detail), so the meaningful diff is on the detail
object actually sent to Splunk:

| 1.x field | 2.0 field | Change |
|---|---|---|
| `id` | `id` | unchanged |
| `aggregationRulesToKeys` (top-level; TA dropped it if present) | — | field no longer exists on `ThreatAlertDetail` at all (dropped server-side) |
| `policyViolations[].jsonData` (base64-encoded JSON string) | `policyViolations[].jsonData` (plain JSON string) | **base64 layer removed** — TA no longer base64-decodes; it now just `json.loads()`s directly |
| `policyViolations[].aggregationRuleToKey` (base64) | `policyViolations[].aggregationRuleToKey` (plain string) | base64 removed; TA continues to strip this field before sending, matching 1.x's intent of never surfacing it |
| `status`, `riskLevel`, `createdAt`, `updatedAt`, `instanceId`, `extractionSources` | same names | unchanged (this detail endpoint was already camelCase JSON in 1.x, not a table-cell response) |
| — | `riskType`, `alertType`, `triggeringViolationId`, `alertPostureScore` | present on the 2.0 detail shape; not independently confirmed whether 1.x's detail response already had these (that endpoint wasn't table-cell based, so it wasn't covered by this migration's table-API research) — verify empirically if these matter to you |

Structural note: `ListThreatAlerts` (the list endpoint) now returns enough
fields for most purposes without a per-alert detail fetch — the 2-call
pattern is no longer *required*, but it's kept in 2.0 to preserve the full
`policyViolations` detail 1.x always sent.

## Accounts (`reco_accounts`)

Old: raw `enriched_account_view` columns (95 columns) via `asset-management/query`.
New: `GET /api/v1/external-api/accounts/list` → `Account` (34 fields).
**Incremental filter added in 2.0**: `lastSeen` (1.x's checkpoint code here was
dead/unreachable, so 1.x always did a full re-pull). `lastSeen` is
`GREATEST(last_seen_time, last_activity_time, last_login_time)`, all sourced
from real vendor/event data with no periodic re-stamping found in the
enrichment pipeline -- verified safe the same way `currentStatusSince` was
verified for posture. `updatedAt`/`createdAt` are *not* safe here -- they are unconditionally
re-stamped by the periodic account-insight recompute, the same trap
posture's `updatedAt` was.

| 1.x column | 2.0 field |
|---|---|
| `account_id` | `id` |
| `full_name` | `name` |
| `instance_id` (+ separate app-name lookup) | `instance.id` / `instance.appName` (nested) |
| `primary_email_address` | `accountEmail` |
| `last_seen_time` | `lastSeen` |
| `has_mfa` | `hasMfa` |
| `roles` | `roles` |
| `user_type_display` | `permissions` |
| `alerts_count` | `openAlerts` |
| `last_extraction_time` | `lastExtractionTime` |
| `identity_departments` | `departmentName` |
| `business_unit_names` | `businessUnit` |
| `related_emails` | `relatedEmails` |
| `profiles` | `profiles` |
| `permission_sets` | `permissionSets` |
| `auth_type` | `authType` |
| `creation_time` | `createTime` |
| `identity_id` | `identityId` |
| `is_admin` | `isAdmin` |
| `is_former_user` | `isFormerUser` |
| `is_inactive` | `isInactive` |
| `is_risky_user` | `isRiskyUser` |
| `is_new` | `isNew` |
| `is_deactivated` | `isDeactivated` |
| `is_orphaned` | `isOrphaned` |
| `is_internal` | `isInternal` |
| `is_provisioned` | `isProvisioned` |
| `is_guest_insight` | `isGuest` |
| `analysis_account_type` | `analysisAccountType` |
| `label_ids` | `labelNames` (resolved to display names) |
| `analysis_account_location` | `analysisAccountLocation` |
| `domain_type` | `domainType` |
| `cannot_determine_permissions` | `cannotDeterminePermissions` |
| `has_reco_defined_labels` | `hasRecoDefinedLabels` |
| `has_user_added_soft_labels` | `hasUserAddedSoftLabels` |
| `has_user_removed_soft_labels` | `hasUserRemovedSoftLabels` |
| `last_login_time` | `lastLoginTime` |
| `last_activity_time` | `lastActivityTime` |
| `job_title` | `jobTitle` |

**Dropped (present in the 1.x raw view, no 2.0 field)**: `is_standard`,
`analysis`, `last_activity_time_by_event` (this was 1.x's *intended*
incremental field, but the checkpoint code that would've used it was dead),
`account_name`, `personal_emails`, `provisioned_app_ids`, every `orig_is_*`
shadow column, `is_never_logged_in`, `analysis_export`, `user_type`,
`has_mfa_insight`, `deactivation_time`, `last_api_message_id`,
`display_full_name`, `analysis_workforce`, `analysis_account_state`,
`analysis_account_status`, `last_extraction_details`,
`last_extraction_source`, `provisioning_explanation`, `photo_url`,
`is_service_account`, `login_type`, `location`, `workspace_id`,
`account_type`, `is_guest_display`, `has_identity`,
`identity_primary_email`, `identity_departments_str`, `admin_label_name`,
`admin_label_update_at`, `is_privileged`, `alerts_30_days`, `num_groups`,
`is_last_login_known`, `is_valid`, `is_federated_and_local`, `labels_json`,
`soft_labels_added`, `soft_labels_removed`, `business_unit_ids`,
`is_sso_verified`, `is_idp_managed`, `is_federated_manual`,
`is_sso_enforced`.

## App Discovery (`reco_discovery`)

Old: `app_discovery` (48 columns, deleted from the codebase in favor of v4 —
recovered from git history) via `asset-management/query`. New:
`GET /api/v1/external-api/apps/list` → `App`, backed by `app_discovery_v4`
(a newer generation of the same view; same join skeleton, several fields
only exist starting in v4).
**Incremental filter added in 2.0**: `lastSeen` (←`last_use_time`), a MAX()
aggregate of real login/authorization event timestamps -- verified safe
(not `now()`-stamped). **Known limitation**: `app_discovery_v4` is a
ClickHouse materialized view refreshed wholesale every 3 hours, so nothing
new will appear between refreshes regardless of poll interval or filter --
a freshness ceiling, not a duplicate-event risk.

| 1.x column | 2.0 field | Note |
|---|---|---|
| `generic_app_id` | `id` | |
| `application_name` | `name` | |
| `category` | `category` | **source column changed**: old view's `category`, new view's `category2` — same JSON name, different underlying column |
| `application_instances_ids` | `instances` | |
| `users_num` | `accounts` | |
| — | `usersCount` (←`current_enriched_identity_count`) | new column, v4-only |
| `first_use_time` | `firstSeen` | |
| `last_use_time` | `lastSeen` | |
| — | `lastAppActivity` (←`last_app_activity`) | new column, v4-only |
| `authorization_status` | `authorization` | |
| `auth_types` | `authType` | |
| `app_owner` | `appOwner` | |
| — | `analysis` | new column, v4-only |
| `type_usage` | `usage` | |
| `shadow_app` | `isShadowApp` | |
| `integrated` | `isIntegrated` | **source column changed**: old generic `integrated`, new `is_integrated` (v4-only) |
| `is_using_ai` | `isUsingAi` | |
| `security_score` | `vendorScore` | |
| `bk_grade_letter` | `vendorGrade` | |
| — | `discoveryMethod` (←`discovery_method`) | new column, v4-only |
| `description` | `description` | |
| — | `businessCriticality` (←`business_criticality`) | new column, v4-only |
| `system_authorization_status` | `systemAuthorizationStatus` | |
| — | `aiCapability` (←`ai_capability`) | new column, v4-only |
| — | `isShadowBusinessDualInsight` (filter-only, not in response) | new, v4-only |

**Dropped**: `application_instances_names`, `genric_app_id` (a duplicate/typo
column, not a real loss), `last_thirty_days_score`, `company_size`,
`security_score_url`, `last_refresh`, `label_ids`, `labels_json`, `logo`,
`web_link`, `app_groups`, `sso_not_enabled`, `overrode_usage`,
`app_created_at`, `found_in_msft_cas_network_traffic`,
`found_in_zscaler_network_traffic`, `found_in_google_network_traffic`,
`bk_cyber_rating`, `bk_breach_index`, `bk_ransomware_index`,
`bk_cyber_rating_last_updated_at`, `bk_breach_index_last_updated_at`,
`bk_ransomware_index_last_updated_at`, `instance_types`,
`application_instances`, `application_instances_str`, `unused_app`,
`vendor`.

## Identities (`reco_identities`)

Old: `enriched_identity_view` (27 columns) via `asset-management/query`. New:
`GET /api/v1/external-api/users/list` (note: URL path says "users"; the
response array key is also `users`, not `identities`) → `Identity` (16
fields).
**Incremental filter added in 2.0**: `lastSeen`
(`GREATEST(last_login_time, last_activity_time)`, aggregated from the
identity's mapped accounts' real vendor/event timestamps) -- verified safe.
`updatedAt`/`createdAt` are not safe here for the same reason as accounts.

| 1.x column | 2.0 field |
|---|---|
| `identity_id` | `id` |
| `full_name` | `name` |
| `primary_email_address` | `email` |
| `departments` | `departments` |
| `job_titles` | `jobTitles` |
| `private_emails` | `personalEmails` |
| `related_emails` | `relatedEmails` |
| `filtered_label_json` | `analysis` |
| `num_admin_instance_ids` | `adminAccounts` |
| `num_accounts` | `accounts` |
| `alerts_count` | `openAlerts` |
| `is_former` | `isFormer` |
| `has_access` | `hasAccess` |
| `last_seen_time` | `lastSeen` |
| `last_login_time` | `lastLogin` |
| `is_internal` | `isInternal` |

**Dropped**: `application_instances_ids`, `admin_instance_types`,
`profile_photo_url`, `is_admin`, `system_labels_removed`, `label_names`,
`soft_labels_removed`, `departments_str`, `labels_json`, `label_ids`.

## System / Audit Logs (`reco_system_logs`)

Old: `system_logs_view` (24 columns) via `asset-management/query`. New:
`GET /api/v1/external-api/audit-logs/list` → `AuditLog` (13 fields).
**Incremental filter unchanged**: `timestamp` in both versions — this was
already the one working 1.x incremental input.

| 1.x column | 2.0 field |
|---|---|
| `id` | `id` |
| `timestamp` | `timestamp` |
| `instance_id` | `instance.id` (nested) |
| `user_email` | `userEmail` |
| `user_roles` | `userRoles` |
| `user_type` | `userType` |
| `module` | `module` |
| `action` | `action` |
| `object_name` | `objectName` |
| `object_id` | `objectId` |
| `previous_value` | `previousValue` |
| `current_value` | `currentValue` |
| `remote_addr` | `remoteAddr` |

**Dropped**: `user_identity`, `user_name`, `object_type`, `object_email`,
`value_key`, `body`, `additional_info`, `user_identity_primary_email`,
`object_identity_primary_email`, `object_id_identity_primary_email`.

## Not addressed in this release (follow-up needed)

- Bundled dashboards (`reco__posture`, `reco__posture__details`,
  `reco__alerts`, `reco__alert__history`, `reco__accounts`,
  `reco__discovery`, `reco__users`) reference 1.x field names and will need
  their SPL updated to the 2.0 field names above before they render
  correctly.
- `status` (posture) / `alert_status` (alerts) input args remain
  unapplied — unchanged from 1.x, not part of this migration's scope.
