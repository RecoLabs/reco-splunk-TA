import json
from datetime import datetime

import reco_external_api as reco_api

RESOURCE_PATH = "posture-issues/list"
ITEMS_KEY = "issues"
# current_status_since is the only posture-issue timestamp that's genuinely
# change-conditioned: created_at/updated_at get re-stamped by the backend's
# hourly full-table rescan even when nothing about the finding changed, so
# filtering on them causes duplicate re-sends. current_status_since only
# advances on a real status transition. Known limitation: a finding whose
# score/risk/other fields change without a status transition will not be
# re-sent under this filter.
STATUS_SINCE_FIELD = "currentStatusSince"


def validate_input(helper, definition):
    """Validate the input configurations."""
    pass


def collect_events(helper, ew):
    """Fetch posture issues from Reco's External API and send them to Splunk."""
    helper.log_info("=== Starting reco_posture collection job ===")
    max_fetch = helper.get_arg('limit')
    status = None  # helper.get_arg('status') -- unused since 1.x, kept disabled
    last_run = helper.get_check_point("last_run1") or {}

    tenant_url, api_key = reco_api.get_tenant_config(helper)
    if not tenant_url:
        return

    after = reco_api.parse_checkpoint_time(last_run.get("lastRun"))
    reco_api.log_checkpoint_state(helper, after, STATUS_SINCE_FIELD)

    issues = []
    succeeded = False
    try:
        issues = fetch_posture_issues(helper, tenant_url, api_key, max_fetch, status, after)
        helper.log_info(f"Fetched {len(issues)} posture issues.")
        send_events(issues, helper, ew)
        succeeded = True
    except Exception as e:
        reco_api.log_exception(helper, "Error fetching posture issues", e)

    if succeeded:
        reco_api.save_checkpoint(helper, "last_run1", datetime.now())
    else:
        helper.log_info("Error fetching posture issues this run -- checkpoint left unchanged")
    helper.log_info("=== Finished reco_posture collection job ===")


def fetch_posture_issues(helper, tenant_url, api_key, max_fetch, status, after):
    """Retrieve posture issues from Reco's External API."""
    filters = build_filters(status, after)
    return reco_api.fetch_all(helper, tenant_url, api_key, RESOURCE_PATH, ITEMS_KEY,
                               page_size=max_fetch, filters=filters,
                               sort_by=STATUS_SINCE_FIELD, sort_order="ascending")


def build_filters(status, after):
    """Build the SCIM filter expression for the posture-issues/list request."""
    clauses = []
    if status:
        clauses.append(f'checkStatus eq "{status}"')
    if after:
        clauses.append(f'{STATUS_SINCE_FIELD} gt "{reco_api.format_checkpoint_time(after)}"')
    return " and ".join(clauses) if clauses else None


def send_events(issues, helper, ew):
    """Send posture issues as events to Splunk."""
    for issue in issues:
        event = helper.new_event(data=json.dumps(issue), source=helper.get_input_type(),
                                  sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(issues)} events to Splunk.")
