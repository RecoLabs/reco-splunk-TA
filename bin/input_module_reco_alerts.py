import json
from datetime import datetime

import reco_external_api as reco_api

RESOURCE_PATH = "alerts/list"
ITEMS_KEY = "alerts"
DETAIL_RESOURCE_PATH = "alert-details/{id}"
CREATED_AT_FIELD = "createdAt"


def validate_input(helper, definition):
    """Validate the input configurations."""
    pass


def collect_events(helper, ew):
    """Fetch alerts from Reco's External API and send them to Splunk."""
    max_fetch = helper.get_arg('limit')
    status = None  # helper.get_arg('alert_status') -- unused since 1.x, kept disabled
    last_run = helper.get_check_point("last_run") or {}
    tenant_url = "https://" + helper.get_global_setting("tenant_url")
    api_key = helper.get_global_setting("api_key")

    helper.log_info(f"Starting collection of alerts from Reco with max_fetch={max_fetch}, status={status}")

    after = reco_api.parse_checkpoint_time(last_run.get("lastRun"))
    if after:
        helper.log_info(f"Last run time: {after}")

    alerts = []
    try:
        alerts = fetch_reco_alerts(helper, tenant_url, api_key, max_fetch, status, after)
        helper.log_info(f"Fetched {len(alerts)} alerts.")
        send_events(alerts, helper, ew)
    except Exception as e:
        helper.log_error(f"Error fetching alerts: {e}")

    if alerts:
        helper.save_check_point("last_run", {"lastRun": reco_api.format_checkpoint_time(datetime.now())})
        helper.log_info("Checkpoint updated with last run time")


def fetch_reco_alerts(helper, tenant_url, api_key, max_fetch, status, after):
    """Retrieve alert stubs then fetch full detail (incl. policy violations) for each."""
    filters = build_filters(status, after)
    stubs = reco_api.fetch_all(helper, tenant_url, api_key, RESOURCE_PATH, ITEMS_KEY,
                                page_size=max_fetch, filters=filters,
                                sort_by=CREATED_AT_FIELD, sort_order="ascending")

    detailed_alerts = []
    helper.log_info("Fetching detailed information for each alert.")
    for stub in stubs:
        alert_id = stub.get("id")
        if not alert_id:
            helper.log_warning("Alert ID missing in response.")
            continue
        detail = get_single_alert(helper, tenant_url, api_key, alert_id)
        if detail:
            for violation in detail.get("policyViolations", []):
                process_violation(violation)
            detailed_alerts.append(detail)
            helper.log_info(f"Fetched detailed data for alert ID: {alert_id}")

    return detailed_alerts


def get_single_alert(helper, tenant_url, api_key, alert_id):
    """Fetch a single alert's detailed information from Reco's External API."""
    alert = reco_api.get_detail(helper, tenant_url, api_key, DETAIL_RESOURCE_PATH.format(id=alert_id), "alert")
    if not alert:
        helper.log_error(f"Failed to retrieve alert {alert_id}")
        return {}
    return alert


def process_violation(violation):
    """Parse jsonData (plain JSON string, no base64 -- unlike TA 1.x) and drop
    the internal aggregation-rule-to-key mapping, matching 1.x's behavior of
    never surfacing it."""
    violation.pop("aggregationRuleToKey", None)
    raw_json_data = violation.get("jsonData")
    if raw_json_data:
        violation_data = json.loads(raw_json_data)
        violation_data.pop("violation", None)
        violation["jsonData"] = violation_data


def build_filters(status, after):
    """Build the SCIM filter expression for the alerts/list request."""
    clauses = []
    if status:
        clauses.append(f'status eq "{status}"')
    if after:
        clauses.append(f'{CREATED_AT_FIELD} gt "{reco_api.format_checkpoint_time(after)}"')
    return " and ".join(clauses) if clauses else None


def send_events(entities, helper, ew):
    """Send parsed alerts as events to Splunk."""
    for entity in entities:
        event = helper.new_event(data=json.dumps(entity), source=helper.get_input_type(),
                                  sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")
