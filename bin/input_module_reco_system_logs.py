import json
from datetime import datetime

import reco_external_api as reco_api

RESOURCE_PATH = "audit-logs/list"
ITEMS_KEY = "auditLogs"
TIMESTAMP_FIELD = "timestamp"
DATA_SOURCE_LABEL = "system_logs_view"  # preserved 1.x literal for backward-compatible searches
DEFAULT_PAGE_SIZE = 1000


def validate_input(helper, definition):
    """Validate the input configurations."""
    pass


def collect_events(helper, ew):
    """Fetch system/audit logs from Reco's External API and send to Splunk."""
    page_size = int(helper.get_arg('limit') or DEFAULT_PAGE_SIZE)
    last_run = helper.get_check_point("reco_system_logs_last_run") or {}
    tenant_url = "https://" + helper.get_global_setting("tenant_url")
    api_key = helper.get_global_setting("api_key")

    helper.log_info(f"Starting collection of system logs events with page_size={page_size}")

    after = reco_api.parse_checkpoint_time(last_run.get("lastRun"))
    if after:
        helper.log_info(f"Last run time: {after}")

    all_logs = []
    try:
        all_logs = fetch_all_system_logs(helper, tenant_url, api_key, page_size, after)
        helper.log_info(f"Total system logs fetched: {len(all_logs)}")
        send_events(all_logs, helper, ew)
    except Exception as e:
        helper.log_error(f"Error fetching system logs data: {e}")

    if all_logs:
        helper.save_check_point("reco_system_logs_last_run", {"lastRun": reco_api.format_checkpoint_time(datetime.now())})
        helper.log_info("Checkpoint updated with last run time")


def fetch_all_system_logs(helper, tenant_url, api_key, page_size, after):
    """Retrieve all system logs from Reco's External API with pagination."""
    def stamp_page_metadata(page_items, page_number, total_results):
        for log in page_items:
            log["total_apps_count"] = total_results  # kept literal for output parity with 1.x (originally a copy-paste field name)
            log["data_source"] = DATA_SOURCE_LABEL
            log["page_number"] = page_number

    filters = build_filters(after)
    logs = reco_api.fetch_all(helper, tenant_url, api_key, RESOURCE_PATH, ITEMS_KEY,
                               page_size=page_size, filters=filters,
                               sort_by=TIMESTAMP_FIELD, sort_order="ascending",
                               on_page=stamp_page_metadata)
    helper.log_info(f"Fetched {len(logs)} system logs.")
    return logs


def build_filters(after):
    """Build the SCIM filter expression for the audit-logs/list request."""
    if after:
        return f'{TIMESTAMP_FIELD} gt "{reco_api.format_checkpoint_time(after)}"'
    return None


def send_events(entities, helper, ew):
    """Send parsed system logs as events to Splunk."""
    for entity in entities:
        event = helper.new_event(data=json.dumps(entity), source=helper.get_input_type(),
                                  sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")
