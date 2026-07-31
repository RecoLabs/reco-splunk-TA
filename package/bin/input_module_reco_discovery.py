import json
from datetime import datetime

import reco_external_api as reco_api

RESOURCE_PATH = "apps/list"
ITEMS_KEY = "apps"
DATA_SOURCE_LABEL = "app_discovery"  # preserved 1.x literal for backward-compatible searches
# lastSeen (last_use_time) is a MAX() aggregate of real login/authorization
# event timestamps -- safe for incremental filtering. Note: app_discovery_v4
# is a ClickHouse materialized view refreshed wholesale every 3h, so nothing
# new will appear between refreshes regardless of poll interval -- that's a
# freshness ceiling, not a duplicate-event risk like posture's rescan was.
LAST_SEEN_FIELD = "lastSeen"


def validate_input(helper, definition):
    """Validate the input configurations."""
    pass


def collect_events(helper, ew):
    """Fetch discovered apps from Reco's External API and send to Splunk."""
    helper.log_info("=== Starting reco_discovery collection job ===")
    # 0/unset means "no limit" -- fetch_all() resolves that to the largest
    # page size, since it already paginates through everything regardless.
    page_size = helper.get_arg('limit')
    last_run = helper.get_check_point("reco_discovery_last_run") or {}

    tenant_url, api_key = reco_api.get_tenant_config(helper)
    if not tenant_url:
        return

    after = reco_api.parse_checkpoint_time(last_run.get("lastRun"))
    reco_api.log_checkpoint_state(helper, after, LAST_SEEN_FIELD)

    all_apps = []
    try:
        all_apps = fetch_all_apps(helper, tenant_url, api_key, page_size, after)
        helper.log_info(f"Total apps fetched: {len(all_apps)}")
        send_events(all_apps, helper, ew)
    except Exception as e:
        reco_api.log_exception(helper, "Error fetching app discovery data", e)

    reco_api.save_checkpoint(helper, "reco_discovery_last_run", datetime.now())
    helper.log_info("=== Finished reco_discovery collection job ===")


def fetch_all_apps(helper, tenant_url, api_key, page_size, after):
    """Retrieve discovered apps from Reco's External API with pagination."""
    def stamp_page_metadata(page_items, page_number, total_results):
        for app in page_items:
            app["total_apps_count"] = total_results
            app["data_source"] = DATA_SOURCE_LABEL
            app["page_number"] = page_number

    filters = build_filters(after)
    apps = reco_api.fetch_all(helper, tenant_url, api_key, RESOURCE_PATH, ITEMS_KEY,
                               page_size=page_size, filters=filters,
                               sort_by=LAST_SEEN_FIELD, sort_order="ascending",
                               on_page=stamp_page_metadata)
    helper.log_info(f"Fetched {len(apps)} apps.")
    return apps


def build_filters(after):
    """Build the SCIM filter expression for the apps/list request."""
    if after:
        return f'{LAST_SEEN_FIELD} gt "{reco_api.format_checkpoint_time(after)}"'
    return None


def send_events(entities, helper, ew):
    """Send parsed apps as events to Splunk."""
    for entity in entities:
        event = helper.new_event(data=json.dumps(entity), source=helper.get_input_type(),
                                  sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")
