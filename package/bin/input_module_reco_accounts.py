import json
from datetime import datetime

import reco_external_api as reco_api

RESOURCE_PATH = "accounts/list"
ITEMS_KEY = "accounts"
DATA_SOURCE_LABEL = "enriched_account_view"  # preserved 1.x literal for backward-compatible searches
# lastSeen = GREATEST(last_seen_time, last_activity_time, last_login_time),
# all sourced from real vendor/event data (no periodic now()-stamping found
# in the enrichment pipeline) -- safe for incremental filtering, unlike
# updated_at/created_at which ARE unconditionally re-stamped on the
# recurring enrichment recompute (same trap posture's updated_at was).
LAST_SEEN_FIELD = "lastSeen"


def validate_input(helper, definition):
    """Validate the input configurations."""
    pass


def collect_events(helper, ew):
    """Fetch accounts from Reco's External API and send to Splunk."""
    helper.log_info("=== Starting reco_accounts collection job ===")
    # 0/unset means "no limit" -- fetch_all() resolves that to the largest
    # page size, since it already paginates through everything regardless.
    page_size = helper.get_arg('limit')
    last_run = helper.get_check_point("reco_accounts_last_run") or {}

    tenant_url, api_key = reco_api.get_tenant_config(helper)
    if not tenant_url:
        return

    after = reco_api.parse_checkpoint_time(last_run.get("lastRun"))
    reco_api.log_checkpoint_state(helper, after, LAST_SEEN_FIELD)

    all_accounts = []
    succeeded = False
    try:
        all_accounts = fetch_all_accounts(helper, tenant_url, api_key, page_size, after)
        helper.log_info(f"Total accounts fetched: {len(all_accounts)}")
        send_events(all_accounts, helper, ew)
        succeeded = True
    except Exception as e:
        reco_api.log_exception(helper, "Error fetching accounts", e)

    if succeeded:
        reco_api.save_checkpoint(helper, "reco_accounts_last_run", datetime.now())
    else:
        helper.log_info("Error fetching accounts this run -- checkpoint left unchanged")
    helper.log_info("=== Finished reco_accounts collection job ===")


def fetch_all_accounts(helper, tenant_url, api_key, page_size, after):
    """Retrieve accounts from Reco's External API with pagination."""
    def stamp_page_metadata(page_items, page_number, total_results):
        for account in page_items:
            account["total_accounts_count"] = total_results
            account["data_source"] = DATA_SOURCE_LABEL
            account["page_number"] = page_number

    filters = build_filters(after)
    accounts = reco_api.fetch_all(helper, tenant_url, api_key, RESOURCE_PATH, ITEMS_KEY,
                                   page_size=page_size, filters=filters,
                                   sort_by=LAST_SEEN_FIELD, sort_order="ascending",
                                   on_page=stamp_page_metadata)
    helper.log_info(f"Fetched {len(accounts)} accounts.")
    return accounts


def build_filters(after):
    """Build the SCIM filter expression for the accounts/list request."""
    if after:
        return f'{LAST_SEEN_FIELD} gt "{reco_api.format_checkpoint_time(after)}"'
    return None


def send_events(entities, helper, ew):
    """Send parsed accounts as events to Splunk."""
    for entity in entities:
        event = helper.new_event(data=json.dumps(entity), source=helper.get_input_type(),
                                  sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")
