import json

import reco_external_api as reco_api

RESOURCE_PATH = "users/list"
ITEMS_KEY = "users"  # the ListIdentities response envelope calls its array "users", not "identities"
DATA_SOURCE_LABEL = "enriched_identity_view"  # preserved 1.x literal for backward-compatible searches
# lastSeen = GREATEST(last_login_time, last_activity_time), both sourced
# from the identity's mapped accounts' real vendor/event timestamps -- safe
# for incremental filtering (verified: not touched by the periodic identity
# recompute regardless of real change, unlike updated_at/created_at).
LAST_SEEN_FIELD = "lastSeen"


def validate_input(helper, definition):
    """Validate the input configurations."""
    pass


def collect_events(helper, ew):
    """Fetch identities from Reco's External API and send to Splunk."""
    helper.log_info("=== Starting reco_identities collection job ===")
    # 0/unset means "no limit" -- fetch_all() resolves that to the largest
    # page size, since it already paginates through everything regardless.
    page_size = helper.get_arg('limit')
    last_run = helper.get_check_point("reco_identities_last_run") or {}

    tenant_url, api_key = reco_api.get_tenant_config(helper)
    if not tenant_url:
        return

    after = reco_api.parse_checkpoint_time_or_now(helper, last_run.get("lastRun"))
    reco_api.log_checkpoint_state(helper, after, LAST_SEEN_FIELD)

    all_identities = []
    latest_seen = None
    succeeded = False
    try:
        all_identities = fetch_all_identities(helper, tenant_url, api_key, page_size, after)
        helper.log_info(f"Total identities fetched: {len(all_identities)}")
        send_events(all_identities, helper, ew)
        succeeded = True
        latest_seen = reco_api.max_field_datetime(helper, all_identities, LAST_SEEN_FIELD)
    except Exception as e:
        reco_api.log_exception(helper, "Error fetching identities", e)

    if succeeded and latest_seen:
        reco_api.save_checkpoint(helper, "reco_identities_last_run", latest_seen)
    elif succeeded:
        helper.log_info("No identities fetched this run -- checkpoint left unchanged")
    else:
        helper.log_info("Error fetching identities this run -- checkpoint left unchanged")
    helper.log_info("=== Finished reco_identities collection job ===")


def fetch_all_identities(helper, tenant_url, api_key, page_size, after):
    """Retrieve identities from Reco's External API with pagination."""
    def stamp_page_metadata(page_items, page_number, total_results):
        for identity in page_items:
            identity["total_identities_count"] = total_results
            identity["data_source"] = DATA_SOURCE_LABEL
            identity["page_number"] = page_number

    filters = build_filters(after)
    identities = reco_api.fetch_all(helper, tenant_url, api_key, RESOURCE_PATH, ITEMS_KEY,
                                     page_size=page_size, filters=filters,
                                     sort_by=LAST_SEEN_FIELD, sort_order="ascending",
                                     on_page=stamp_page_metadata)
    helper.log_info(f"Fetched {len(identities)} identities.")
    return identities


def build_filters(after):
    """Build the SCIM filter expression for the users/list request."""
    if after:
        return f'{LAST_SEEN_FIELD} gt "{reco_api.format_checkpoint_time(after)}"'
    return None


def send_events(entities, helper, ew):
    """Send parsed identities as events to Splunk."""
    for entity in entities:
        event = helper.new_event(data=json.dumps(entity), source=helper.get_input_type(),
                                  sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")
