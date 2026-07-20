import json

import reco_external_api as reco_api

RESOURCE_PATH = "accounts/list"
ITEMS_KEY = "accounts"
DATA_SOURCE_LABEL = "enriched_account_view"  # preserved 1.x literal for backward-compatible searches
DEFAULT_PAGE_SIZE = 1000


def validate_input(helper, definition):
    """Validate the input configurations."""
    pass


def collect_events(helper, ew):
    """Fetch all accounts from Reco's External API and send to Splunk.

    No incremental filter is applied (unchanged from 1.x): the 1.x checkpoint
    machinery here was dead code (an unreachable `if after:` branch), so this
    was always a full re-pull every run. That external behavior is preserved.
    """
    page_size = int(helper.get_arg('limit') or DEFAULT_PAGE_SIZE)
    tenant_url = "https://" + helper.get_global_setting("tenant_url")
    api_key = helper.get_global_setting("api_key")

    helper.log_info(f"Starting collection of accounts with page_size={page_size}")

    all_accounts = []
    try:
        all_accounts = fetch_all_accounts(helper, tenant_url, api_key, page_size)
        helper.log_info(f"Total accounts fetched: {len(all_accounts)}")
        send_events(all_accounts, helper, ew)
    except Exception as e:
        helper.log_error(f"Error fetching accounts: {e}")


def fetch_all_accounts(helper, tenant_url, api_key, page_size):
    """Retrieve all accounts from Reco's External API with pagination."""
    def stamp_page_metadata(page_items, page_number, total_results):
        for account in page_items:
            account["total_accounts_count"] = total_results
            account["data_source"] = DATA_SOURCE_LABEL
            account["page_number"] = page_number

    accounts = reco_api.fetch_all(helper, tenant_url, api_key, RESOURCE_PATH, ITEMS_KEY,
                                   page_size=page_size, on_page=stamp_page_metadata)
    helper.log_info(f"Fetched {len(accounts)} accounts.")
    return accounts


def send_events(entities, helper, ew):
    """Send parsed accounts as events to Splunk."""
    for entity in entities:
        event = helper.new_event(data=json.dumps(entity), source=helper.get_input_type(),
                                  sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")
