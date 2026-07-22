"""Shared client for Reco's External API (v2 TA).

Replaces the old internal `policy-subsystem/alert-inbox/table` and
`asset-management/query`+`/count` table APIs used by TA 1.x. Auth is
unchanged (Bearer API key); the wire format is a plain paginated JSON
GET instead of a base64-cell table response, and pagination is a single
`totalResults`/`itemsPerPage` envelope instead of a separate /count call.
"""
import datetime

EXTERNAL_API_BASE = "/api/v1/external-api"
OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_PAGE_SIZE = 10000
# Keep in lockstep with the version in app.manifest / default/app.conf /
# globalConfig.json / TA-reco.aob_meta -- there is no single source of truth
# for the TA version, so this must be bumped by hand alongside those.
TA_VERSION = "2.0.0"


def build_headers(api_key):
    return {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": f"splunk-ta/{TA_VERSION}",
    }


def fetch_all(helper, tenant_url, api_key, resource_path, items_key, page_size=1000,
              filters=None, sort_by=None, sort_order=None, timeout=30, on_page=None):
    """Page through a Reco External API list endpoint and return all items.

    `resource_path` is the path segment after EXTERNAL_API_BASE, e.g. "posture-issues/list".
    `items_key` is the JSON key holding the item array in the response envelope
    (e.g. "issues", "alerts", "accounts", "apps", "users", "auditLogs").
    `on_page(page_items, page_number, total_results)`, if given, is called once
    per page (0-indexed) before its items are added to the result, so callers
    can stamp per-row page metadata the way TA 1.x did for accounts/discovery/
    identities/system_logs.
    """
    # Splunk modular-input args (helper.get_arg) always come back as strings,
    # even for numeric fields, so page_size must be coerced before comparing.
    page_size = min(int(page_size) if page_size else 1000, MAX_PAGE_SIZE)
    headers = build_headers(api_key)
    url = f"{tenant_url}{EXTERNAL_API_BASE}/{resource_path}"

    items = []
    start_index = 1
    page_number = 0
    while True:
        params = {"startIndex": start_index, "count": page_size}
        if filters:
            params["filters"] = filters
        if sort_by:
            params["sortBy"] = sort_by
        if sort_order:
            params["sortOrder"] = sort_order

        response = helper.send_http_request(url=url, method="GET", parameters=params,
                                              headers=headers, timeout=timeout)
        if response.status_code != 200:
            raise ValueError(f"Failed to retrieve {resource_path}, status code: {response.status_code}, "
                              f"body: {response.text}")

        body = response.json()
        page_items = body.get(items_key) or []
        # int64 proto fields (totalResults, itemsPerPage) are serialized as
        # JSON strings (e.g. "3"), not numbers -- protobuf's canonical JSON
        # mapping avoids precision loss for 64-bit values. Coerce to int
        # before comparing, or `items_per_page < page_size` throws
        # "'<' not supported between instances of 'str' and 'int'".
        total_results = int(body.get("totalResults", len(items) + len(page_items)))
        if on_page:
            on_page(page_items, page_number, total_results)
        items.extend(page_items)

        items_per_page = int(body.get("itemsPerPage", len(page_items)))
        if not page_items or items_per_page < page_size or len(items) >= total_results:
            break
        start_index += page_size
        page_number += 1

    return items


def get_detail(helper, tenant_url, api_key, resource_path, item_key, timeout=30):
    """Fetch a single-item detail endpoint, e.g. alert-details/{id}."""
    headers = build_headers(api_key)
    url = f"{tenant_url}{EXTERNAL_API_BASE}/{resource_path}"
    response = helper.send_http_request(url=url, method="GET", headers=headers, timeout=timeout)
    if response.status_code != 200:
        return None
    return response.json().get(item_key, {})


def format_checkpoint_time(dt):
    return dt.strftime(OCCURRED_FORMAT)


def parse_checkpoint_time(value):
    return datetime.datetime.strptime(value, OCCURRED_FORMAT) if value else None
