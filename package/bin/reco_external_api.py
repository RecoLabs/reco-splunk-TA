"""Shared client for Reco's External API (v2 TA).

Replaces the old internal `policy-subsystem/alert-inbox/table` and
`asset-management/query`+`/count` table APIs used by TA 1.x. Auth is
unchanged (Bearer API key); the wire format is a plain paginated JSON
GET instead of a base64-cell table response, and pagination is a single
`totalResults`/`itemsPerPage` envelope instead of a separate /count call.
"""
import datetime
import traceback

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


def get_tenant_config(helper):
    """Read and validate the add-on's global tenant_url/api_key settings.

    Returns (tenant_url, api_key) with the scheme prepended, or (None, None)
    if either is missing -- in which case a specific, actionable error has
    already been logged, so callers should just return early.
    """
    raw_tenant_url = helper.get_global_setting("tenant_url")
    api_key = helper.get_global_setting("api_key")
    if not raw_tenant_url:
        helper.log_error(
            "Reco tenant URL is not configured. Set it on the add-on's "
            "Configuration page (enter just the hostname, e.g. "
            "'your-tenant.us.reco.ai' -- no 'https://' prefix, no trailing slash)."
        )
        return None, None
    if not api_key:
        helper.log_error(
            "Reco API key is not configured. Set it on the add-on's Configuration page."
        )
        return None, None
    return "https://" + raw_tenant_url, api_key


def classify_http_error(status_code):
    """Return a short, actionable hint for a non-200 HTTP status."""
    if status_code in (401, 403):
        return "check that the configured API key is valid and has permission for this resource"
    if status_code == 404:
        return "resource not found -- check the configured tenant URL is correct"
    if status_code == 429:
        return "rate limited by the Reco API -- this should resolve on the next poll cycle"
    if status_code >= 500:
        return "Reco API server error -- may be transient, check again on the next poll cycle"
    return "unexpected HTTP status from the Reco API"


def log_exception(helper, context_msg, exc):
    """Log an exception with its full traceback, not just str(exc).

    helper.log_error only accepts a plain string (no exc_info kwarg), so the
    traceback has to be formatted into the message directly or it's lost --
    leaving only a bare message like "'<' not supported between instances of
    'str' and 'int'" with no indication of where it happened.
    """
    helper.log_error(f"{context_msg}: {exc}\n{traceback.format_exc()}")


def fetch_all(helper, tenant_url, api_key, resource_path, items_key, page_size=0,
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
    # `limit`'s new default is 0/unset, meaning "no limit" -- since this
    # already pages through every result regardless of page_size, "no limit"
    # just means using the largest page size (fewest HTTP round trips).
    page_size = int(page_size) if page_size else 0
    page_size = min(page_size, MAX_PAGE_SIZE) if page_size > 0 else MAX_PAGE_SIZE
    headers = build_headers(api_key)
    url = f"{tenant_url}{EXTERNAL_API_BASE}/{resource_path}"

    helper.log_info(
        f"Requesting {resource_path}: filters={filters or '(none -- full pull)'}, "
        f"sort_by={sort_by or '(none)'}, sort_order={sort_order or '(none)'}, page_size={page_size}"
    )

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
            hint = classify_http_error(response.status_code)
            helper.log_error(
                f"Request to {resource_path} failed: status={response.status_code}, "
                f"hint: {hint}, body={response.text}"
            )
            raise ValueError(f"Failed to retrieve {resource_path}, status code: {response.status_code}")

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
        helper.log_info(
            f"{resource_path}: page {page_number} fetched {len(page_items)} items "
            f"(cumulative {len(items)}/{total_results})"
        )
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
        hint = classify_http_error(response.status_code)
        helper.log_error(
            f"Request to {resource_path} failed: status={response.status_code}, "
            f"hint: {hint}, body={response.text}"
        )
        return None
    return response.json().get(item_key, {})


def format_checkpoint_time(dt):
    return dt.strftime(OCCURRED_FORMAT)


def parse_checkpoint_time(value):
    return datetime.datetime.strptime(value, OCCURRED_FORMAT) if value else None


def log_checkpoint_state(helper, after, field_name):
    """Log whether this run is resuming from a checkpoint or doing a full pull."""
    if after:
        helper.log_info(f"Resuming from checkpoint: {field_name} > {format_checkpoint_time(after)}")
    else:
        helper.log_info(f"No checkpoint found -- performing a full pull on {field_name}")


def save_checkpoint(helper, checkpoint_name, now):
    """Save the checkpoint and log the new value."""
    new_value = format_checkpoint_time(now)
    helper.save_check_point(checkpoint_name, {"lastRun": new_value})
    helper.log_info(f"Checkpoint '{checkpoint_name}' updated to {new_value}")
