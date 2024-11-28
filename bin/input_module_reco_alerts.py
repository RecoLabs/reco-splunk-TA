import json
import base64
from datetime import datetime

# Required configurations for Reco API
RECO_API_TIMEOUT_IN_SECONDS = 30
RECO_ACTIVE_ALERTS_VIEW = "ALERT_VIEW_WITH_SHARED_STATUS"
UPDATED_AT_FIELD = "updated_at"
FILTER_RELATIONSHIP_AND = "AND"
OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

def validate_input(helper, definition):
    """Validate the input configurations."""
    pass

def collect_events(helper, ew):
    """Fetch incidents and alerts from Reco API and send them to Splunk."""
    max_fetch = helper.get_arg('limit')
    status = None #helper.get_arg('alert_status')
    source = helper.get_arg('source')  # Retrieve 'source' if specified
    last_run = helper.get_check_point("last_run") or {}
    tenant_url = helper.get_global_setting("tenant_url")
    api_key = helper.get_global_setting("api_key")

    helper.log_info(f"Starting collection of events from Reco with max_fetch={max_fetch}, status={status}, source={source}")

    # Convert last_run time to a datetime object if present
    after = datetime.strptime(last_run.get("lastRun", ""), OCCURRED_FORMAT) if "lastRun" in last_run else None
    if after:
        helper.log_info(f"Last run time: {after}")

    alerts = []

    # Fetch alerts
    try:
        alerts = fetch_reco_alerts(helper, tenant_url, api_key, max_fetch, status, source, after)
        helper.log_info(f"Fetched {len(alerts)} alerts.")
        send_events(alerts, helper, ew)
    except Exception as e:
        helper.log_error(f"Error fetching alerts: {e}")

    # Save the last fetched time to checkpoint
    if alerts:
        helper.save_check_point("last_run", {"lastRun": datetime.now().strftime(OCCURRED_FORMAT)})
        helper.log_info("Checkpoint updated with last run time")

def fetch_reco_alerts(helper, tenant_url, api_key, max_fetch, status, source, after):
    """Retrieve alerts from Reco API and get additional details for each alert."""
    headers = {"Authorization": f"Bearer {api_key}"}
    params = create_params(RECO_ACTIVE_ALERTS_VIEW, max_fetch, status, source, after)

    helper.log_info("Sending request to Reco API for alert IDs.")
    response = helper.send_http_request(
        url=f"{tenant_url}/api/v1/policy-subsystem/alert-inbox/table",
        method="PUT",
        payload=json.dumps(params),
        headers=headers,
        timeout=RECO_API_TIMEOUT_IN_SECONDS,
    )

    alerts = parse_response(response)
    detailed_alerts = []

    # Fetch additional details for each alert
    helper.log_info("Fetching detailed information for each alert.")
    for alert in alerts:
        alert_id = base64.b64decode(alert.get("id")).decode("utf-8")
        if alert_id:
            single_alert = get_single_alert(helper, tenant_url, api_key, alert_id)
            if "aggregationRulesToKeys" in single_alert:
                single_alert.pop("aggregationRulesToKeys")
            for violation in single_alert.get("policyViolations", []):
                violation_data = json.loads(base64.b64decode(violation["jsonData"]))
                if "violation" in violation_data:
                    violation_data.pop("violation")
                violation["jsonData"] = violation_data
            detailed_alerts.append(single_alert)
            helper.log_info(f"Fetched detailed data for alert ID: {alert_id}")
        else:
            helper.log_warning("Alert ID missing in response.")

    return detailed_alerts

def get_single_alert(helper, tenant_url, api_key, alert_id):
    """Fetch a single alert's detailed information from Reco API."""
    headers = {"Authorization": f"Bearer {api_key}"}
    response = helper.send_http_request(
        url=f"{tenant_url}/api/v1/policy-subsystem/alert-inbox/{alert_id}",
        method="GET",
        headers=headers,
        timeout=RECO_API_TIMEOUT_IN_SECONDS,
    )

    if response.status_code != 200:
        helper.log_error(f"Failed to retrieve alert {alert_id}, status code: {response.status_code}")
        return {}

    return response.json().get("alert", {})

def create_params(view_name, max_fetch, status, source, after):
    """Create request parameters for Reco API."""
    filters = {"relationship": FILTER_RELATIONSHIP_AND, "filters": {"filters": []}}
    if status:
        filters["filters"]["filters"].append({"field": "status", "stringEquals": {"value": status}})
    if source:
        filters["filters"]["filters"].append({"field": "data_source", "stringEquals": {"value": source}})
    if after:
        filters["filters"]["filters"].append(
            {"field": UPDATED_AT_FIELD, "after": {"value": after.strftime(OCCURRED_FORMAT)}}
        )

    return {
        "getTableRequest": {
            "tableName": view_name,
            "pageSize": max_fetch,
            "fieldFilters": filters,
            "fieldSorts": {
                "sorts": [{"sortBy": "updated_at", "sortDirection": "SORT_DIRECTION_ASC"}]
            }
        }
    }

def parse_response(response):
    """Parse Reco API response."""
    if response.status_code != 200:
        raise ValueError(f"Failed to retrieve data, status code: {response.status_code}")
    response_data = response.json().get("getTableResponse", {}).get("data", {}).get("rows", [])
    return [parse_table_row_to_dict(row.get("cells", [])) for row in response_data]

def parse_table_row_to_dict(alert):
    """Parse a row of alert data into a dictionary format."""
    alert_as_dict = {}
    for obj in alert:
        key = obj.get("key")
        value = obj.get("value")
        if key and value:
            alert_as_dict[key] = base64.b64decode(value).decode("utf-8").replace('"', "")
    return alert_as_dict

def send_events(entities, helper, ew):
    """Send parsed incidents or alerts as events to Splunk."""
    for entity in entities:
        event = helper.new_event(data=json.dumps(entity), source=helper.get_input_type(), sourcetype=helper.get_sourcetype(), index=helper.get_output_index())
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")
