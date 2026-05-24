import json
import base64
from datetime import datetime
import sys

# Required configurations for Reco API
RECO_API_TIMEOUT_IN_SECONDS = 30
UPDATED_AT_FIELD = "timestamp"
FILTER_RELATIONSHIP_AND = "AND"
OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_PAGE_SIZE = 1000

def validate_input(helper, definition):
    """Validate the input configurations."""
    pass

def collect_events(helper, ew):
    """Fetch system logs data from Reco API and send to Splunk."""
    page_size = helper.get_arg('limit') or DEFAULT_PAGE_SIZE
    page_size = int(page_size)    
    source = helper.get_arg('source')
    last_run = helper.get_check_point("reco_system_logs_last_run") or {}
    tenant_url = helper.get_global_setting("tenant_url")
    tenant_url = "https://"+tenant_url
    api_key = helper.get_global_setting("api_key")

    helper.log_info(f"Starting collection of system logs events with page_size={page_size}")

    # Convert last_run time to a datetime object if present
    after = datetime.strptime(last_run.get("lastRun", ""), OCCURRED_FORMAT) if "lastRun" in last_run else None
    if after:
        helper.log_info(f"Last run time: {after}")

    all_apps = []

    # Fetch all system logs data with pagination
    try:
        all_apps = fetch_all_system_logs(helper, tenant_url, api_key, page_size, after)
        helper.log_info(f"Total system logs fetched: {len(all_apps)}")
        send_events(all_apps, helper, ew)
    except Exception as e:
        helper.log_error(f"Error fetching system logs data: {e}")

    # Save the last fetched time to checkpoint
    if all_apps:
        helper.save_check_point("reco_system_logs_last_run", {"lastRun": datetime.now().strftime(OCCURRED_FORMAT)})
        helper.log_info("Checkpoint updated with last run time")

def fetch_all_system_logs(helper, tenant_url, api_key, page_size, after):
    """Retrieve all system logs data from Reco API with pagination."""
    headers = {"Authorization": f"Bearer {api_key}"}
    all_apps = []
    page_number = 0
    
    # First, get the total count
    count_params = create_system_logs_params(page_size, page_number, after)
    
    helper.log_info("Getting total count of system logs from Reco API.")
    count_response = helper.send_http_request(
        url=f"{tenant_url}/api/v1/asset-management/count",
        method="PUT",
        payload=json.dumps(count_params),
        headers=headers,
        timeout=RECO_API_TIMEOUT_IN_SECONDS,
    )
    
    total_count = 0
    if count_response.status_code == 200:
        total_count = count_response.json().get("getTableResponse", {}).get("totalNumberOfResults", 0)
        helper.log_info(f"Total number of system logs: {total_count}")
    else:
        raise ValueError(f"Failed to get count, status code: {count_response.status_code}")
    
    # Calculate total pages needed
    total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 0
    
    # Fetch all pages
    for page_number in range(total_pages):
        helper.log_info(f"Fetching page {page_number + 1} of {total_pages}")
        
        params = create_system_logs_params(page_size, page_number, after)
        
        response = helper.send_http_request(
            url=f"{tenant_url}/api/v1/asset-management/query",
            method="PUT",
            payload=json.dumps(params),
            headers=headers,
            timeout=RECO_API_TIMEOUT_IN_SECONDS,
        )

        apps = parse_response(response)
        
        # Enrich each system log with metadata
        for app in apps:
            app["total_apps_count"] = total_count
            app["data_source"] = "system_logs_view"
            app["page_number"] = page_number
            all_apps.append(app)
        
        helper.log_info(f"Fetched {len(apps)} system logs from page {page_number + 1}")
    
    return all_apps

def create_system_logs_params(page_size, page_number, after):
    """Create request parameters for system_logs."""
    params = {
        "getTableRequest": {
            "tableName": "system_logs_view",
            "pageSize": page_size,
            "pageNumber": page_number,
            "fieldSorts": {}
        }
    }
    
    # Add time filter if we have a last run time
    if after:
        params["getTableRequest"]["fieldFilters"] = {
            "relationship": FILTER_RELATIONSHIP_AND,
            "filters": {
                "filters": [
                    {
                        "field": UPDATED_AT_FIELD,
                        "after": {"value": after.strftime(OCCURRED_FORMAT)}
                    }
                ]
            }
        }
    
    return params

def parse_response(response):
    """Parse Reco API response."""
    if response.status_code != 200:
        raise ValueError(f"Failed to retrieve data, status code: {response.status_code}")
    
    response_data = response.json().get("getTableResponse", {}).get("data", {}).get("rows", [])
    return [parse_table_row_to_dict(row.get("cells", [])) for row in response_data]

def parse_table_row_to_dict(cells):
    """Parse a row of data into a dictionary with automatic type detection."""
    row_dict = {}
    for obj in cells:
        key = obj.get("key")
        value = obj.get("value")
        if key and value:
            try:
                # Decode base64 value
                decoded_value = base64.b64decode(value).decode("utf-8")
                
                # Parse the value with automatic type detection
                row_dict[key] = parse_json_value(decoded_value)
                    
            except Exception as e:
                # If base64 decode fails, try to parse the raw value
                row_dict[key] = parse_json_value(value)
    
    return row_dict

def parse_json_value(value):
    """Parse a JSON value with automatic type detection."""
    if not isinstance(value, str):
        return value
    
    # Remove outer quotes if present
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    
    # Empty string or null
    if value == '' or value.lower() == 'null':
        return None
    
    # Try to parse as JSON first
    try:
        parsed = json.loads(value)
        # If it's still a string, try to parse it again (nested JSON)
        if isinstance(parsed, str):
            return parse_json_value(parsed)
        return parsed
    except json.JSONDecodeError:
        pass
    
    # Check for boolean values
    if value.lower() == 'true':
        return True
    elif value.lower() == 'false':
        return False
    
    # Try to parse as number
    try:
        # Check if it's a float
        if '.' in value:
            return float(value)
        else:
            # Try to parse as int
            return int(value)
    except ValueError:
        pass
    
    # Check if it looks like a timestamp
    if is_timestamp(value):
        return value
    
    # Return as string
    return value

def is_timestamp(value):
    """Check if a string looks like a timestamp."""
    timestamp_patterns = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d"
    ]
    
    # Quick checks to avoid unnecessary parsing
    if not any(char in value for char in ['-', ':', 'T']):
        return False
    
    for pattern in timestamp_patterns:
        try:
            datetime.strptime(value, pattern)
            return True
        except ValueError:
            continue
    return False

def send_events(entities, helper, ew):
    """Send parsed data as events to Splunk."""
    for entity in entities:
        event = helper.new_event(
            data=json.dumps(entity), 
            source=helper.get_input_type(), 
            sourcetype=helper.get_sourcetype(), 
            index=helper.get_output_index()
        )
        ew.write_event(event)
    helper.log_info(f"Sent {len(entities)} events to Splunk.")

# Command line testing
if __name__ == "__main__":
    import requests
    
    if len(sys.argv) < 3:
        print("Usage: python reco_collector_system_logs.py <tenant_url> <api_key>")
        sys.exit(1)
    
    tenant_url = sys.argv[1]
    api_key = sys.argv[2]
    
    # Simple helper class for testing
    class TestHelper:
        def __init__(self, tenant_url, api_key):
            self.tenant_url = tenant_url
            self.api_key = api_key
            self.checkpoints = {}
            
        def get_arg(self, name):
            return None
            
        def get_global_setting(self, name):
            if name == "tenant_url":
                return self.tenant_url
            elif name == "api_key":
                return self.api_key
            return None
            
        def get_check_point(self, name):
            return self.checkpoints.get(name, {})
            
        def save_check_point(self, name, value):
            self.checkpoints[name] = value
            
        def log_info(self, msg):
            print(f"INFO: {msg}")
            
        def log_error(self, msg):
            print(f"ERROR: {msg}")
            
        def send_http_request(self, url, method, payload=None, headers=None, timeout=30):
            if method == "PUT":
                return requests.put(url, data=payload, headers=headers, timeout=timeout)
            elif method == "GET":
                return requests.get(url, headers=headers, timeout=timeout)
                
        def get_input_type(self):
            return "reco_system_logs"
            
        def get_sourcetype(self):
            return "reco:system:logs"
            
        def get_output_index(self):
            return "main"
    
    class TestEventWriter:
        def write_event(self, event):
            print(f"Event: {event.data}")
    
    class TestEvent:
        def __init__(self, data, source, sourcetype, index):
            self.data = data
            self.source = source
            self.sourcetype = sourcetype
            self.index = index
    
    # Run the collection
    helper = TestHelper(tenant_url, api_key)
    ew = TestEventWriter()
    
    # Override helper methods for testing
    def new_event(data, source, sourcetype, index):
        return TestEvent(data, source, sourcetype, index)
    
    helper.new_event = new_event
    
    print("Starting system logs collection test...")
    collect_events(helper, ew)
    print("Test completed!")

