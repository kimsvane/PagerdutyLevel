import os
import json
import time
import threading
import sys
from datetime import datetime
from flask import Flask, jsonify, request
import requests
from dotenv import load_dotenv
import logging
from azure.cosmos import CosmosClient, PartitionKey

# Version 3.1
# Load environment variables from a .env file (local dev)
load_dotenv()

# === Configuration ===
LEVEL_API_URL = os.getenv("LEVEL_API_URL", "https://api.level.io/v2/alerts")
LEVEL_API_KEY = os.getenv("LEVEL_API_KEY")  # must be set
PAGERDUTY_URL = os.getenv("PAGERDUTY_URL", "https://events.pagerduty.com/v2/enqueue")
# Fallback default routing key (used when group mapping not found)
PAGERDUTY_ROUTING_KEY = os.getenv("PAGERDUTY_ROUTING_KEY")
# Optional: a JSON env var mapping Level group name -> routing key
# Example: {"VB365": "key1", "OtherGroup": "key2"}
PAGERDUTY_ROUTING_KEYS_JSON = os.getenv("PAGERDUTY_ROUTING_KEYS", "{}")

APPINSIGHTS_CONNECTION_STRING = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
COSMOS_ENDPOINT = os.getenv("COSMOS_ENDPOINT")
COSMOS_KEY = os.getenv("COSMOS_KEY")
COSMOS_DB_NAME = "Pagerduty_Alerts_AppService"
COSMOS_CONTAINER_NAME = "DedupKeys"

# === Flask app and logging ===
app = Flask(__name__)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

from azure.monitor.opentelemetry.exporter import AzureMonitorLogExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry._logs import set_logger_provider

# Configure OpenTelemetry logging (safe even if APPINSIGHTS_CONNECTION_STRING is None)
try:
    logger_provider = LoggerProvider(
        resource=Resource.create({SERVICE_NAME: "levelio-alert-checker"})
    )
    log_exporter = AzureMonitorLogExporter(connection_string=APPINSIGHTS_CONNECTION_STRING)
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
    set_logger_provider(logger_provider)
    otel_handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
    logger.addHandler(otel_handler)
    logger.info("✅ OpenTelemetry + Application Insights logging enabled.")
except Exception as e:
    logger.warning(f"⚠️ OpenTelemetry init failed (continuing without AppInsights): {e}")

LOG_FILE = "checkforalerts.log"
if LOG_FILE:
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    app.logger.info(f"File logging enabled to {LOG_FILE}")

def log_message(message, level=logging.INFO):
    if level == logging.DEBUG:
        logger.debug(message)
    elif level == logging.INFO:
        logger.info(message)
    elif level == logging.WARNING:
        logger.warning(message)
    elif level == logging.ERROR:
        logger.error(message)
    elif level == logging.CRITICAL:
        logger.critical(message)
    else:
        logger.info(message)

def debug_message(message):
    log_message(message, level=logging.DEBUG)

# === Cosmos DB init (after logging) ===
try:
    cosmos_client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
    database = cosmos_client.create_database_if_not_exists(id=COSMOS_DB_NAME)
    container = database.create_container_if_not_exists(
        id=COSMOS_CONTAINER_NAME,
        partition_key=PartitionKey(path="/alert_id"),
        offer_throughput=400
    )
    log_message("Cosmos DB client initialized successfully.", level=logging.INFO)
except Exception as e:
    log_message(f"CRITICAL: Failed to initialize Cosmos DB client: {e}", level=logging.CRITICAL)
    container = None  # keep code running; DB ops will be guarded

# === Service status and locks ===
service_status = {
    "status": "Initializing",
    "last_check_time": None,
    "last_successful_check_time": None,
    "last_error": None,
    "running": False,
    "alert_loop_active": False,
}
status_lock = threading.Lock()

# === Routing key mapping ===
try:
    PAGERDUTY_ROUTING_KEYS = json.loads(PAGERDUTY_ROUTING_KEYS_JSON or "{}")
    if not isinstance(PAGERDUTY_ROUTING_KEYS, dict):
        PAGERDUTY_ROUTING_KEYS = {}
        log_message("PAGERDUTY_ROUTING_KEYS env var was not a JSON mapping; ignoring.", level=logging.WARNING)
except Exception as e:
    PAGERDUTY_ROUTING_KEYS = {}
    log_message(f"Failed to parse PAGERDUTY_ROUTING_KEYS: {e}", level=logging.WARNING)

def get_routing_key_for_group(group_name):
    """
    Return the routing key for the given Level group name.
    Falls back to the DEFAULT PAGERDUTY_ROUTING_KEY if no mapping exists.
    """
    if group_name and group_name in PAGERDUTY_ROUTING_KEYS and PAGERDUTY_ROUTING_KEYS[group_name]:
        return PAGERDUTY_ROUTING_KEYS[group_name]
    return PAGERDUTY_ROUTING_KEY

# === Cosmos helpers ===
def save_dedup_key(alert_id, dedup_key, group_name=None):
    if container is None:
        log_message("Cosmos container not available, skipping save_dedup_key.", level=logging.WARNING)
        return
    try:
        container.upsert_item({
            "id": alert_id,
            "alert_id": alert_id,
            "dedup_key": dedup_key,
            "group_name": group_name,
            "updated_at": datetime.utcnow().isoformat()
        })
        log_message(f"Saved dedup_key for alert {alert_id} (group={group_name}).", level=logging.INFO)
    except Exception as e:
        log_message(f"❌ Error saving dedup key to Cosmos: {e}", level=logging.CRITICAL)

def check_existing_dedup_key(alert_id):
    """
    Return dedup_key if exists, else None.
    """
    if container is None:
        return None
    try:
        item_response = container.read_item(item=alert_id, partition_key=alert_id)
        return item_response.get("dedup_key")
    except Exception as e:
        # Could be not found or read error
        log_message(f"🔍 Dedup key not found for {alert_id} (or read error): {e}", level=logging.DEBUG)
        return None

def get_dedup_record(alert_id):
    """Return the full record from Cosmos, or None."""
    if container is None:
        return None
    try:
        return container.read_item(item=alert_id, partition_key=alert_id)
    except Exception as e:
        log_message(f"🔍 Could not read item {alert_id}: {e}", level=logging.DEBUG)
        return None

def remove_dedup_key(alert_id):
    if container is None:
        return
    try:
        container.delete_item(item=alert_id, partition_key=alert_id)
        log_message(f"Removed dedup key for alert {alert_id} from Cosmos DB.", level=logging.INFO)
    except Exception as e:
        log_message(f"Failed to delete dedup key from Cosmos DB: {e}", level=logging.WARNING)

# === HTTP session & request helper ===
session = requests.Session()

def make_api_request(method, url, headers=None, json_payload=None, stream=False):
    global session

    log_message(f"Requesting {method} {url}", level=logging.DEBUG)
    if "level.io" in url and not LEVEL_API_KEY:
        error_msg = f"LEVEL_API_KEY is not set. Cannot call {url}"
        log_message(error_msg, level=logging.CRITICAL)
        with status_lock:
            service_status["last_error"] = error_msg
            service_status["status"] = "Error - Missing Level API Key"
        return {"data": []}

    response = None
    try:
        response = session.request(method, url, headers=headers, json=json_payload, stream=stream, timeout=30)
        log_message(f"Response status: {response.status_code}", level=logging.DEBUG)
        response.raise_for_status()
        try:
            return response.json()
        except ValueError:
            log_message("Response not JSON, returning raw text.", level=logging.WARNING)
            return {"raw_response": response.text}
    except requests.exceptions.Timeout as te:
        error_msg = f"Timeout requesting {url}: {te}"
        log_message(error_msg, level=logging.WARNING)
        with status_lock:
            service_status["last_error"] = error_msg
            service_status["status"] = "Error - Timeout"
        # Reset session and return empty data for level alerts
        session.close()
        session = requests.Session()
        return {"data": []}
    except requests.exceptions.RequestException as re:
        response_text = response.text if response is not None else 'N/A'
        error_msg = f"RequestException for {url}: {re}. Resp: {response_text}"
        log_message(error_msg, level=logging.WARNING)
        # reset session and retry once
        session.close()
        session = requests.Session()
        try:
            log_message("Retrying once with fresh session...", level=logging.WARNING)
            response = session.request(method, url, headers=headers, json=json_payload, stream=stream, timeout=15)
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                return {"raw_response": response.text}
        except Exception as retry_err:
            retry_msg = f"Retry after session reset also failed: {retry_err}"
            log_message(retry_msg, level=logging.CRITICAL)
            with status_lock:
                service_status["last_error"] = retry_msg
                service_status["status"] = "Error - API Request Failed"
            # Do NOT exit the process — return empty dataset for level alerts so loop keeps running
            return {"data": []}

# === Level API helpers ===
def fetch_alerts_api():
    url = LEVEL_API_URL
    url = f"{url}{'&' if '?' in url else '?'}status=active"
    headers = {
        "Authorization": LEVEL_API_KEY,
        "accept": "application/json"
    }
    resp = make_api_request("GET", url, headers)
    try:
        log_message(f"Raw Level response: {json.dumps(resp)[:1000]}", level=logging.DEBUG)
    except Exception:
        pass
    return resp

def fetch_device_info_api(device_id):
    if not device_id:
        return {}
    url = f"https://api.level.io/v2/devices/{device_id}"
    headers = {"Authorization": LEVEL_API_KEY, "accept": "application/json"}
    return make_api_request("GET", url, headers) or {}

def fetch_device_group_name_api(group_id):
    if not group_id:
        return None
    url = f"https://api.level.io/v2/groups/{group_id}"
    headers = {"Authorization": LEVEL_API_KEY, "accept": "application/json"}
    response_data = make_api_request("GET", url, headers)
    return response_data.get("name") if isinstance(response_data, dict) else None

# === PagerDuty helpers (choose routing key by group) ===
def trigger_pagerduty_incident_api(summary, severity, source, group_name=None, custom_details=None):
    routing_key = get_routing_key_for_group(group_name)
    if not routing_key:
        error_msg = "No PagerDuty routing key configured for this group and no default key available."
        log_message(error_msg, level=logging.CRITICAL)
        with status_lock:
            service_status["last_error"] = error_msg
            service_status["status"] = "Error - Missing PagerDuty Routing Key"
        return {}

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": source,
            "component": "level.io",
            "custom_details": custom_details or {}
        }
    }
    log_message(f"Sending PagerDuty trigger: {summary} [group={group_name}]", level=logging.INFO)
    headers = {"Content-Type": "application/json"}
    return make_api_request("POST", PAGERDUTY_URL, headers, json_payload=payload)

def resolve_pagerduty_incident_api(dedup_key, group_name=None):
    routing_key = get_routing_key_for_group(group_name)
    if not routing_key:
        log_message("No routing key for resolve; skipping.", level=logging.WARNING)
        return {}

    payload = {
        "dedup_key": dedup_key,
        "routing_key": routing_key,
        "event_action": "resolve"
    }
    headers = {"Content-Type": "application/json"}
    log_message(f"Resolving PagerDuty dedup_key={dedup_key} [group={group_name}]", level=logging.INFO)
    return make_api_request("POST", PAGERDUTY_URL, headers, json_payload=payload)

# === Main alert loop ===
def alert_checking_loop():
    # Require at least level API key to run. It's okay if group mapping is empty.
    if not LEVEL_API_KEY:
        log_message("Missing LEVEL_API_KEY, cannot start alert loop.", level=logging.CRITICAL)
        return

    with status_lock:
        service_status["alert_loop_active"] = True
        service_status["status"] = "Running"
        service_status["last_error"] = None

    while service_status["running"]:
        try:
            alerts_data = fetch_alerts_api()
            active_alert_ids = set()

            with status_lock:
                service_status["last_check_time"] = datetime.now().isoformat()

            alerts_list = alerts_data.get("data", []) if isinstance(alerts_data, dict) else []

            for alert in alerts_list:
                alert_id = alert.get("id")
                name = alert.get("name")
                severity = alert.get("severity")
                is_resolved = alert.get("is_resolved", False)

                if alert_id:
                    active_alert_ids.add(alert_id)

                pd_severity = "critical" if severity == "emergency" else "error"

                if severity == "emergency" and not is_resolved:
                    existing_dedup_key = check_existing_dedup_key(alert_id)
                    if not existing_dedup_key:
                        device_id = alert.get("device_id")
                        device_info = fetch_device_info_api(device_id) if device_id else {}
                        hostname = device_info.get("hostname", "Unknown Host")
                        group_name = fetch_device_group_name_api(device_info.get("group_id")) if device_info else None

                        custom_details = {
                            "platform": device_info.get("platform"),
                            "tags": device_info.get("tags"),
                            "online": device_info.get("online"),
                            "maintenance_mode": device_info.get("maintenance_mode"),
                            "group": group_name,
                            "public_ip": device_info.get("public_ip_address"),
                            "city": device_info.get("city"),
                            "country": device_info.get("country"),
                            "device_url": f"https://app.level.io/device/{device_id.split('/')[-1]}/overview" if device_id else None,
                            "alert_name": name,
                            "alert_severity": severity,
                            "alert_id": alert_id
                        }

                        pd_response = trigger_pagerduty_incident_api(
                            summary=f"CRITICAL: {name} on {hostname} [{group_name}]",
                            severity=pd_severity,
                            source=hostname,
                            group_name=group_name,
                            custom_details=custom_details
                        )
                        # PagerDuty v2 enqueue returns a dict with dedup_key on success
                        if isinstance(pd_response, dict) and pd_response.get("dedup_key"):
                            save_dedup_key(alert_id, pd_response["dedup_key"], group_name=group_name)
                        else:
                            log_message(f"PagerDuty trigger did not return dedup_key for alert {alert_id}: {pd_response}", level=logging.WARNING)

            # Resolve incidents whose alerts are no longer active
            try:
                if container is not None:
                    for item in container.read_all_items():
                        if item.get("alert_id") not in active_alert_ids:
                            dedup_key = item.get("dedup_key")
                            group_name = item.get("group_name")
                            if dedup_key:
                                log_message(f"Resolving PagerDuty incident {dedup_key} (no longer active).", level=logging.INFO)
                                resolve_pagerduty_incident_api(dedup_key, group_name=group_name)
                            remove_dedup_key(item.get("alert_id"))
            except Exception as e:
                log_message(f"Error during resolve sweep: {e}", level=logging.WARNING)

            with status_lock:
                service_status["last_successful_check_time"] = datetime.now().isoformat()
                service_status["status"] = "Running"
                service_status["last_error"] = None

        except Exception as e:
            err = f"Unhandled exception in alert loop: {e}"
            log_message(err, level=logging.ERROR)
            with status_lock:
                service_status["last_error"] = err
                service_status["status"] = "Error - Processing Issue"

        time.sleep(60)

# === Startup / thread control ===
def start_alert_thread():
    with status_lock:
        if service_status["alert_loop_active"]:
            log_message("Alert checking thread already active. Skipping start.", level=logging.INFO)
            return
        service_status["running"] = True

    thread = threading.Thread(target=alert_checking_loop, daemon=True)
    thread.start()
    log_message("Background alert checking thread started.", level=logging.INFO)

log_message("Starting alert monitor engine", level=logging.INFO)
log_message(f"Following PD_Routing keys were discovered:{PAGERDUTY_ROUTING_KEYS_JSON} fallback routing key: {PAGERDUTY_ROUTING_KEY} ", level=logging.INFO)
start_alert_thread()

# === Flask endpoints ===
@app.route('/')
def home():
    return "Level.io PagerDuty Integration Service is running. Check /status for details."

@app.route('/status')
def get_service_status():
    with status_lock:
        status_copy = service_status.copy()
    return jsonify(status_copy)

@app.route('/restart', methods=['POST'])
def restart_app():
    secret = os.getenv("RESTART_SECRET")
    token = request.headers.get("Authorization") or request.args.get("token")
    if not secret or token != secret:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    log_message("Manual restart called. Exiting to trigger App Service restart...", level=logging.CRITICAL)
    with status_lock:
        service_status["running"] = False
        service_status["alert_loop_active"] = False
    time.sleep(1)
    sys.exit(1)
    return jsonify({"status": "ok", "message": "Restart triggered"}), 200

@app.route('/healthcheck')
def healthcheck():
    with status_lock:
        status_copy = service_status.copy()

    status_text = status_copy.get("status", "Unknown")
    last_error = status_copy.get("last_error")
    error_states = [
        "Error - API Request Failed",
        "Error - Timeout",
        "Error - Missing Level API Key",
        "Error - Missing PagerDuty Routing Key",
        "Error - Missing API Keys",
        "Error - Processing Issue",
    ]

    if any(status_text.startswith(e) for e in error_states):
        return jsonify({
            "status": "unhealthy",
            "error": status_text,
            "last_error": last_error
        }), 503

    return jsonify({
        "status": "healthy",
        "service_status": status_text,
        "last_successful_check_time": status_copy.get("last_successful_check_time")
    }), 200

# === Local run ===
if __name__ == '__main__':
    try:
        app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 80)))
    finally:
        log_message("Local Flask server shutting down. Signaling background thread to stop.", level=logging.CRITICAL)
        with status_lock:
            service_status["running"] = False
