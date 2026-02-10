from collections import defaultdict
from datetime import timedelta

def detect_threats(logs, config):
    alerts = []
    critical_alerts = []
    failed_logins = defaultdict(list)
    traffic_count = defaultdict(list)

    for log in logs:
        timestamp = log["timestamp"]
        ip = log["source_ip"]
        raw = log["raw"]
        alert_triggered = None

        if log["status_code"] == "FAIL":
            failed_logins[ip].append(timestamp)
            window = timedelta(seconds=config["thresholds"]["failed_logins_window"])
            failed_attempts = [t for t in failed_logins[ip] if timestamp - t <= window]
            if len(failed_attempts) > config["thresholds"]["failed_logins"]:
                alert_triggered = "Brute Force Indicator"

        traffic_count[ip].append(timestamp)
        window = timedelta(seconds=config["thresholds"]["high_traffic_window"])
        recent_traffic = [t for t in traffic_count[ip] if timestamp - t <= window]
        if len(recent_traffic) > config["thresholds"]["high_traffic"]:
            alert_triggered = "High Traffic Spike"

        if ip in config["blacklisted_ips"]:
            alert_triggered = "Suspicious IP Access"

        if any(ep in log["request_type"] for ep in config["restricted_endpoints"]):
            alert_triggered = "Unauthorized Access Attempt"

        if "BLOCKED" in raw:
            alert_triggered = "Firewall Block Alert"

        if alert_triggered:
            alert_entry = {
                "timestamp": timestamp,
                "ip": ip,
                "activity": raw,
                "rule": alert_triggered
            }
            if alert_triggered in ["Brute Force Indicator", "High Traffic Spike", "Unauthorized Access Attempt", "Suspicious IP Access"]:
                critical_alerts.append(alert_entry)
            else:
                alerts.append(alert_entry)

    return alerts, critical_alerts
