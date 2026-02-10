from collections import defaultdict

def log_alert(severity, timestamp, ip, activity):
    print(f"[{severity.upper()}] {timestamp} | {ip} | {activity}")

class RuleEngine:
    def evaluate(self, log):
        alerts = []
        event = log["event"]

        if event == "FAIL_LOGIN":
            alerts.append(("critical", "Brute Force Indicator"))
        elif event == "BLACKLIST_IP":
            alerts.append(("critical", "Suspicious IP Access"))
        elif event == "TRAFFIC_SPIKE":
            alerts.append(("critical", "High Traffic Spike"))
        elif event == "BLOCKED":
            alerts.append(("medium", "Firewall Block Event"))
        elif event == "UNAUTHORIZED":
            alerts.append(("critical", "Unauthorized Endpoint Access"))
        elif event == "UNUSUAL_COUNTRY":
            alerts.append(("medium", "Unusual Country Traffic"))

        return alerts

def generate_security_report(stats, threats, suspicious_ips, hourly_activity, blocked_count):
    print("\nDAILY SECURITY REPORT ")
    print(f"Total Logs Processed: {stats['total_logs']}")
    print(f"Alerts Detected: {stats['alerts']}")
    print(f"Critical Alerts: {stats['critical']}\n")

    print("Threat Categories Triggered:")
    for t in threats:
        print(f"- {t}")

    print("\nTop Suspicious IPs:")
    for ip in suspicious_ips:
        print(ip)

    print("\nHourly Activity:")
    for hour, count in hourly_activity.items():
        print(f"{hour} | {'||' * count}")

    print(f"\nBlocked Attempts: {blocked_count}")
    print("\n")

parsed_logs = [
    {"timestamp": "10:15", "source_ip": "203.0.113.9", "event": "FAIL_LOGIN"},
    {"timestamp": "10:16", "source_ip": "185.220.101.4", "event": "BLACKLIST_IP"},
    {"timestamp": "10:18", "source_ip": "45.67.89.120", "event": "TRAFFIC_SPIKE"},
    {"timestamp": "10:20", "source_ip": "91.234.56.78", "event": "BLOCKED"},
    {"timestamp": "10:22", "source_ip": "203.0.113.9", "event": "UNAUTHORIZED"},
    {"timestamp": "10:25", "source_ip": "45.67.89.120", "event": "UNUSUAL_COUNTRY"},
]

stats = {
    "total_logs": 18742,
    "alerts": 97,
    "critical": 24
}

threats = {
    "Brute Force Attacks",
    "Suspicious IP Access",
    "High Traffic Spikes",
    "Unauthorized Endpoint Access",
    "Firewall Block Events",
    "Unusual Country Traffic"
}

suspicious_ips = [
    "203.0.113.9",
    "185.220.101.4",
    "45.67.89.120",
    "91.234.56.78"
]

hourly_activity = {
    "00:00": 4, "02:00": 7, "04:00": 2, "06:00": 10,
    "08:00": 13, "10:00": 16, "12:00": 9, "14:00": 7,
    "16:00": 10, "18:00": 13, "20:00": 6, "22:00": 4
}

blocked_count = 67

engine = RuleEngine()

for log in parsed_logs:
    alerts = engine.evaluate(log)
    for severity, activity in alerts:
        log_alert(severity, log["timestamp"], log["source_ip"], activity)

generate_security_report(
    stats,
    threats,
    suspicious_ips,
    hourly_activity,
    blocked_count
)
