import os
from datetime import datetime

def write_logs(alerts, critical_alerts, log_folder="logs"):
    os.makedirs(log_folder, exist_ok=True)
    with open(os.path.join(log_folder, "alerts.log"), "w") as f:
        for alert in alerts:
            f.write(f"{alert['timestamp']} {alert['ip']} {alert['activity']} {alert['rule']}\n")
    with open(os.path.join(log_folder, "critical_alerts.log"), "w") as f:
        for alert in critical_alerts:
            f.write(f"{alert['timestamp']} {alert['ip']} {alert['activity']} {alert['rule']}\n")

def generate_report(logs, alerts, critical_alerts, output_folder="output/reports"):
    os.makedirs(output_folder, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    file_path = os.path.join(output_folder, f"security_report_{date_str}.txt")
    unique_ips = set(log["source_ip"] for log in logs)
    top_ips = {}
    for log in logs:
        top_ips[log["source_ip"]] = top_ips.get(log["source_ip"], 0) + 1
    top_ips_sorted = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5]
    with open(file_path, "w") as f:
        f.write(f"Date: {date_str}\n")
        f.write(f"Total logs processed: {len(logs)}\n")
        f.write(f"Total alerts: {len(alerts)}\n")
        f.write(f"Total critical alerts: {len(critical_alerts)}\n")
        f.write("Top 5 most active IPs:\n")
        for ip, count in top_ips_sorted:
            f.write(f"{ip}: {count}\n")
        f.write("Blocked / suspicious activity:\n")
        for alert in critical_alerts:
            f.write(f"{alert['timestamp']} {alert['ip']} {alert['rule']}\n")
