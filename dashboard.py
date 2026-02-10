from collections import Counter

def show_dashboard(logs, alerts, critical_alerts):
    ip_counter = Counter([l["src_ip"] for l in logs])
    failed_logins = sum(1 for l in logs if l["status"] == "401")

    print("\n SECURITY DASHBOARD ")
    print(f"Total Logs Processed: {len(logs)}")
    print(f"Unique IPs: {len(ip_counter)}")
    print(f"Alerts: {len(alerts)}")
    print(f"Critical Alerts: {len(critical_alerts)}")
    print(f"Failed Login Attempts: {failed_logins}")

    print("\nTop 5 Active IPs:")
    for ip, count in ip_counter.most_common(5):
        print(f"{ip} -> {count}")
