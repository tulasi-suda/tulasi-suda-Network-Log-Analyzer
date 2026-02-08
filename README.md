# Enterprise Network Log Analyzer & Security Event Detection Automation

# Overview

The Enterprise Network Log Analyzer is a Python-based SOC automation system that ingests network logs, detects suspicious activities using a configuration-driven threat detection engine, generates alerts, maintains dashboards, and produces daily security reports.

# Key Features

# 1. Log Parsing

-   Logs are read from the network_logs/ directory and parsed into structured entries containing:
-   Timestamp
-   Source IP (source_ip)
-   Destination IP (destination_ip)
-   Request type (request_type)
-   Status code (status_code)
-   Raw log line (raw)
-   User ID (optional)

# 2. Configuration-Driven Threat Detection

Threat detection is implemented using the detect_threats() function, which evaluates logs against rules defined in config.json.

Detection uses:

-   Sliding time windows (datetime.timedelta)
-   Per-IP activity tracking (defaultdict)
-   Configurable thresholds

Detection Rules:

Brute Force Indicator
* More than configured failed login attempts from the same IP
* Within configured time window
  
High Traffic Spike
* More than configured requests from a single IP
* Within configured traffic window
  
Suspicious IP Access
* Source IP present in blacklisted_ips
  
Unauthorized Access Attempt
* Request contains restricted endpoint listed in restricted_endpoints
  
Firewall Block Alert
* Log line contains BLOCKED

# 3. Alert Classification

Alerts are categorized automatically:

Critical Alerts

* Brute Force Indicator
* High Traffic Spike
* Unauthorized Access Attempt
* Suspicious IP Access

Medium Alerts
* Firewall Block Alert

Each alert entry contains:
* Timestamp
* IP address
* Raw activity (log line)
* Triggered rule

# 4. Alert Logging

Alerts are written to:
```
logs/alerts.log
logs/critical_alerts.log
```

5. Security Dashboard

The dashboard displays:
* Total logs processed
* Unique IPs
* Total alerts
* Critical alerts
* Failed login attempts
* Top 5 most active IPs

# Configuration File (config.json)
```
{
  "blacklisted_ips": ["185.220.101.4"],
  "restricted_endpoints": ["/admin", "/secure"],
  "thresholds": {
    "failed_logins": 5,
    "failed_logins_window": 120,
    "high_traffic": 100,
    "high_traffic_window": 10
  }
}
```

# Project Structure

```
network_security/
│── network_logs/
│── logs/
│   ├── alerts.log
│   ├── critical_alerts.log
│── output/
│   ├── reports/
│── modules/
│   ├── log_parser.py
│   ├── threat_detector.py
│   ├── dashboard.py
│   ├── reporter.py
│── config.json
│── main.py
```

# To Run the Application
```
python main.py
```
Execution flow:

1. Parse logs

2. Load configuration

3. Detect threats using thresholds

4. Write alerts to log files

5. Display security dashboard

6. Generate daily report

# Libraries Used

* os
* re
* datetime
* collections
* json
* logging 
