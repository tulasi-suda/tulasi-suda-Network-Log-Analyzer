import os
import re
from datetime import datetime

def parse_logs(log_folder):
    logs = []
    for filename in os.listdir(log_folder):
        file_path = os.path.join(log_folder, filename)
        with open(file_path, "r") as f:
            for line in f:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 5:
                    log = {
                        "timestamp": datetime.strptime(parts[0], "%Y-%m-%dT%H:%M:%S"),
                        "source_ip": parts[1],
                        "destination_ip": parts[2],
                        "request_type": parts[3],
                        "status_code": parts[4],
                        "user_id": parts[5] if len(parts) > 5 else None,
                        "raw": line.strip()
                    }
                    logs.append(log)
    return logs
