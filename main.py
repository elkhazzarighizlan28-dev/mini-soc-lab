
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE = Path("data/sample_auth.log")
REPORT_DIR = Path("reports")

THRESHOLD = 3
WINDOW_SECONDS = 60
HIGH_THRESHOLD = 6


def analyze_logs():
    attempts = defaultdict(deque)
    total_failed = Counter()
    alerts = []

    if not LOG_FILE.exists():
        print(f"Error: log file not found: {LOG_FILE}")
        return

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            if "LOGIN_FAILED" not in line:
                continue

            parts = line.split()

            try:
                timestamp = datetime.strptime(
                    " ".join(parts[:2]),
                    "%Y-%m-%d %H:%M:%S"
                )

                ip_field = next(
                    part for part in parts
                    if part.startswith("ip=")
                )
                ip = ip_field.removeprefix("ip=")

            except (ValueError, StopIteration):
                print(
                    f"[WARNING] Invalid log line: {line_number}"
                )
                continue

            total_failed[ip] += 1
            recent = attempts[ip]

            cutoff = timestamp - timedelta(
                seconds=WINDOW_SECONDS
            )

            while recent and recent[0] < cutoff:
                recent.popleft()

            recent.append(timestamp)

            # Generate alerts at 3 and 6 attempts
            count = len(recent)

            if count == THRESHOLD or count == HIGH_THRESHOLD:
                severity = (
                    "HIGH" if count >= HIGH_THRESHOLD
                    else "MEDIUM"
                )

                alerts.append(
                    f"[{severity}] IP: {ip} | "
                    f"{count} failed attempts in "
                    f"{WINDOW_SECONDS} seconds | "
                    f"Last attempt: {timestamp}"
                )

    # Create the reports directory
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report_lines = [
        "=== MINI SOC : SECURITY REPORT ===",
        f"Generated at: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Threshold: {THRESHOLD}",
        f"High severity threshold: {HIGH_THRESHOLD}",
        f"Time window: {WINDOW_SECONDS} seconds",
        f"IPs with failed attempts: {len(total_failed)}",
        "",
        "=== TOTAL FAILED ATTEMPTS ===",
    ]

    for ip, count in total_failed.most_common():
        report_lines.append(
            f"IP: {ip} | Failed attempts: {count}"
        )

    report_lines.extend([
        "",
        "=== TIME-BASED ALERTS ==="
    ])

    if alerts:
        report_lines.extend(alerts)
    else:
        report_lines.append(
            "No time-based alerts detected."
        )

    report_text = "\n".join(report_lines)

    print(report_text)

    report_file = REPORT_DIR / "security_report.txt"
    report_file.write_text(
        report_text + "\n",
        encoding="utf-8"
    )

    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    analyze_logs()
