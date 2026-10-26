
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<message>.*)$"
)

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+)"
)

ACCEPTED_PATTERN = re.compile(
    r"Accepted \S+ for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+)"
)


def analyze_log(path: Path, threshold: int = 3) -> None:
    failures = Counter()
    successes = Counter()
    failed_events = []

    for line_number, line in enumerate(
        path.read_text().splitlines(), start=1
    ):
        match = LOG_PATTERN.match(line)
        if not match:
            continue

        try:
            timestamp = datetime.fromisoformat(
                match.group("timestamp")
            )
        except ValueError:
            print(f"Skipping invalid timestamp on line {line_number}")
            continue

        message = match.group("message")

        failed = FAILED_PATTERN.search(message)
        accepted = ACCEPTED_PATTERN.search(message)

        if failed:
            ip = failed.group("ip")
            username = failed.group("username")

            failures[ip] += 1
            failed_events.append((timestamp, ip, username))

        elif accepted:
            ip = accepted.group("ip")
            username = accepted.group("username")
            successes[ip] += 1

    print("\n=== SSH Authentication Summary ===")
    print(f"Failed authentication events: {sum(failures.values())}")
    print(f"Successful authentication events: {sum(successes.values())}")

    print("\n=== Failed Attempts by Source IP ===")
    if not failures:
        print("No failed authentication events found.")

    for ip, count in failures.most_common():
        print(f"{ip}: {count} failure(s)")

        if count >= threshold:
            print(
                f"  ALERT: {ip} has at least "
                f"{threshold} failed attempts."
            )

    print("\n=== Repeated Failures Within 5 Minutes ===")
    window = timedelta(minutes=5)
    by_ip = {}

    for timestamp, ip, username in failed_events:
        by_ip.setdefault(ip, []).append((timestamp, username))

    found_alert = False

    for ip, events in by_ip.items():
        events.sort()

        for start in range(len(events)):
            end = start
            while (
                end < len(events)
                and events[end][0] - events[start][0] <= window
            ):
                end += 1

            if end - start >= threshold:
                print(
                    f"ALERT: {ip} had {end - start} failed "
                    f"attempts within 5 minutes."
                )
                found_alert = True
                break

    if not found_alert:
        print("No repeated-failure alert triggered.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ssh_log_analyzer.py <log-file>")
        raise SystemExit(2)

    log_path = Path(sys.argv[1])

    if not log_path.is_file():
        print(f"Error: log file not found: {log_path}")
        raise SystemExit(1)

    analyze_log(log_path)

