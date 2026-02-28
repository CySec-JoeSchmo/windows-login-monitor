"""
Windows Failed Login Monitor
Reads failed login attempts (Event ID 4625) from Windows Security event log.
Requires running as Administrator.
"""

import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
import argparse
import csv
import ipaddress


def is_private_ip(ip_str):
    """Check if IP is private (internal) or public (external)."""
    if ip_str == "-" or not ip_str:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return True


def get_failed_logins(max_events=200):
    """Query failed login events from Windows Security log using wevtutil."""
    print(f"Querying Security log (last {max_events} events)...")
    
    cmd = [
        "wevtutil", "qe", "Security",
        "/q:*[System[EventID=4625]]",
        "/f:xml",
        f"/c:{max_events}",
        "/rd:true",
        "/uni:true",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True)
    except FileNotFoundError:
        print("Error: wevtutil not found (Windows only)")
        sys.exit(1)

    # Decode UTF-16 output from wevtutil
    try:
        text = result.stdout.decode("utf-16")
    except Exception:
        text = result.stdout.decode("utf-8", errors="replace")

    # Check for errors
    if result.returncode != 0 or "Access is denied" in text:
        try:
            err_text = result.stderr.decode("utf-16")
        except Exception:
            err_text = result.stderr.decode("utf-8", errors="replace")
        msg = err_text.strip() or text.strip()
        print(f"Error: {msg}")
        print("Note: Must run as Administrator")
        sys.exit(1)

    # Parse XML
    try:
        root = ET.fromstring(f"<Events>{text}</Events>")
    except ET.ParseError as e:
        print(f"XML parse error: {e}")
        sys.exit(1)

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    entries = []

    for event in root.findall("e:Event", ns):
        sys_el = event.find("e:System", ns)
        event_data = event.find("e:EventData", ns)

        if sys_el is None or event_data is None:
            continue

        event_id_el = sys_el.find("e:EventID", ns)
        time_el = sys_el.find("e:TimeCreated", ns)
        event_id = int(event_id_el.text) if event_id_el is not None else None
        timestamp = time_el.attrib.get("SystemTime", "Unknown") if time_el is not None else "Unknown"

        # Extract data fields
        data = {}
        for d in event_data.findall("e:Data", ns):
            name = d.attrib.get("Name", "")
            data[name] = (d.text or "").strip()

        username = data.get("TargetUserName", "-")
        domain = data.get("TargetDomainName", "-")
        ip = data.get("IpAddress", "-")
        port = data.get("IpPort", "-")
        logon_type = data.get("LogonType", "-")
        failure_reason = data.get("FailureReason", "-")
        sub_status = data.get("SubStatus", "-")

        # Decode logon type
        logon_types = {
            "2": "Interactive",
            "3": "Network",
            "4": "Batch",
            "5": "Service",
            "7": "Unlock",
            "8": "NetworkCleartext",
            "10": "RemoteInteractive",
            "11": "CachedInteractive",
        }
        logon_type_str = logon_types.get(logon_type, f"Type {logon_type}")

        # Decode failure reason
        reasons = {
            "0xC000006A": "Wrong password",
            "0xC0000064": "Username does not exist",
            "0xC000006D": "Bad username or auth package",
            "0xC0000070": "Workstation restriction",
            "0xC0000072": "Account disabled",
            "0xC0000234": "Account locked out",
        }
        reason = reasons.get(sub_status, failure_reason or sub_status)

        entries.append({
            "event_id": event_id,
            "time": timestamp,
            "username": username,
            "domain": domain,
            "ip": ip,
            "port": port,
            "logon_type": logon_type_str,
            "failure_reason": reason,
        })

    return entries


def print_report(entries):
    """Print a summary of failed login attempts."""
    if not entries:
        print("\nNo failed login attempts found.\n")
        return

    print(f"\nFound {len(entries)} failed login attempts:\n")

    # Summary by IP
    ip_counts = defaultdict(int)
    ip_usernames = defaultdict(set)
    suspicious_ips = set()
    
    for e in entries:
        ip = e["ip"]
        ip_counts[ip] += 1
        ip_usernames[ip].add(e["username"])
        if not is_private_ip(ip):
            suspicious_ips.add(ip)

    # Flag suspicious IPs
    if suspicious_ips:
        print("SUSPICIOUS ACTIVITY (External/Public IPs):")
        for ip in sorted(suspicious_ips):
            count = ip_counts[ip]
            usernames = ", ".join(sorted(ip_usernames[ip]))
            print(f"  {ip:<20} {count:>3} attempts  ({usernames})")
        print()

    print("Attempts by IP address:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        usernames = ", ".join(sorted(ip_usernames[ip]))
        flag = "SUSP " if ip in suspicious_ips else "  "
        print(f"  {flag}{ip:<20} {count:>3} attempts  ({usernames})")

    # Summary by username
    print("\nAttempts by username:")
    user_counts = defaultdict(int)
    for e in entries:
        user_counts[e["username"]] += 1
    for user, count in sorted(user_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {user:<20} {count:>3} attempts")

    # Recent events
    print("\nRecent events (last 15):")
    print(f"  {'Timestamp':<20} {'IP':<20} {'Username':<15} {'Type':<15} {'Reason'}")
    print("  " + "-" * 80)
    for e in entries[:15]:
        ts = e["time"][:19].replace("T", " ")
        flag = "!" if not is_private_ip(e["ip"]) else " "
        print(f"  {flag}{ts:<19} {e['ip']:<20} {e['username']:<15} {e['logon_type']:<15} {e['failure_reason']}")

    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def save_csv(entries, filename):
    """Export events to CSV file."""
    if not entries:
        print("No data to export.")
        return
    
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=entries[0].keys())
        writer.writeheader()
        writer.writerows(entries)
    print(f"Saved to {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze Windows failed login attempts from the Security event log."
    )
    parser.add_argument(
        "--max", type=int, default=200,
        help="Maximum number of failed login events to retrieve (default: 200)"
    )
    parser.add_argument(
        "--export", type=str, default=None,
        help="Optional: export results to a CSV file (e.g. --export results.csv)"
    )
    args = parser.parse_args()

    entries = get_failed_logins(max_events=args.max)
    print_report(entries)

    if args.export and entries:
        save_csv(entries, args.export)