# Windows Failed Login Monitor

Simple script to collect and summarize failed Windows logon attempts (Event ID 4625) from the Security event log.
I was tired of seeing the alerts from my home router for the attempts being made and blocked, so I made this script to see how close these attackers were at getting into my machine. 

This repository contains `windows-login-monitor.py`, a lightweight tool that queries Windows Event Log (via `wevtutil`) and prints a human-friendly report summarizing failed login attempts and highlighting external (public) source IPs.

## Requirements

- Windows (wevtutil is Windows-only)
- Python 3.10+ (or compatible)
- Administrator / elevated shell to read the Security log

Optional:
- `pywin32` is accepted in older versions but this script uses `wevtutil` and has no extra runtime dependencies.

## Usage

Open an elevated PowerShell or CMD (right-click "Run as administrator") and run:

```powershell
python windows-login-monitor.py --max 200
```

Options:

- `--max N` — maximum number of failed events to retrieve (default: 200)
- `--export file.csv` — save results to a CSV file

Examples:

```powershell
# show last 100 failed logins
python windows-login-monitor.py --max 100

# export results to CSV
python windows-login-monitor.py --export results.csv
```

## What the script shows

- Summary of attempts grouped by source IP and username
- Recent event listing with timestamp, source IP, username, logon type and failure reason
- External/public IPs are flagged as suspicious (so you can spot Internet-origin attempts quickly)

## Notes & Troubleshooting

- You must run the script from an elevated shell. If you see `Access is denied`, re-launch PowerShell/CMD as Administrator.
- The script decodes `wevtutil`'s UTF-16 output and will report a parsing error only for malformed XML returned by `wevtutil`.
- For network logons (logon type "Network") the `IpAddress` field is used — this is the source IP that attempted the connection.
- The script only reports metadata (usernames, IPs, logon type); Windows does not log attempted passwords.

## Export

Use the `--export` option to write events to a CSV file. The CSV columns match the script's output fields: `event_id,time,username,domain,ip,port,logon_type,failure_reason`.
---
