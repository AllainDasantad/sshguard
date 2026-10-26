
# SSHGuard Lab

A Python-based SSH authentication testing and log-analysis
project built in an isolated local environment.

## Project goals

- Understand SSH password authentication.
- Practice Python SSH automation with Paramiko.
- Analyze authentication logs.
- Detect repeated failed logins.
- Test detection rules with automated unit tests.

## Architecture

1. A local SSH server runs in Docker.
2. A Python client demonstrates authentication against the
   authorized lab account.
3. The log analyzer parses authentication events.
4. Detection rules identify repeated failures.
5. Unit tests verify the analyzer's behavior.

## Requirements

- Python 3.11 or later
- Paramiko
- Docker Engine
- Docker Compose

## Setup

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install paramiko
```

Start the local SSH server:

```bash
docker compose up -d
```

Run the authentication demonstration:

```bash
python ssh_bruteforce.py
```

Analyze the sample logs:

```bash
python ssh_log_analyzer.py samples/ssh_auth.log
```

Run automated tests:

```bash
python -m unittest discover -s tests -v
```

## Detection rules

The analyzer reports failed authentication counts per source IP
and flags repeated failures that meet a configurable threshold
within a five-minute window.

## Limitations

- The sample logs are synthetic.
- The analyzer supports a limited, documented log format.
- Alerts are informational and do not block network traffic.
- Log formats vary across SSH server implementations.
- This project is designed for authorized local testing.

## Security

Only test authentication against systems you own or are
explicitly authorized to assess. Keep the lab bound to localhost.

## Future improvements

- Support additional OpenSSH log formats.
- Export alerts as JSON.
- Add configurable thresholds and time windows.
- Add structured logging and broader test coverage.
- Document defensive controls such as SSH keys and rate limiting.

