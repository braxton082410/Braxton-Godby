# Braxton-Godby

Real-time suspicious activity monitor for Linux devices.

## What it does

`sudo python3 suspicious_activity_monitor.py` samples local process and network
activity and emits warnings when it detects behavior such as:

- Connections to commonly abused command-and-control ports.
- A sudden high count of established external connections.
- New processes opening external connections for the first time.
- High-CPU processes that are also communicating externally.

## Usage

```bash
python3 suspicious_activity_monitor.py --help
sudo python3 suspicious_activity_monitor.py --interval 2 --conn-threshold 30 --cpu-threshold 85
```

> Tip: run with `sudo` for richer process/socket visibility.
