#!/usr/bin/env python3
"""Real-time suspicious activity monitor for Linux hosts.

This script inspects network sockets and process CPU usage in a loop and
emits warnings when behavior looks anomalous.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Ports commonly associated with reverse shells, RAT callbacks, or IRC C2.
SUSPICIOUS_PORTS = {4444, 5555, 6667, 1337, 31337}

# RFC1918 / loopback / link-local patterns we treat as internal.
PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:"),
    re.compile(r"^fc"),
    re.compile(r"^fd"),
]


@dataclass(frozen=True)
class Connection:
    """A simplified network connection tuple."""

    state: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    pid: Optional[int]
    process_name: Optional[str]


@dataclass
class MonitorState:
    """State shared across samples to detect changes."""

    known_network_processes: Set[str]
    established_count_history: List[int]


def run_command(command: Iterable[str]) -> str:
    """Run a command and return text output, raising on failure."""

    try:
        completed = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Command not found: {command}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise RuntimeError(f"Command failed ({' '.join(command)}): {stderr}")
    return completed.stdout


def parse_endpoint(value: str) -> Tuple[str, int]:
    """Parse an endpoint in the form IP:PORT (IPv4/IPv6-aware)."""

    value = value.strip()
    if value in {"*", "*:*"}:
        return "*", 0

    if value.startswith("[") and "]" in value:
        # [IPv6]:port
        match = re.match(r"^\[(.+)]:(\d+)$", value)
        if match:
            return match.group(1), int(match.group(2))

    # Split from right to support plain IPv6 without [] when possible.
    if ":" in value:
        left, right = value.rsplit(":", 1)
        if right.isdigit():
            return left, int(right)

    return value, 0


def parse_ss_output(raw_output: str) -> List[Connection]:
    """Parse `ss -tunapH` output into structured Connection objects."""

    connections: List[Connection] = []
    for line in raw_output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue

        state = parts[0]
        local_ip, local_port = parse_endpoint(parts[3])
        remote_ip, remote_port = parse_endpoint(parts[4])

        pid: Optional[int] = None
        process_name: Optional[str] = None
        process_blob = " ".join(parts[5:])

        pid_match = re.search(r"pid=(\d+)", process_blob)
        if pid_match:
            pid = int(pid_match.group(1))

        process_match = re.search(r'\("([^\"]+)"', process_blob)
        if process_match:
            process_name = process_match.group(1)

        connections.append(
            Connection(
                state=state,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                pid=pid,
                process_name=process_name,
            )
        )
    return connections


def parse_netstat_output(raw_output: str) -> List[Connection]:
    """Parse `netstat -tunap` output into structured Connection objects."""

    connections: List[Connection] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith("Proto") or line.startswith("Active"):
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        # netstat TCP columns include state, UDP usually do not.
        proto = parts[0]
        local_idx = 3
        remote_idx = 4
        state_idx = 5 if proto.startswith("tcp") else None
        pid_prog_idx = 6 if state_idx is not None and len(parts) > 6 else 5

        local_ip, local_port = parse_endpoint(parts[local_idx])
        remote_ip, remote_port = parse_endpoint(parts[remote_idx])
        state = parts[state_idx] if state_idx is not None else "UNCONN"

        process_blob = parts[pid_prog_idx] if len(parts) > pid_prog_idx else ""
        pid: Optional[int] = None
        process_name: Optional[str] = None
        if "/" in process_blob:
            pid_str, process_name = process_blob.split("/", 1)
            if pid_str.isdigit():
                pid = int(pid_str)
        elif process_blob.isdigit():
            pid = int(process_blob)

        connections.append(
            Connection(
                state=state,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                pid=pid,
                process_name=process_name,
            )
        )
    return connections


def collect_connections() -> List[Connection]:
    """Collect active TCP/UDP sockets using `ss` or `netstat`."""

    try:
        output = run_command(["ss", "-tunapH"])
        return parse_ss_output(output)
    except RuntimeError:
        output = run_command(["netstat", "-tunap"])
        return parse_netstat_output(output)


def collect_process_metrics() -> Dict[int, Tuple[str, float, float]]:
    """Collect process CPU/memory metrics from `ps`."""

    output = run_command(["ps", "-eo", "pid=,comm=,pcpu=,pmem="])
    metrics: Dict[int, Tuple[str, float, float]] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split(None, 3)
        if len(fields) != 4:
            continue
        pid_str, comm, cpu_str, mem_str = fields
        if not pid_str.isdigit():
            continue
        try:
            metrics[int(pid_str)] = (comm, float(cpu_str), float(mem_str))
        except ValueError:
            continue
    return metrics


def is_external_ip(ip: str) -> bool:
    """Heuristic to determine whether an IP looks external/public."""

    if ip in {"*", "0.0.0.0", "::", ""}:
        return False
    return not any(pattern.search(ip) for pattern in PRIVATE_IP_PATTERNS)


def log_warning(message: str) -> None:
    now = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    print(f"[{now}] [WARNING] {message}")


def analyze(
    connections: List[Connection],
    process_metrics: Dict[int, Tuple[str, float, float]],
    state: MonitorState,
    conn_threshold: int,
    cpu_threshold: float,
) -> None:
    """Apply simple detection heuristics and print warnings."""

    established_external = [
        c
        for c in connections
        if c.state.startswith("ESTAB") and is_external_ip(c.remote_ip)
    ]

    state.established_count_history.append(len(established_external))
    state.established_count_history[:] = state.established_count_history[-20:]

    if len(established_external) >= conn_threshold:
        log_warning(
            f"High number of established external connections: {len(established_external)} "
            f"(threshold: {conn_threshold})"
        )

    for conn in established_external:
        proc_name = conn.process_name or "unknown"

        if conn.remote_port in SUSPICIOUS_PORTS:
            log_warning(
                f"Connection to suspicious destination port {conn.remote_port} "
                f"from process '{proc_name}' (pid={conn.pid})."
            )

        if proc_name not in state.known_network_processes:
            state.known_network_processes.add(proc_name)
            log_warning(
                f"New process observed opening external connection: "
                f"'{proc_name}' (pid={conn.pid}) -> {conn.remote_ip}:{conn.remote_port}."
            )

        if conn.pid is not None and conn.pid in process_metrics:
            _comm, cpu, mem = process_metrics[conn.pid]
            if cpu >= cpu_threshold:
                log_warning(
                    f"Process '{proc_name}' (pid={conn.pid}) has high CPU usage ({cpu:.1f}%) "
                    f"while maintaining external network connection to "
                    f"{conn.remote_ip}:{conn.remote_port} (mem={mem:.1f}%)."
                )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Monitor local process + network activity and warn in real time "
            "when suspicious behavior is detected."
        )
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Seconds between samples (default: 3.0)",
    )
    parser.add_argument(
        "--conn-threshold",
        type=int,
        default=20,
        help="Warn when established external connections exceed this value.",
    )
    parser.add_argument(
        "--cpu-threshold",
        type=float,
        default=80.0,
        help="Warn when a network-connected process CPU usage reaches this percent.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("--interval must be > 0")

    running = True

    def _handle_signal(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    state = MonitorState(known_network_processes=set(), established_count_history=[])

    print("Starting suspicious activity monitor. Press Ctrl+C to stop.")
    print(
        f"Sampling every {args.interval:.1f}s | "
        f"conn-threshold={args.conn_threshold} | "
        f"cpu-threshold={args.cpu_threshold:.1f}%"
    )

    while running:
        try:
            connections = collect_connections()
            process_metrics = collect_process_metrics()
            analyze(
                connections,
                process_metrics,
                state,
                conn_threshold=args.conn_threshold,
                cpu_threshold=args.cpu_threshold,
            )
        except RuntimeError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
        time.sleep(args.interval)

    print("Monitor stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
