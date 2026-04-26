#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import List, Sequence, Set, Tuple


DEFAULT_TCP_PORTS = "22,80,135,139,443,445,3389"
DEFAULT_UDP_PORTS = "53,67,68,69,123,137,138,161,500,1900"
LIVE_OUTPUT_FILE = "live_hosts.txt"
DOWN_OUTPUT_FILE = "down_hosts.txt"


class BannerArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        copyright_line = style_text("© AhmedAlDiab", GOLD, bold=True)
        return f"{copyright_line}\n\n{super().format_help()}"

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{style_text('error:', ERROR_RED, bold=True)} {message}\nUse -h or --help for help.\n")


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


USE_COLOR = supports_color()
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""

GOLD = "\033[38;2;212;175;55m" if USE_COLOR else ""
LIGHT_GOLD = "\033[38;2;244;214;110m" if USE_COLOR else ""
OLIVE_GREEN = "\033[38;2;102;112;60m" if USE_COLOR else ""
ERROR_RED = "\033[38;2;220;80;70m" if USE_COLOR else ""


def style_text(text: str, color: str = "", bold: bool = False) -> str:
    if not USE_COLOR:
        return text
    prefix = ""
    if bold:
        prefix += BOLD
    prefix += color
    return f"{prefix}{text}{RESET}"


def info(message: str) -> None:
    print(f"\n{style_text('[*]', GOLD, bold=True)} {message}")


def success(message: str) -> None:
    print(f"{style_text('[+]', OLIVE_GREEN, bold=True)} {message}")


def failure(message: str) -> None:
    print(f"{style_text('[-]', ERROR_RED, bold=True)} {message}", file=sys.stderr)


def normalize_custom_port_syntax(argv: Sequence[str]) -> List[str]:
    normalized: List[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("-tcp") and arg not in ("-tcp", "--tcp"):
            spec = arg[4:]
            if not spec:
                raise ValueError("Missing TCP port specification after -tcp.")
            normalized.extend(["--tcp", spec])
        elif arg in ("-tcp", "--tcp"):
            if i + 1 >= len(argv):
                raise ValueError("Missing TCP port specification after -tcp/--tcp.")
            normalized.extend(["--tcp", argv[i + 1]])
            i += 1
        elif arg.startswith("-udp") and arg not in ("-udp", "--udp"):
            spec = arg[4:]
            if not spec:
                raise ValueError("Missing UDP port specification after -udp.")
            normalized.extend(["--udp", spec])
        elif arg in ("-udp", "--udp"):
            if i + 1 >= len(argv):
                raise ValueError("Missing UDP port specification after -udp/--udp.")
            normalized.extend(["--udp", argv[i + 1]])
            i += 1
        else:
            normalized.append(arg)
        i += 1
    return normalized


def validate_port_spec(spec: str) -> str:
    spec = spec.strip()
    if not spec:
        raise argparse.ArgumentTypeError("Port specification cannot be empty.")
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", spec):
        raise argparse.ArgumentTypeError("Invalid port specification. Use 22,80,443 or 1-1000.")
    return spec


def build_parser() -> argparse.ArgumentParser:
    parser = BannerArgumentParser(
        prog="HostDiscovery",
        usage="HostDiscovery [-h] [--tcp PORTS | -tcp<ports>] [--udp PORTS | -udp<ports>] target [target ...]",
        description=(
            "Automates two-stage Nmap host discovery.\n\n"
            "Stage 1: Initial ICMP/ARP Discovery (-sn)\n"
            "Stage 2: Retry hosts marked 'down' using TCP/UDP probes (-PS/-PU)\n\n"
            "Interactive Progress:\n"
            "  While a scan is running, press <Space> or <Enter> at any time\n"
            "  to display the current percentage and elapsed time natively."
        ),
        epilog=(
            "Custom port syntax examples:\n"
            "  -tcp1-1000\n"
            "  -tcp22,80,443\n"
            "  -udp1-500\n\n"
            f"Default TCP: {DEFAULT_TCP_PORTS}\n"
            f"Default UDP: {DEFAULT_UDP_PORTS}\n\n"
            "Example run:\n"
            "  python3 HostDiscovery.py 192.168.1.0/24 -tcp22,80 -udp53"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", help="Target(s) to scan.")
    parser.add_argument("--tcp", dest="tcp_ports", metavar="PORTS", type=validate_port_spec, default=DEFAULT_TCP_PORTS)
    parser.add_argument("--udp", dest="udp_ports", metavar="PORTS", type=validate_port_spec, default=DEFAULT_UDP_PORTS)
    return parser


def ensure_nmap_installed() -> None:
    if shutil.which("nmap") is None:
        raise RuntimeError("Nmap was not found in PATH. Please install Nmap.")


def parse_gnmap_output(gnmap_text: str) -> Tuple[Set[str], Set[str]]:
    up_hosts, down_hosts = set(), set()
    host_pattern = re.compile(r"^Host:\s+(\S+)(?:\s+\(.*?\))?\s+Status:\s+(Up|Down)\b", re.IGNORECASE)
    
    for line in gnmap_text.splitlines():
        match = host_pattern.match(line.strip())
        if match:
            host, status = match.groups()
            if status.lower() == "up":
                up_hosts.add(host)
                down_hosts.discard(host)
            else:
                down_hosts.add(host)
                up_hosts.discard(host)
                
    return up_hosts, down_hosts


def execute_scan(scan_options: Sequence[str], targets: Sequence[str]) -> Tuple[Set[str], Set[str]]:
    # Create temp files for the targets (to prevent CLI length limits) and output
    fd_out, gnmap_path = tempfile.mkstemp(prefix="hostdiscovery_", suffix=".gnmap")
    os.close(fd_out)
    
    fd_in, target_list_path = tempfile.mkstemp(prefix="hostdiscovery_targets_", suffix=".txt")
    os.close(fd_in)

    try:
        # Write targets to a file for -iL
        with open(target_list_path, "w", encoding="utf-8") as f:
            for t in targets:
                f.write(f"{t}\n")

        # Command inherits current console (stdin/stdout/stderr) so user can press Space/Enter to see %
        command = ["nmap"] + list(scan_options) + ["-oG", gnmap_path, "-iL", target_list_path]
        
        result = subprocess.run(command)
        
        if result.returncode != 0:
            raise RuntimeError(f"Nmap exited with error code {result.returncode}")

        # Parse results silently
        with open(gnmap_path, "r", encoding="utf-8", errors="replace") as file:
            gnmap_text = file.read()
            
        return parse_gnmap_output(gnmap_text)
        
    finally:
        # Cleanup temporary files
        try:
            os.remove(gnmap_path)
            os.remove(target_list_path)
        except OSError:
            pass


def host_sort_key(host: str):
    try:
        ip = ipaddress.ip_address(host)
        return (0, ip.version, int(ip))
    except ValueError:
        return (1, host.lower())


def save_hosts(path: str, hosts: Sequence[str]) -> None:
    with open(path, "w", encoding="utf-8") as file:
        for host in hosts:
            file.write(f"{host}\n")


def main() -> int:
    try:
        normalized_argv = normalize_custom_port_syntax(sys.argv[1:])
        args = build_parser().parse_args(normalized_argv)
        ensure_nmap_installed()

        # ================= STAGE 1 =================
        info(f"STAGE 1: Running Initial Discovery (-sn) on: {' '.join(args.targets)}")
        print(style_text("Hint: Press <Enter> or <Space> while it runs to see progress percentage.", LIGHT_GOLD))
        
        first_live, first_down = execute_scan(["-sn", "-v", "-T4"], args.targets)
        success(f"Stage 1 Complete: {len(first_live)} live, {len(first_down)} down")

        # ================= STAGE 2 =================
        second_live = set()
        still_down = set(first_down)

        if first_down:
            info(f"STAGE 2: Running TCP/UDP Ping on {len(first_down)} down hosts")
            print(style_text(f"TCP Ports: {args.tcp_ports} | UDP Ports: {args.udp_ports}", LIGHT_GOLD))
            print(style_text("Hint: Press <Enter> or <Space> while it runs to see progress percentage.", LIGHT_GOLD))
            
            second_live, second_down = execute_scan(
                ["-sn", "-v", "-T4", f"-PS{args.tcp_ports}", f"-PU{args.udp_ports}"], 
                sorted(first_down, key=host_sort_key)
            )
            
            # The hosts that are STILL down are the ones that were down in stage 1, and didn't come up in stage 2
            still_down = set(first_down) - set(second_live)
            success(f"Stage 2 Complete: {len(second_live)} additional hosts recovered")
        else:
            info("No down hosts found in Stage 1. Skipping Stage 2.")

        # ================= RESULTS =================
        all_live = set(first_live).union(second_live)
        sorted_live = sorted(all_live, key=host_sort_key)
        sorted_down = sorted(still_down - all_live, key=host_sort_key)

        info("Saving Results...")
        save_hosts(LIVE_OUTPUT_FILE, sorted_live)
        save_hosts(DOWN_OUTPUT_FILE, sorted_down)

        success(f"Saved {len(sorted_live)} live hosts to {LIVE_OUTPUT_FILE}")
        success(f"Saved {len(sorted_down)} down hosts to {DOWN_OUTPUT_FILE}")
        return 0

    except KeyboardInterrupt:
        failure("\nOperation cancelled by user.")
        return 130
    except Exception as exc:
        failure(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())