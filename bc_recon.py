#!/usr/bin/env python3

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import socket
import ssl
import sys
import urllib.request
import urllib.error
from pathlib import Path


MAX_WORKERS = 64
TIMEOUT = 2


# -----------------------------
# 1. Parse Port Range
# -----------------------------

def parse_ports(value):
    ports = set()

    try:
        for part in value.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))

        if not ports or any(p < 1 or p > 65535 for p in ports):
            raise ValueError

        return sorted(ports)

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Example: 22,80,443,8000-8010"
        )


# -----------------------------
# 2. Load Allowlist
# -----------------------------

def load_allowlist(filename):
    entries = []

    with open(filename, "r") as file:
        for line in file:
            line = line.split("#")[0].strip()

            if not line:
                continue

            try:
                entries.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                entries.append(line.lower().rstrip("."))

    if not entries:
        raise ValueError("Allowlist is empty")

    return entries


# -----------------------------
# 3. Resolve Target
# -----------------------------

def resolve_target(target):
    try:
        ipaddress.ip_address(target)
        return [target]

    except ValueError:
        results = socket.getaddrinfo(
            target, None, type=socket.SOCK_STREAM
        )

        return sorted({item[4][0] for item in results})


# -----------------------------
# 4. Scope Verification
# -----------------------------

def check_scope(target, addresses, allowlist):

    if target.lower().rstrip(".") in allowlist:
        return True

    networks = [
        item for item in allowlist
        if not isinstance(item, str)
    ]

    for address in addresses:
        ip = ipaddress.ip_address(address)

        allowed = any(
            ip.version == network.version and ip in network
            for network in networks
        )

        if not allowed:
            raise PermissionError(
                f"Scope check failed: {address} is not allowlisted"
            )

    return True


# -----------------------------
# 5. Banner Grabbing
# -----------------------------

def grab_banner(sock):

    sock.settimeout(1)

    try:
        banner = sock.recv(1024)
        return banner.decode(errors="replace").strip()

    except (socket.timeout, OSError):
        return ""


# -----------------------------
# 6. Port Scanning
# -----------------------------

def scan_port(address, port):

    result = {
        "address": address,
        "port": port,
        "state": "closed_or_filtered",
        "banner": ""
    }

    family = (
        socket.AF_INET6 if ":" in address
        else socket.AF_INET
    )

    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        connection = sock.connect_ex((address, port))

        if connection == 0:
            result["state"] = "open"
            result["banner"] = grab_banner(sock)

    except OSError as error:
        result["error"] = str(error)

    finally:
        sock.close()

    return result


# -----------------------------
# 7. HTTP Header Audit
# -----------------------------

def header_audit(target, port):

    scheme = "https" if port == 443 else "http"

    url = f"{scheme}://{target}:{port}/"

    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "bc-recon/1.0"}
    )

    try:
        context = ssl.create_default_context()

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )

        with opener.open(request, timeout=3) as response:
            status = response.status
            headers = dict(response.headers.items())

    except urllib.error.HTTPError as error:
        status = error.code
        headers = dict(error.headers.items())

    except Exception as error:
        return {
            "port": port,
            "error": str(error)
        }

    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy"
    ]

    return {
        "port": port,
        "status": status,
        "headers": {
            key: headers[key]
            for key in security_headers
            if key in headers
        }
    }


# -----------------------------
# 8. Save JSON Report
# -----------------------------

def save_report(filename, run):

    path = Path(filename)

    if path.exists():
        with open(path, "r") as file:
            report = json.load(file)
    else:
        report = {
            "tool": "bc-recon",
            "runs": []
        }

    report["runs"].append(run)

    with open(path, "w") as file:
        json.dump(report, file, indent=4)


# -----------------------------
# 9. Main Function
# -----------------------------

def main():

    parser = argparse.ArgumentParser(
        description="BC Recon - Mini Reconnaissance Tool"
    )

    parser.add_argument(
        "target",
        help="Target IP or hostname"
    )

    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=parse_ports("21,22,80,443,8080"),
        help="Port range"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="report.json",
        help="Output JSON file"
    )

    parser.add_argument(
        "--allowlist",
        required=True,
        help="Authorized targets file"
    )

    args = parser.parse_args()

    # Scope check BEFORE network scanning

    try:
        allowlist = load_allowlist(args.allowlist)

        addresses = resolve_target(args.target)

        check_scope(
            args.target,
            addresses,
            allowlist
        )

    except Exception as error:
        print(f"[!] Scope verification failed: {error}")
        return

    print(f"\n[+] Target: {args.target}")
    print(f"[+] Resolved IPs: {addresses}")
    print("[+] Scope approved\n")

    # Threaded port scanning

    all_results = []

    for address in addresses:

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = [
                executor.submit(scan_port, address, port)
                for port in args.ports
            ]

            for future in concurrent.futures.as_completed(futures):

                result = future.result()
                all_results.append(result)

                if result["state"] == "open":
                    print(
                        f"[OPEN] {address}:{result['port']}"
                    )

                    if result["banner"]:
                        print(f"       Banner: {result['banner']}")

    # HTTP Header Audit

    header_results = []

    for result in all_results:

        if (
            result["state"] == "open"
            and result["port"] in [80, 443, 8080]
        ):

            print(
                f"\n[*] Auditing HTTP headers on port {result['port']}"
            )

            header_results.append(
                header_audit(args.target, result["port"])
            )

    # Create report

    run = {
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),

        "target": args.target,

        "resolved_addresses": addresses,

        "ports_scanned": args.ports,

        "scan_results": all_results,

        "http_header_audit": header_results
    }

    try:
        save_report(args.output, run)

        print(f"\n[+] Report saved to {args.output}")

    except (OSError, json.JSONDecodeError) as error:
        print(f"[!] Could not save report: {error}")


if __name__ == "__main__":
    main()
