#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VIBETRACK OSINT V2
A lightweight, Termux-friendly toolkit for IP, DNS, HTTP and basic
security checks on systems you own or are authorized to assess.

Install:
    pkg update && pkg install python
    pip install -r requirements.txt
Run:
    python ip_recon_v2.py
"""

import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    import requests
except ImportError:
    print("\n[!] Missing dependency: requests")
    print("    Install it with: pip install requests")
    sys.exit(1)


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich import box as rich_box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

def ui_print(message="", style=None):
    """Print through Rich when installed; otherwise use standard terminal output."""
    if RICH_AVAILABLE:
        console.print(message, style=style)
    else:
        print(message)

def animated_wait(label="Working", seconds=1.0):
    """Short, non-blocking-style visual feedback; no network action is implied."""
    if RICH_AVAILABLE:
        import time as _time
        with console.status(f"[bold cyan]{label}...[/]", spinner="dots"):
            _time.sleep(seconds)
    else:
        print(f"[*] {label}...")
        time.sleep(seconds)

def show_result_table(title, rows):
    if RICH_AVAILABLE:
        table = Table(title=title, box=rich_box.ROUNDED, header_style="bold cyan")
        table.add_column("FIELD", style="green")
        table.add_column("RESULT", style="white", overflow="fold")
        for key, value in rows:
            table.add_row(str(key), str(value))
        console.print(table)
    else:
        print("\\n" + title)
        for key, value in rows:
            print(f"{key:<18}: {value}")

APP_NAME = "VIBETRACK OSINT"
VERSION = "1.0"
LOG_FILE = Path("ip_recon_history.json")
TIMEOUT = 8
MAX_HISTORY = 200

# ANSI colors (disable with NO_COLOR=1)
if os.environ.get("NO_COLOR"):
    R = G = Y = C = M = W = BOLD = END = ""
else:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    C = "\033[96m"
    M = "\033[95m"
    W = "\033[97m"
    BOLD = "\033[1m"
    END = "\033[0m"

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "VibeTrack-OSINT/1.0 (authorized security diagnostics)"
})

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 445, 587,
    993, 995, 1433, 3306, 3389, 5432, 8080, 8443, 9000, 10000
]

LOGIN_PATHS = [
    "/login", "/admin", "/admin/login", "/wp-login.php",
    "/wp-admin", "/administrator", "/user/login", "/dashboard"
]


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    clear_screen()
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold bright_cyan]VIBETRACK OSINT[/bold bright_cyan]\n"
            "[bold white]NETWORK INTELLIGENCE • DNS • WEB SECURITY[/bold white]\n"
            "[green]Developer: darkvibez456[/green]  [yellow]Version: 1.0[/yellow]",
            border_style="bright_cyan",
            padding=(1, 4)
        ))
        console.print("[yellow]WARNING:[/] Use network checks only on systems you own or are authorized to assess. No permission phrase is required.")
    else:
        print(f"""{C}{BOLD}
╔══════════════════════════════════════════════════════╗
║                   VIBETRACK OSINT                     ║
║       NETWORK INTELLIGENCE • DNS • WEB SECURITY      ║
║                    VERSION 1.0                       ║
╚══════════════════════════════════════════════════════╝
{END}
 Developer : darkvibez456
 Mode      : Authorized diagnostics only
 WARNING   : Use only on systems you own or have permission to test
""")


def pause():
    input(f"\n{Y}Press Enter to continue...{END}")


def print_line():
    print(C + "─" * 58 + END)


def record_history(kind, target, result):
    """Store a compact, JSON-safe audit record."""
    try:
        history = []
        if LOG_FILE.exists():
            try:
                loaded = json.loads(LOG_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    history = loaded
            except (json.JSONDecodeError, OSError):
                history = []

        history.insert(0, {
            "time": datetime.now().astimezone().isoformat(timespec="seconds"),
            "type": kind,
            "target": str(target),
            "result": result,
        })
        LOG_FILE.write_text(
            json.dumps(history[:MAX_HISTORY], indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except OSError as exc:
        print(f"{Y}[!] Could not save history: {exc}{END}")


def valid_ip(value):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def normalize_url(value):
    """Return a safe HTTP(S) URL, adding https:// when no scheme is supplied."""
    value = value.strip()
    if not value:
        raise ValueError("URL/domain cannot be empty.")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parts.hostname:
        raise ValueError("Invalid URL or domain.")
    if parts.username or parts.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def normalize_host(value):
    """Accept a hostname or IP only; reject URL paths and explicit ports."""
    value = value.strip()
    if not value or "://" in value or "/" in value or " " in value:
        raise ValueError("Enter only a hostname or IP address (no scheme/path).")
    ip_obj = valid_ip(value)
    if ip_obj:
        return str(ip_obj)
    if ":" in value:
        raise ValueError("Do not include a port. Enter only the hostname or IP.")
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}\.?$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?",
        value
    ):
        raise ValueError("Invalid hostname.")
    return value.rstrip(".").lower()


def request_json(url):
    response = SESSION.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def ip_lookup():
    raw = input(f"{G}Enter public IP address: {W}").strip()
    ip_obj = valid_ip(raw)
    if not ip_obj:
        print(f"{R}[!] Invalid IP address.{END}")
        pause()
        return
    if not ip_obj.is_global:
        print(f"{Y}[!] This is not a public global IP. Public geolocation APIs may not return useful data.{END}")
    animated_wait("Fetching IP intelligence", 0.5)
    data = None
    try:
        data = request_json(f"https://ipwho.is/{ip_obj}")
        if not data.get("success", False):
            data = None
    except (requests.RequestException, ValueError):
        data = None

    if data is None:
        try:
            fallback = request_json(f"https://ipapi.co/{ip_obj}/json/")
            if not fallback.get("error"):
                data = {
                    "ip": fallback.get("ip"),
                    "type": fallback.get("version"),
                    "continent": fallback.get("continent_code"),
                    "country": fallback.get("country_name"),
                    "region": fallback.get("region"),
                    "city": fallback.get("city"),
                    "postal": fallback.get("postal"),
                    "latitude": fallback.get("latitude"),
                    "longitude": fallback.get("longitude"),
                    "timezone": {"id": fallback.get("timezone")},
                    "connection": {
                        "isp": fallback.get("org"),
                        "asn": fallback.get("asn"),
                    },
                }
        except (requests.RequestException, ValueError):
            data = None

    if not data:
        print(f"{R}[!] IP lookup providers did not return data.{END}")
        pause()
        return

    connection = data.get("connection") or {}
    timezone_data = data.get("timezone") or {}
    fields = {
        "IP": data.get("ip") or str(ip_obj),
        "Type": data.get("type"),
        "Continent": data.get("continent"),
        "Country": data.get("country"),
        "Region": data.get("region"),
        "City": data.get("city"),
        "Postal": data.get("postal"),
        "Latitude": data.get("latitude"),
        "Longitude": data.get("longitude"),
        "Timezone": timezone_data.get("id") if isinstance(timezone_data, dict) else timezone_data,
        "ISP": connection.get("isp"),
        "Organization": connection.get("org"),
        "ASN": connection.get("asn"),
        "Proxy": data.get("security", {}).get("proxy") if isinstance(data.get("security"), dict) else None,
        "Hosting": data.get("security", {}).get("hosting") if isinstance(data.get("security"), dict) else None,
    }
    print_line()
    print(f"{BOLD}{C}IP INTELLIGENCE{END}")
    for key, value in fields.items():
        if value not in (None, "", []):
            print(f"{G}{key:<15}{W}: {value}")
    print_line()
    record_history("IP lookup", str(ip_obj), fields)
    pause()


def website_status():
    try:
        url = normalize_url(input(f"{G}Enter website URL/domain: {W}"))
        animated_wait("Checking website response", 0.4)
        try:
            response = SESSION.head(url, timeout=TIMEOUT, allow_redirects=True)
            if response.status_code in (405, 501):
                response = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
            result = {
                "final_url": response.url,
                "status_code": response.status_code,
                "reason": response.reason,
                "elapsed_seconds": round(response.elapsed.total_seconds(), 3),
            }
            print(f"\n{G}[+] Website responded{END}")
            print(f"Status      : {response.status_code} {response.reason}")
            print(f"Final URL   : {response.url}")
            print(f"Response    : {result['elapsed_seconds']} seconds")
            response.close()
            record_history("Website status", url, result)
        except requests.RequestException as exc:
            print(f"{R}[!] Request failed: {exc}{END}")
    except ValueError as exc:
        print(f"{R}[!] {exc}{END}")
    pause()


def dns_lookup():
    try:
        host = normalize_host(input(f"{G}Enter domain or hostname: {W}"))
        animated_wait(f"Resolving {host}", 0.4)
        results = {"A/AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}

        try:
            for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                address = item[4][0]
                if address not in results["A/AAAA"]:
                    results["A/AAAA"].append(address)
        except socket.gaierror as exc:
            print(f"{Y}[!] Basic DNS resolution: {exc}{END}")

        try:
            import dns.resolver  # Optional dependency: dnspython
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 4
            for record_type in ("MX", "NS", "TXT", "CNAME"):
                try:
                    answers = resolver.resolve(host, record_type)
                    results[record_type] = [str(answer) for answer in answers]
                except Exception:
                    results[record_type] = []
        except ImportError:
            print(f"{Y}[i] Install dnspython for MX/NS/TXT/CNAME: pip install dnspython{END}")

        print_line()
        print(f"{BOLD}{C}DNS RESULTS{END}")
        for record_type, values in results.items():
            print(f"\n{G}{record_type}:{END}")
            if values:
                for value in values:
                    print("  " + value)
            else:
                print("  No record returned")
        print_line()
        record_history("DNS lookup", host, results)
    except ValueError as exc:
        print(f"{R}[!] {exc}{END}")
    pause()


def port_scan():
    try:
        host = normalize_host(input(f"{G}Enter one authorized host/IP: {W}"))
    except ValueError as exc:
        print(f"{R}[!] {exc}{END}")
        pause()
        return


    print("\nDefault ports:")
    print(", ".join(str(port) for port in COMMON_PORTS))
    custom = input("Enter custom comma-separated ports, or press Enter for defaults: ").strip()
    if custom:
        try:
            ports = sorted(set(int(item.strip()) for item in custom.split(",")))
            if not ports or len(ports) > 50 or any(port < 1 or port > 65535 for port in ports):
                raise ValueError
        except ValueError:
            print(f"{R}[!] Enter 1-50 valid ports (1-65535).{END}")
            pause()
            return
    else:
        ports = COMMON_PORTS[:]

    print(f"\n{Y}[WARNING] Scan only systems you own or are authorized to test.{END}")
    print(f"{Y}[*] Checking {len(ports)} TCP ports on {host} (one host only)...{END}")
    opened = []
    try:
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=1.2):
                    opened.append(port)
                    print(f"{G}[OPEN] {port}{END}")
            except (OSError, socket.timeout):
                print(f"{R}[CLOSED/FILTERED] {port}{END}")
            time.sleep(0.15)  # conservative request rate
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Scan stopped by user.{END}")

    result = {"checked_ports": ports, "open_ports": opened}
    show_result_table("TCP PORT CHECK RESULTS", [("Target", host), ("Open ports", ", ".join(map(str, opened)) or "None detected"), ("Count", len(opened))])
    record_history("Authorized TCP port check", host, result)
    pause()


def ssl_certificate_check():
    try:
        host = normalize_host(input(f"{G}Enter hostname (no https://): {W}"))
        context = ssl.create_default_context()
        animated_wait(f"Checking TLS certificate for {host}:443", 0.5)
        with socket.create_connection((host, 443), timeout=TIMEOUT) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()

        expiry_text = cert.get("notAfter")
        expiry = datetime.strptime(expiry_text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if expiry_text else None
        now = datetime.now(timezone.utc)
        days_left = (expiry - now).days if expiry else None
        sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]

        print_line()
        print(f"{BOLD}{C}TLS CERTIFICATE{END}")
        print(f"Hostname       : {host}")
        print(f"Issuer         : {cert.get('issuer')}")
        print(f"Valid from     : {cert.get('notBefore')}")
        print(f"Expires        : {expiry_text}")
        print(f"Days remaining : {days_left}")
        print(f"Subject names  : {', '.join(sans[:12]) if sans else 'Not listed'}")
        print_line()
        record_history("TLS certificate", host, {
            "issuer": str(cert.get("issuer")),
            "not_before": cert.get("notBefore"),
            "not_after": expiry_text,
            "days_remaining": days_left,
            "subject_alt_names": sans,
        })
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"{R}[!] TLS check failed: {exc}{END}")
    pause()


def http_headers_check(security_only=False):
    try:
        url = normalize_url(input(f"{G}Enter authorized website URL: {W}"))
        response = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
        headers = dict(response.headers)
        print_line()
        print(f"{BOLD}{C}{'SECURITY HEADERS' if security_only else 'HTTP RESPONSE HEADERS'}{END}")
        print(f"Final URL : {response.url}")
        print(f"Status    : {response.status_code} {response.reason}")
        if security_only:
            for header in SECURITY_HEADERS:
                value = headers.get(header)
                if value:
                    print(f"{G}[PRESENT] {header}: {value}{END}")
                else:
                    print(f"{R}[MISSING] {header}{END}")
            if urlsplit(url).scheme == "https" and not headers.get("Strict-Transport-Security"):
                print(f"{Y}[!] HSTS is missing on the requested HTTPS URL.{END}")
        else:
            for key, value in headers.items():
                print(f"{G}{key}{W}: {value}")
        print_line()
        record_history("Security headers" if security_only else "HTTP headers", url, {
            "status_code": response.status_code,
            "final_url": response.url,
            "headers": headers,
        })
        response.close()
    except (ValueError, requests.RequestException) as exc:
        print(f"{R}[!] Header check failed: {exc}{END}")
    pause()


def rdap_lookup():
    try:
        domain = normalize_host(input(f"{G}Enter domain (example.com): {W}"))
        if valid_ip(domain):
            raise ValueError("Enter a domain name, not an IP address.")
        animated_wait("Querying public RDAP data", 0.5)
        response = SESSION.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()

        events = {}
        for event in data.get("events", []):
            events[event.get("eventAction", "event")] = event.get("eventDate")
        nameservers = [
            item.get("ldhName") for item in data.get("nameservers", [])
            if item.get("ldhName")
        ]
        statuses = data.get("status", [])

        print_line()
        print(f"{BOLD}{C}DOMAIN RDAP INFORMATION{END}")
        print(f"Domain       : {data.get('ldhName', domain)}")
        print(f"Handle       : {data.get('handle', 'N/A')}")
        print(f"Status       : {', '.join(statuses) if statuses else 'N/A'}")
        print(f"Registered   : {events.get('registration', 'N/A')}")
        print(f"Updated      : {events.get('last changed', 'N/A')}")
        print(f"Expires      : {events.get('expiration', 'N/A')}")
        print(f"Nameservers  : {', '.join(nameservers) if nameservers else 'N/A'}")
        print_line()
        record_history("Domain RDAP", domain, {
            "status": statuses, "events": events, "nameservers": nameservers
        })
    except (ValueError, requests.RequestException) as exc:
        print(f"{R}[!] RDAP lookup failed: {exc}{END}")
    pause()


def ip_calculator():
    raw = input(f"{G}Enter IP/CIDR (example 192.168.1.10/24): {W}").strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
        print_line()
        print(f"{BOLD}{C}IP / SUBNET CALCULATOR{END}")
        print(f"Network       : {network}")
        print(f"IP version    : IPv{network.version}")
        print(f"Network addr  : {network.network_address}")
        print(f"Prefix length : /{network.prefixlen}")
        print(f"Netmask       : {network.netmask}")
        if network.version == 4:
            print(f"Broadcast     : {network.broadcast_address}")
            print(f"Usable hosts  : {max(network.num_addresses - 2, 0)}")
        else:
            print(f"Total addresses: {network.num_addresses}")
        print_line()
        record_history("IP calculator", raw, {
            "network": str(network),
            "version": network.version,
            "network_address": str(network.network_address),
            "prefix": network.prefixlen,
            "netmask": str(network.netmask),
        })
    except ValueError as exc:
        print(f"{R}[!] Invalid IP/CIDR: {exc}{END}")
    pause()


def admin_panel_finder():
    """
    Check a short, fixed list of common web admin/login routes on one
    explicitly authorized website. This is discovery only, not exploitation.
    """
    try:
        url = normalize_url(input(f"{G}Enter your authorized website URL: {W}"))
    except ValueError as exc:
        print(f"{R}[!] {exc}{END}")
        pause()
        return


    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"

    admin_paths = [
        "/admin", "/admin/", "/admin/login", "/admin/dashboard",
        "/administrator", "/administrator/", "/adminpanel",
        "/admin-panel", "/login", "/login/", "/signin",
        "/sign-in", "/dashboard", "/controlpanel", "/control-panel",
        "/user/login", "/account/login", "/auth/login",
        "/wp-admin", "/wp-login.php", "/administrator/index.php",
        "/admin.php", "/admin.html", "/admin/index.php",
        "/panel", "/manage", "/manager", "/siteadmin",
    ]

    print(f"\n{Y}[WARNING] Check only websites you own or are authorized to assess.{END}")
    print(f"{Y}[*] Checking {len(admin_paths)} common routes on {base}{END}")
    print(f"{Y}[i] One website only; no port sweep, brute force, or login attempts.{END}")

    findings = []
    try:
        for path in admin_paths:
            response = None
            try:
                response = SESSION.get(
                    base + path,
                    timeout=5,
                    allow_redirects=False,
                    headers={"Accept": "text/html"},
                    stream=True,
                )
                status = response.status_code
                location = response.headers.get("Location", "")
                content_type = response.headers.get("Content-Type", "")
                sample = ""
                if "text" in content_type.lower() or "html" in content_type.lower():
                    try:
                        sample = response.raw.read(65536, decode_content=True).decode(
                            response.encoding or "utf-8", errors="replace"
                        ).lower()
                    except Exception:
                        sample = ""

                login_markers = (
                    "login", "log in", "username", "password",
                    "sign in", "administrator", "dashboard"
                )

                if status == 200 and any(marker in sample for marker in login_markers):
                    label = "POSSIBLE LOGIN/ADMIN PAGE"
                    color = G
                elif status == 401:
                    label = "AUTHENTICATION REQUIRED"
                    color = M
                elif status == 403:
                    label = "ACCESS RESTRICTED"
                    color = Y
                elif status in (301, 302, 303, 307, 308) and any(
                    word in location.lower() for word in ("login", "admin", "signin")
                ):
                    label = "LOGIN/ADMIN REDIRECT"
                    color = C
                elif status == 200:
                    label = "HTTP 200 - REVIEW MANUALLY"
                    color = Y
                else:
                    label = f"HTTP {status}"
                    color = W

                if status in (200, 301, 302, 303, 307, 308, 401, 403):
                    finding = {
                        "path": path,
                        "status": status,
                        "classification": label,
                        "location": location,
                    }
                    findings.append(finding)
                    suffix = f" -> {location}" if location else ""
                    print(f"{color}[{label}] {path} (HTTP {status}){suffix}{END}")

            except requests.RequestException:
                # Do not print a line for every unreachable route.
                pass
            finally:
                if response is not None:
                    response.close()
            time.sleep(0.35)

    except KeyboardInterrupt:
        print(f"\n{Y}[!] Check stopped by user.{END}")

    show_result_table("ADMIN ROUTE DISCOVERY", [("Target", url), ("Notable responses", len(findings)), ("Paths", ", ".join(item["path"] for item in findings) or "None detected")])
    print(
        f"{Y}[i] A status code alone does not prove an admin panel exists. "
        f"Open findings manually and verify ownership/access.{END}"
    )
    record_history("Authorized admin panel route discovery", url, findings)
    pause()


def network_diagnostics():
    try:
        host = normalize_host(input(f"{G}Enter hostname/IP to resolve: {W}"))
        started = time.perf_counter()
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        addresses = sorted({item[4][0] for item in infos})
        print_line()
        print(f"{BOLD}{C}NETWORK DIAGNOSTICS{END}")
        print(f"Host          : {host}")
        print(f"DNS time      : {elapsed_ms} ms")
        print("Resolved IPs  :")
        for address in addresses:
            print(f"  - {address}")
        print_line()
        record_history("Network diagnostics", host, {
            "dns_time_ms": elapsed_ms, "addresses": addresses
        })
    except (ValueError, socket.gaierror) as exc:
        print(f"{R}[!] Network diagnostic failed: {exc}{END}")
    pause()


def user_agent_generator():
    agents = [
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]
    import random
    agent = random.choice(agents)
    print(f"\n{C}Generated User-Agent:{END}\n{agent}")
    record_history("User-Agent generator", "local", {"user_agent": agent})
    pause()


def show_history():
    if not LOG_FILE.exists():
        print(f"{Y}[i] No history found yet.{END}")
        pause()
        return
    try:
        history = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        print_line()
        print(f"{BOLD}{C}RECENT SCAN HISTORY{END}")
        for index, item in enumerate(history[:20], 1):
            print(f"{G}{index:>2}.{END} [{item.get('time', 'N/A')}] "
                  f"{item.get('type', 'Unknown')} - {item.get('target', 'N/A')}")
        print_line()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{R}[!] Could not read history: {exc}{END}")
    pause()


def export_history():
    if not LOG_FILE.exists():
        print(f"{Y}[i] No history to export.{END}")
        pause()
        return
    try:
        history = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        if not history:
            print(f"{Y}[i] History is empty.{END}")
            pause()
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        print("1. JSON\n2. CSV\n3. TXT")
        choice = input(f"{G}Choose export format: {W}").strip()
        if choice == "1":
            filename = f"dark_vibez_report_{stamp}.json"
            Path(filename).write_text(
                json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        elif choice == "2":
            filename = f"dark_vibez_report_{stamp}.csv"
            with open(filename, "w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=["time", "type", "target", "result"])
                writer.writeheader()
                for item in history:
                    writer.writerow(item)
        elif choice == "3":
            filename = f"dark_vibez_report_{stamp}.txt"
            lines = []
            for item in history:
                lines.append(
                    f"Time: {item.get('time')}\nType: {item.get('type')}\n"
                    f"Target: {item.get('target')}\nResult: "
                    f"{json.dumps(item.get('result'), ensure_ascii=False)}\n"
                    + "-" * 55
                )
            Path(filename).write_text("\n".join(lines), encoding="utf-8")
        else:
            print(f"{R}[!] Invalid choice.{END}")
            pause()
            return
        print(f"{G}[+] Exported: {filename}{END}")
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{R}[!] Export failed: {exc}{END}")
    pause()


def main():
    menu = [
        ("1", "IP Intelligence Lookup"),
        ("2", "Website Status Check"),
        ("3", "DNS Record Lookup"),
        ("4", "TCP Port Check (Single Host)"),
        ("5", "SSL/TLS Certificate Check"),
        ("6", "HTTP Response Headers"),
        ("7", "Website Security Headers Audit"),
        ("8", "Domain RDAP / WHOIS-style Lookup"),
        ("9", "IP & Subnet Calculator"),
        ("10", "Admin Panel Finder (Authorized)"),
        ("11", "Network DNS Diagnostics"),
        ("12", "Random User-Agent Generator"),
        ("13", "View Scan History"),
        ("14", "Export Reports (JSON/CSV/TXT)"),
        ("0", "Exit"),
    ]

    while True:
        banner()
        print(f"{Y}WARNING: Use scans only on systems you own or are authorized to assess.{END}")
        if RICH_AVAILABLE:
            menu_table = Table(title="MAIN MENU", box=rich_box.SIMPLE_HEAVY, header_style="bold cyan")
            menu_table.add_column("NO.", style="bold green", width=5)
            menu_table.add_column("MODULE", style="white")
            for number, label in menu:
                menu_table.add_row(number, label)
            console.print(menu_table)
        else:
            print(f"{BOLD}{C}MAIN MENU{END}")
            for number, label in menu:
                print(f" {G}{number:>2}{END}  {label}")

        print_line()
        choice = input(f"{G}Select option: {W}").strip()

        actions = {
            "1": ip_lookup,
            "2": website_status,
            "3": dns_lookup,
            "4": port_scan,
            "5": ssl_certificate_check,
            "6": lambda: http_headers_check(False),
            "7": lambda: http_headers_check(True),
            "8": rdap_lookup,
            "9": ip_calculator,
            "10": admin_panel_finder,
            "11": network_diagnostics,
            "12": user_agent_generator,
            "13": show_history,
            "14": export_history,
        }
        if choice == "0":
            print(f"{Y}Exiting VIBETRACK OSINT. Stay ethical!{END}")
            break
        action = actions.get(choice)
        if action:
            action()
        else:
            print(f"{R}[!] Invalid option.{END}")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}Interrupted. Exiting safely.{END}")
