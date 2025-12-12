#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
"""
DataCore REST API Debug Script (Extended Version)

This script helps diagnose connection and API issues when connecting to
the DataCore SANsymphony REST API.

Tests performed:
- Network connectivity (DNS, TCP port)
- SSL/TLS handshake and certificate details
- REST API endpoints (v1.0 and v2.0) with ServerHost header
- ServerHost header variations
- Available servers listing

Usage:
    python3 debug_datacore_api.py --host 192.168.1.1 --user administrator --password SECRET --nodename ssv-node1
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import sys
import time
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

# Check for required modules
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("WARNING: urllib3 not found, SSL warnings may appear")

try:
    import requests
    REQUESTS_VERSION = requests.__version__
except ImportError:
    print("ERROR: 'requests' module not found. Install with: pip install requests")
    sys.exit(1)


# =============================================================================
# Helper Classes and Functions
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @classmethod
    def disable(cls):
        """Disable colors for non-terminal output."""
        cls.GREEN = cls.RED = cls.YELLOW = cls.BLUE = cls.CYAN = cls.BOLD = cls.END = ''


def ok(msg):
    # type: (str) -> str
    return "{GREEN}✓ {msg}{END}".format(GREEN=Colors.GREEN, msg=msg, END=Colors.END)


def fail(msg):
    # type: (str) -> str
    return "{RED}✗ {msg}{END}".format(RED=Colors.RED, msg=msg, END=Colors.END)


def warn(msg):
    # type: (str) -> str
    return "{YELLOW}⚠ {msg}{END}".format(YELLOW=Colors.YELLOW, msg=msg, END=Colors.END)


def info(msg):
    # type: (str) -> str
    return "{BLUE}ℹ {msg}{END}".format(BLUE=Colors.BLUE, msg=msg, END=Colors.END)


def print_header(title):
    # type: (str) -> None
    """Print a section header."""
    print("\n{BOLD}{line}".format(BOLD=Colors.BOLD, line="=" * 70))
    print("  {title}".format(title=title))
    print("{line}{END}".format(line="=" * 70, END=Colors.END))


def print_subheader(title):
    # type: (str) -> None
    """Print a subsection header."""
    print("\n{CYAN}--- {title} ---{END}".format(CYAN=Colors.CYAN, title=title, END=Colors.END))


# =============================================================================
# Test Functions
# =============================================================================

class TestResults:
    """Collect and summarize test results."""

    def __init__(self):
        self.results = []  # type: List[Tuple[str, str, str]]
        self.details = {}  # type: Dict[str, Any]

    def add(self, category, test_name, passed, detail=""):
        # type: (str, str, bool, str) -> None
        status = "PASS" if passed else "FAIL"
        self.results.append((category, test_name, status))
        if detail:
            self.details["{cat}:{test}".format(cat=category, test=test_name)] = detail

    def add_warning(self, category, test_name, detail=""):
        # type: (str, str, str) -> None
        self.results.append((category, test_name, "WARN"))
        if detail:
            self.details["{cat}:{test}".format(cat=category, test=test_name)] = detail

    def print_summary(self):
        # type: () -> None
        print_header("TEST SUMMARY")

        current_category = ""
        for category, test_name, status in self.results:
            if category != current_category:
                print("\n{BOLD}{cat}:{END}".format(BOLD=Colors.BOLD, cat=category, END=Colors.END))
                current_category = category

            if status == "PASS":
                print("  {result}".format(result=ok(test_name)))
            elif status == "FAIL":
                print("  {result}".format(result=fail(test_name)))
            else:
                print("  {result}".format(result=warn(test_name)))

        # Count results
        passed = sum(1 for _, _, s in self.results if s == "PASS")
        failed = sum(1 for _, _, s in self.results if s == "FAIL")
        warnings = sum(1 for _, _, s in self.results if s == "WARN")

        print("\n{BOLD}Total: {p} passed, {f} failed, {w} warnings{END}".format(
            BOLD=Colors.BOLD, p=passed, f=failed, w=warnings, END=Colors.END))


def test_dns_resolution(host, results):
    # type: (str, TestResults) -> Optional[str]
    """Test DNS resolution for hostname."""
    print_subheader("DNS Resolution")

    # Check if host is already an IP
    try:
        socket.inet_aton(host)
        print(info("Host '{host}' is already an IP address".format(host=host)))
        results.add("Network", "DNS Resolution", True, "IP address provided")
        return host
    except socket.error:
        pass

    # Try to resolve hostname
    try:
        ip = socket.gethostbyname(host)
        print(ok("Resolved '{host}' to {ip}".format(host=host, ip=ip)))
        results.add("Network", "DNS Resolution", True, "Resolved to {ip}".format(ip=ip))
        return ip
    except socket.gaierror as e:
        print(fail("DNS resolution failed for '{host}': {e}".format(host=host, e=e)))
        results.add("Network", "DNS Resolution", False, str(e))
        return None


def test_tcp_connection(host, port, results):
    # type: (str, int, TestResults) -> bool
    """Test TCP connection to host:port."""
    print_subheader("TCP Connection (Port {port})".format(port=port))

    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()

        if result == 0:
            print(ok("Port {port} is open (connected in {elapsed:.1f}ms)".format(port=port, elapsed=elapsed)))
            results.add("Network", "TCP Port {port}".format(port=port), True, "{elapsed:.1f}ms".format(elapsed=elapsed))
            return True
        else:
            print(fail("Port {port} is closed or filtered".format(port=port)))
            results.add("Network", "TCP Port {port}".format(port=port), False, "Connection refused")
            return False
    except socket.timeout:
        print(fail("Connection to port {port} timed out".format(port=port)))
        results.add("Network", "TCP Port {port}".format(port=port), False, "Timeout")
        return False
    except Exception as e:
        print(fail("Connection error: {e}".format(e=e)))
        results.add("Network", "TCP Port {port}".format(port=port), False, str(e))
        return False


def test_ssl_certificate(host, port, results):
    # type: (str, int, TestResults) -> Dict[str, Any]
    """Test SSL/TLS connection and get certificate details."""
    print_subheader("SSL/TLS Certificate")

    cert_info = {}  # type: Dict[str, Any]

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse certificate using ssl
                cert_decoded = ssl.DER_cert_to_PEM_cert(cert)

                print(ok("SSL/TLS Handshake successful"))
                print("    Protocol: {version}".format(version=version))
                print("    Cipher: {cipher} ({bits} bits)".format(cipher=cipher[0], bits=cipher[2]))

                cert_info['protocol'] = version
                cert_info['cipher'] = cipher[0]
                cert_info['bits'] = cipher[2]

                # Try to get more cert details
                try:
                    import subprocess
                    proc = subprocess.run(
                        ['openssl', 'x509', '-noout', '-subject', '-issuer', '-dates'],
                        input=cert_decoded.encode(),
                        capture_output=True,
                        timeout=5
                    )
                    if proc.returncode == 0:
                        output = proc.stdout.decode()
                        print("\n    Certificate Details:")
                        for line in output.strip().split('\n'):
                            print("      {line}".format(line=line))
                            if 'subject=' in line.lower():
                                cert_info['subject'] = line.split('=', 1)[1] if '=' in line else line
                            elif 'issuer=' in line.lower():
                                cert_info['issuer'] = line.split('=', 1)[1] if '=' in line else line

                        # Check for self-signed
                        if cert_info.get('subject') == cert_info.get('issuer'):
                            print(warn("Certificate is SELF-SIGNED"))
                            results.add_warning("SSL/TLS", "Certificate", "Self-signed certificate")
                        else:
                            results.add("SSL/TLS", "Certificate", True)
                except Exception:
                    print(info("(Could not parse certificate details - openssl not available)"))
                    results.add("SSL/TLS", "Certificate", True, "Details unavailable")

                results.add("SSL/TLS", "Handshake", True, "{version} / {cipher}".format(version=version, cipher=cipher[0]))
                return cert_info

    except ssl.SSLError as e:
        print(fail("SSL Error: {e}".format(e=e)))
        results.add("SSL/TLS", "Handshake", False, str(e))
        return {}
    except Exception as e:
        print(fail("Connection error: {e}".format(e=e)))
        results.add("SSL/TLS", "Handshake", False, str(e))
        return {}


def test_http_request(
    session,
    url,
    headers,
    test_name,
    results,
    category="API",
    verify_ssl=False,
    show_body_on_success=False,
):
    # type: (requests.Session, str, Dict[str, str], str, TestResults, str, bool, bool) -> Optional[requests.Response]
    """Make an HTTP request and analyze the response."""

    print("\n  Testing: {test_name}".format(test_name=test_name))
    print("  URL: {url}".format(url=url))

    # Show headers (hide password)
    headers_display = {}
    for k, v in headers.items():
        if k.lower() == 'authorization':
            headers_display[k] = 'Basic ***HIDDEN***'
        else:
            headers_display[k] = v
    print("  Headers: {headers}".format(headers=headers_display))

    try:
        start = time.time()
        response = session.get(url, headers=headers, timeout=15, verify=verify_ssl)
        elapsed = (time.time() - start) * 1000

        status_ok = response.status_code == 200

        # Print result
        if status_ok:
            print("  {result}".format(result=ok("Status: {code} ({elapsed:.0f}ms)".format(code=response.status_code, elapsed=elapsed))))
        else:
            print("  {result}".format(result=fail("Status: {code} ({elapsed:.0f}ms)".format(code=response.status_code, elapsed=elapsed))))

        # Show response body for errors or if requested
        if not status_ok or response.status_code >= 400 or show_body_on_success:
            print("  Response Body ({length} bytes):".format(length=len(response.content)))
            try:
                json_resp = response.json()
                print("    {body}".format(body=json.dumps(json_resp, indent=4)))
            except json.JSONDecodeError:
                body = response.text[:500] if response.text else "(empty)"
                print("    {body}".format(body=body))

        results.add(category, test_name, status_ok, "HTTP {code}".format(code=response.status_code))
        return response

    except requests.exceptions.Timeout:
        print("  {result}".format(result=fail("Request timed out")))
        results.add(category, test_name, False, "Timeout")
        return None
    except requests.exceptions.ConnectionError as e:
        print("  {result}".format(result=fail("Connection error: {e}".format(e=e))))
        results.add(category, test_name, False, "Connection error")
        return None
    except Exception as e:
        print("  {result}".format(result=fail("Error: {e}".format(e=e))))
        results.add(category, test_name, False, str(e))
        return None


# =============================================================================
# Main Function
# =============================================================================

def main():
    # type: () -> int
    parser = argparse.ArgumentParser(
        description="Debug DataCore REST API connection issues (Extended Version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 debug_datacore_api.py --host 192.168.1.1 --user admin --password secret --nodename SSV1
    python3 debug_datacore_api.py --host datacore.local --user admin --password secret --nodename Server01 --no-color
        """,
    )
    parser.add_argument("--host", required=True, help="DataCore server IP or hostname")
    parser.add_argument("--user", required=True, help="Username for authentication")
    parser.add_argument("--password", required=True, help="Password for authentication")
    parser.add_argument("--nodename", required=True, help="DataCore server nodename (Caption)")
    parser.add_argument("--proto", default="https", choices=["http", "https"], help="Protocol (default: https)")
    parser.add_argument("--port", type=int, default=None, help="Port (default: 443 for https, 80 for http)")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Determine port
    port = args.port or (443 if args.proto == "https" else 80)

    # Build URLs
    base_url = "{proto}://{host}:{port}/RestService/rest.svc".format(
        proto=args.proto, host=args.host, port=port)

    # Create auth header
    auth_string = "{user}:{password}".format(user=args.user, password=args.password)
    auth_bytes = base64.b64encode(auth_string.encode()).decode()
    auth_header = "Basic {auth}".format(auth=auth_bytes)

    # Standard headers (ServerHost is REQUIRED for DataCore REST API)
    std_headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
        "ServerHost": args.nodename,
    }

    # Create session
    session = requests.Session()
    results = TestResults()

    # =========================================================================
    # HEADER: System Info
    # =========================================================================
    print_header("DataCore REST API Debug Script (Extended)")
    print("  Timestamp: {ts}".format(ts=datetime.now().isoformat()))
    print("  Python: {ver}".format(ver=sys.version.split()[0]))
    print("  Requests: {ver}".format(ver=REQUESTS_VERSION))
    print("  Target: {proto}://{host}:{port}".format(proto=args.proto, host=args.host, port=port))
    print("  User: {user}".format(user=args.user))
    print("  Nodename: {nodename}".format(nodename=args.nodename))

    # =========================================================================
    # TEST 1: Network Connectivity
    # =========================================================================
    print_header("1. NETWORK CONNECTIVITY")

    resolved_ip = test_dns_resolution(args.host, results)
    if not resolved_ip:
        print(fail("\nCannot proceed without DNS resolution"))
        results.print_summary()
        return 1

    tcp_ok = test_tcp_connection(resolved_ip, port, results)
    if not tcp_ok:
        print(fail("\nCannot proceed - port {port} not reachable".format(port=port)))
        results.print_summary()
        return 1

    # =========================================================================
    # TEST 2: SSL/TLS (if https)
    # =========================================================================
    if args.proto == "https":
        print_header("2. SSL/TLS CERTIFICATE")
        test_ssl_certificate(resolved_ip, port, results)
    else:
        print_header("2. SSL/TLS CERTIFICATE")
        print(info("Skipped (using HTTP)"))

    # =========================================================================
    # TEST 3: Authentication (with ServerHost header)
    # =========================================================================
    print_header("3. AUTHENTICATION")

    print_subheader("With Provided Credentials + ServerHost")
    auth_response = test_http_request(
        session, "{base}/1.0/servers".format(base=base_url),
        std_headers,
        "Authentication Test", results, "Auth", args.verify_ssl
    )

    if auth_response and auth_response.status_code != 200:
        # Show hint for common errors
        try:
            error_json = auth_response.json()
            error_msg = error_json.get("Message", "")
            if "authorization" in error_msg.lower():
                print("\n  {hint}".format(hint=warn("Hint: Check username/password")))
            elif "serverhost" in error_msg.lower():
                print("\n  {hint}".format(hint=warn("Hint: ServerHost header value may be incorrect")))
        except Exception:
            pass

    # =========================================================================
    # TEST 4: API Endpoints
    # =========================================================================
    print_header("4. REST API ENDPOINTS")

    # API v1.0 endpoints
    print_subheader("API Version 1.0")
    for endpoint in ["servers", "pools", "alerts", "ports", "hostgroups", "snapshots"]:
        test_http_request(
            session, "{base}/1.0/{endpoint}".format(base=base_url, endpoint=endpoint),
            std_headers, "v1.0/{endpoint}".format(endpoint=endpoint), results, "API v1.0", args.verify_ssl
        )

    # API v2.0 endpoints
    print_subheader("API Version 2.0")
    for endpoint in ["servers", "pools", "virtualdisks", "physicaldisks", "hosts"]:
        test_http_request(
            session, "{base}/2.0/{endpoint}".format(base=base_url, endpoint=endpoint),
            std_headers, "v2.0/{endpoint}".format(endpoint=endpoint), results, "API v2.0", args.verify_ssl
        )

    # =========================================================================
    # TEST 5: ServerHost Header Variations
    # =========================================================================
    print_header("5. SERVERHOST HEADER VARIATIONS")

    # Headers without ServerHost
    headers_no_sh = {
        "Authorization": auth_header,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }

    serverhost_tests = [
        ("No ServerHost", headers_no_sh),
        ("Empty ServerHost", {**headers_no_sh, "ServerHost": ""}),
        ("Original: {n}".format(n=args.nodename), {**headers_no_sh, "ServerHost": args.nodename}),
        ("Lowercase: {n}".format(n=args.nodename.lower()), {**headers_no_sh, "ServerHost": args.nodename.lower()}),
        ("Uppercase: {n}".format(n=args.nodename.upper()), {**headers_no_sh, "ServerHost": args.nodename.upper()}),
    ]

    for test_name, headers in serverhost_tests:
        print_subheader("ServerHost: {name}".format(name=test_name))
        test_http_request(
            session, "{base}/1.0/servers".format(base=base_url),
            headers, test_name, results, "ServerHost", args.verify_ssl
        )

    # =========================================================================
    # TEST 6: List Available Servers
    # =========================================================================
    print_header("6. AVAILABLE SERVERS")

    # Try to get server list (with ServerHost header)
    try:
        resp = session.get(
            "{base}/1.0/servers".format(base=base_url),
            headers=std_headers,
            timeout=15,
            verify=args.verify_ssl
        )
        if resp.status_code == 200:
            servers = resp.json()
            print(ok("Found {count} server(s):".format(count=len(servers))))
            for server in servers:
                caption = server.get("Caption", "Unknown")
                hostname = server.get("HostName", "Unknown")
                server_id = server.get("Id", "Unknown")
                state = server.get("State", "Unknown")
                product_version = server.get("ProductVersion", "Unknown")
                print("\n  {BOLD}{caption}{END}".format(BOLD=Colors.BOLD, caption=caption, END=Colors.END))
                print("    HostName: {hostname}".format(hostname=hostname))
                print("    ID: {id}".format(id=server_id))
                print("    State: {state}".format(state=state))
                print("    Version: {ver}".format(ver=product_version))

                # Check if this matches the provided nodename
                if caption.lower() == args.nodename.lower():
                    if caption == args.nodename:
                        print("    {result}".format(result=ok("Matches provided nodename (exact)")))
                    else:
                        print("    {result}".format(result=warn("Matches but case differs! Use: {caption}".format(caption=caption))))
        else:
            print(fail("Could not retrieve server list (HTTP {code})".format(code=resp.status_code)))
            try:
                print("  Response: {body}".format(body=resp.json()))
            except Exception:
                print("  Response: {body}".format(body=resp.text[:200]))
    except Exception as e:
        print(fail("Error retrieving server list: {e}".format(e=e)))

    # =========================================================================
    # TEST 7: Performance Data Endpoints
    # =========================================================================
    print_header("7. PERFORMANCE DATA ENDPOINTS")

    # Try to get a pool and then its performance data
    try:
        resp = session.get(
            "{base}/2.0/pools".format(base=base_url),
            headers=std_headers,
            timeout=15,
            verify=args.verify_ssl
        )
        if resp.status_code == 200:
            pools = resp.json()
            if pools:
                pool = pools[0]
                pool_id = pool.get("Id", "")
                pool_name = pool.get("Caption", "Unknown")
                print(info("Testing performance endpoint for pool: {name}".format(name=pool_name)))

                # Test v1.0 performance endpoint
                print_subheader("v1.0 Performance Data")
                test_http_request(
                    session, "{base}/1.0/performance/{id}".format(base=base_url, id=pool_id),
                    std_headers, "v1.0/performance (Pool)", results, "Performance", args.verify_ssl
                )

                # Test v2.0 performance endpoint
                print_subheader("v2.0 Performance Data")
                test_http_request(
                    session, "{base}/2.0/pools/{id}/performance".format(base=base_url, id=pool_id),
                    std_headers, "v2.0/pools/ID/performance", results, "Performance", args.verify_ssl
                )
            else:
                print(info("No pools found to test performance endpoints"))
        else:
            print(warn("Could not get pools to test performance endpoints"))
    except Exception as e:
        print(warn("Could not test performance endpoints: {e}".format(e=e)))

    # =========================================================================
    # SUMMARY AND RECOMMENDATIONS
    # =========================================================================
    results.print_summary()

    print_header("RECOMMENDATIONS")

    # Analyze results and give recommendations
    recommendations = []

    # Check auth issues
    auth_results = [r for r in results.results if r[0] == "Auth"]
    if any(r[2] == "FAIL" for r in auth_results):
        recommendations.append("- Check username and password are correct")
        recommendations.append("- Verify the user has REST API access permissions in DataCore")
        recommendations.append("- Ensure the ServerHost (nodename) value is correct")

    # Check ServerHost issues
    sh_results = [r for r in results.results if r[0] == "ServerHost"]
    working_sh = [r[1] for r in sh_results if r[2] == "PASS"]
    failed_sh = [r[1] for r in sh_results if r[2] == "FAIL"]

    if "No ServerHost" in failed_sh:
        recommendations.append("- ServerHost header is REQUIRED for this DataCore installation")

    if working_sh:
        # Find the best working ServerHost value
        for w in working_sh:
            if "Original" in w:
                recommendations.append("- ServerHost '{nodename}' works correctly".format(nodename=args.nodename))
                break
            elif "Lowercase" in w and "Original" not in working_sh:
                recommendations.append("- Use lowercase ServerHost: {n}".format(n=args.nodename.lower()))
                break
            elif "Uppercase" in w and "Original" not in working_sh and "Lowercase" not in working_sh:
                recommendations.append("- Use uppercase ServerHost: {n}".format(n=args.nodename.upper()))
                break

    # Check API version issues
    v1_results = [r for r in results.results if r[0] == "API v1.0"]
    v2_results = [r for r in results.results if r[0] == "API v2.0"]

    v1_ok = any(r[2] == "PASS" for r in v1_results)
    v2_ok = any(r[2] == "PASS" for r in v2_results)

    if v1_ok and v2_ok:
        recommendations.append("- Both API v1.0 and v2.0 are working")
    elif v1_ok and not v2_ok:
        recommendations.append("- Only API v1.0 works - check DataCore version for v2.0 support")
    elif v2_ok and not v1_ok:
        recommendations.append("- Only API v2.0 works - unusual, check DataCore configuration")

    # Check performance endpoints
    perf_results = [r for r in results.results if r[0] == "Performance"]
    if perf_results:
        perf_ok = any(r[2] == "PASS" for r in perf_results)
        if perf_ok:
            recommendations.append("- Performance data endpoints are working")
        else:
            recommendations.append("- Performance data endpoints may have issues")

    if not recommendations:
        recommendations.append("- All tests passed! Configuration looks correct.")

    for rec in recommendations:
        print(rec)

    print()
    session.close()

    # Return exit code based on critical tests
    critical_failed = any(r[2] == "FAIL" for r in results.results if r[0] in ["Auth", "Network"])
    return 1 if critical_failed else 0


if __name__ == "__main__":
    sys.exit(main())
