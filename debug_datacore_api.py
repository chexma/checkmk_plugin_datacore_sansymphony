#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
"""
DataCore REST API Debug Script (Extended Version)

This script helps diagnose connection and API issues when connecting to
the DataCore SANsymphony REST API.

Tests performed:
- Network connectivity (DNS, TCP port)
- SSL/TLS handshake and certificate details
- Authentication (with/without credentials)
- REST API endpoints (v1.0 and v2.0)
- ServerHost header variations
- Response analysis

Usage:
    python3 debug_datacore_api.py --host 10.64.36.41 --user USERNAME --password PASSWORD --nodename SERVERNAME
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


def ok(msg: str) -> str:
    return f"{Colors.GREEN}✓ {msg}{Colors.END}"


def fail(msg: str) -> str:
    return f"{Colors.RED}✗ {msg}{Colors.END}"


def warn(msg: str) -> str:
    return f"{Colors.YELLOW}⚠ {msg}{Colors.END}"


def info(msg: str) -> str:
    return f"{Colors.BLUE}ℹ {msg}{Colors.END}"


def print_header(title: str) -> None:
    """Print a section header."""
    print(f"\n{Colors.BOLD}{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}{Colors.END}")


def print_subheader(title: str) -> None:
    """Print a subsection header."""
    print(f"\n{Colors.CYAN}--- {title} ---{Colors.END}")


# =============================================================================
# Test Functions
# =============================================================================

class TestResults:
    """Collect and summarize test results."""

    def __init__(self):
        self.results: List[Tuple[str, str, str]] = []  # (category, test_name, status)
        self.details: Dict[str, Any] = {}

    def add(self, category: str, test_name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        self.results.append((category, test_name, status))
        if detail:
            self.details[f"{category}:{test_name}"] = detail

    def add_warning(self, category: str, test_name: str, detail: str = "") -> None:
        self.results.append((category, test_name, "WARN"))
        if detail:
            self.details[f"{category}:{test_name}"] = detail

    def print_summary(self) -> None:
        print_header("TEST SUMMARY")

        current_category = ""
        for category, test_name, status in self.results:
            if category != current_category:
                print(f"\n{Colors.BOLD}{category}:{Colors.END}")
                current_category = category

            if status == "PASS":
                print(f"  {ok(test_name)}")
            elif status == "FAIL":
                print(f"  {fail(test_name)}")
            else:
                print(f"  {warn(test_name)}")

        # Count results
        passed = sum(1 for _, _, s in self.results if s == "PASS")
        failed = sum(1 for _, _, s in self.results if s == "FAIL")
        warnings = sum(1 for _, _, s in self.results if s == "WARN")

        print(f"\n{Colors.BOLD}Total: {passed} passed, {failed} failed, {warnings} warnings{Colors.END}")


def test_dns_resolution(host: str, results: TestResults) -> Optional[str]:
    """Test DNS resolution for hostname."""
    print_subheader("DNS Resolution")

    # Check if host is already an IP
    try:
        socket.inet_aton(host)
        print(info(f"Host '{host}' is already an IP address"))
        results.add("Network", "DNS Resolution", True, "IP address provided")
        return host
    except socket.error:
        pass

    # Try to resolve hostname
    try:
        ip = socket.gethostbyname(host)
        print(ok(f"Resolved '{host}' to {ip}"))
        results.add("Network", "DNS Resolution", True, f"Resolved to {ip}")
        return ip
    except socket.gaierror as e:
        print(fail(f"DNS resolution failed for '{host}': {e}"))
        results.add("Network", "DNS Resolution", False, str(e))
        return None


def test_tcp_connection(host: str, port: int, results: TestResults) -> bool:
    """Test TCP connection to host:port."""
    print_subheader(f"TCP Connection (Port {port})")

    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()

        if result == 0:
            print(ok(f"Port {port} is open (connected in {elapsed:.1f}ms)"))
            results.add("Network", f"TCP Port {port}", True, f"{elapsed:.1f}ms")
            return True
        else:
            print(fail(f"Port {port} is closed or filtered"))
            results.add("Network", f"TCP Port {port}", False, "Connection refused")
            return False
    except socket.timeout:
        print(fail(f"Connection to port {port} timed out"))
        results.add("Network", f"TCP Port {port}", False, "Timeout")
        return False
    except Exception as e:
        print(fail(f"Connection error: {e}"))
        results.add("Network", f"TCP Port {port}", False, str(e))
        return False


def test_ssl_certificate(host: str, port: int, results: TestResults) -> Dict[str, Any]:
    """Test SSL/TLS connection and get certificate details."""
    print_subheader("SSL/TLS Certificate")

    cert_info = {}

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

                print(ok(f"SSL/TLS Handshake successful"))
                print(f"    Protocol: {version}")
                print(f"    Cipher: {cipher[0]} ({cipher[2]} bits)")

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
                        print(f"\n    Certificate Details:")
                        for line in output.strip().split('\n'):
                            print(f"      {line}")
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

                results.add("SSL/TLS", "Handshake", True, f"{version} / {cipher[0]}")
                return cert_info

    except ssl.SSLError as e:
        print(fail(f"SSL Error: {e}"))
        results.add("SSL/TLS", "Handshake", False, str(e))
        return {}
    except Exception as e:
        print(fail(f"Connection error: {e}"))
        results.add("SSL/TLS", "Handshake", False, str(e))
        return {}


def test_http_request(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    test_name: str,
    results: TestResults,
    category: str = "API",
    verify_ssl: bool = False,
    expect_status: Optional[int] = None,
) -> Optional[requests.Response]:
    """Make an HTTP request and analyze the response."""

    print(f"\n  Testing: {test_name}")
    print(f"  URL: {url}")

    # Show headers (hide password)
    headers_display = {}
    for k, v in headers.items():
        if k.lower() == 'authorization':
            headers_display[k] = 'Basic ***HIDDEN***'
        else:
            headers_display[k] = v
    print(f"  Headers: {headers_display}")

    try:
        start = time.time()
        response = session.get(url, headers=headers, timeout=10, verify=verify_ssl)
        elapsed = (time.time() - start) * 1000

        status_ok = response.status_code == 200
        if expect_status:
            status_ok = response.status_code == expect_status

        # Print result
        status_icon = ok if status_ok else fail
        print(f"  {status_icon(f'Status: {response.status_code} ({elapsed:.0f}ms)')}")

        # Show response body for errors
        if not status_ok or response.status_code >= 400:
            print(f"  Response Body ({len(response.content)} bytes):")
            try:
                json_resp = response.json()
                print(f"    {json.dumps(json_resp, indent=4)}")
            except json.JSONDecodeError:
                body = response.text[:500] if response.text else "(empty)"
                print(f"    {body}")

        results.add(category, test_name, status_ok, f"HTTP {response.status_code}")
        return response

    except requests.exceptions.Timeout:
        print(f"  {fail('Request timed out')}")
        results.add(category, test_name, False, "Timeout")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"  {fail(f'Connection error: {e}')}")
        results.add(category, test_name, False, "Connection error")
        return None
    except Exception as e:
        print(f"  {fail(f'Error: {e}')}")
        results.add(category, test_name, False, str(e))
        return None


def interpret_status_code(code: int) -> str:
    """Return explanation for HTTP status code."""
    explanations = {
        200: "OK - Request successful",
        400: "Bad Request - Invalid request format, wrong headers, or invalid parameter values",
        401: "Unauthorized - Authentication required or credentials invalid",
        403: "Forbidden - Authentication successful but access denied",
        404: "Not Found - Endpoint does not exist",
        405: "Method Not Allowed - HTTP method not supported for this endpoint",
        500: "Internal Server Error - Server-side error",
        502: "Bad Gateway - Proxy/gateway error",
        503: "Service Unavailable - Server temporarily unavailable",
    }
    return explanations.get(code, f"Unknown status code {code}")


# =============================================================================
# Main Function
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Debug DataCore REST API connection issues (Extended Version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 debug_datacore_api.py --host 10.64.36.41 --user admin --password secret --nodename SSV1
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
    base_url = f"{args.proto}://{args.host}:{port}/RestService/rest.svc"

    # Create auth header
    auth_string = f"{args.user}:{args.password}"
    auth_bytes = base64.b64encode(auth_string.encode()).decode()
    auth_header = f"Basic {auth_bytes}"

    # Create session
    session = requests.Session()
    results = TestResults()

    # =========================================================================
    # HEADER: System Info
    # =========================================================================
    print_header("DataCore REST API Debug Script (Extended)")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  Requests: {REQUESTS_VERSION}")
    print(f"  Target: {args.proto}://{args.host}:{port}")
    print(f"  User: {args.user}")
    print(f"  Nodename: {args.nodename}")

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
        print(fail(f"\nCannot proceed - port {port} not reachable"))
        results.print_summary()
        return 1

    # =========================================================================
    # TEST 2: SSL/TLS (if https)
    # =========================================================================
    if args.proto == "https":
        print_header("2. SSL/TLS CERTIFICATE")
        cert_info = test_ssl_certificate(resolved_ip, port, results)
    else:
        print_header("2. SSL/TLS CERTIFICATE")
        print(info("Skipped (using HTTP)"))

    # =========================================================================
    # TEST 3: Authentication
    # =========================================================================
    print_header("3. AUTHENTICATION")

    # Test without credentials
    print_subheader("Without Credentials (expect 401)")
    test_http_request(
        session, f"{base_url}/1.0/servers",
        {"Content-Type": "application/json", "Accept": "application/json"},
        "No Auth", results, "Auth", args.verify_ssl, expect_status=401
    )

    # Test with wrong credentials
    print_subheader("With Wrong Credentials (expect 401/403)")
    wrong_auth = base64.b64encode(b"wronguser:wrongpass").decode()
    test_http_request(
        session, f"{base_url}/1.0/servers",
        {
            "Authorization": f"Basic {wrong_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        "Wrong Credentials", results, "Auth", args.verify_ssl, expect_status=401
    )

    # Test with correct credentials
    print_subheader("With Provided Credentials")
    auth_response = test_http_request(
        session, f"{base_url}/1.0/servers",
        {
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        "Correct Credentials", results, "Auth", args.verify_ssl
    )

    # =========================================================================
    # TEST 4: API Endpoints
    # =========================================================================
    print_header("4. REST API ENDPOINTS")

    # Standard headers for all API tests
    std_headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }

    # API Root
    print_subheader("API Root")
    test_http_request(
        session, f"{args.proto}://{args.host}:{port}/RestService/rest.svc",
        std_headers, "API Root", results, "API", args.verify_ssl
    )

    # API v1.0 endpoints
    print_subheader("API Version 1.0")
    for endpoint in ["servers", "pools", "alerts"]:
        test_http_request(
            session, f"{base_url}/1.0/{endpoint}",
            std_headers, f"v1.0/{endpoint}", results, "API v1.0", args.verify_ssl
        )

    # API v2.0 endpoints
    print_subheader("API Version 2.0")
    for endpoint in ["servers", "pools", "virtualdisks"]:
        test_http_request(
            session, f"{base_url}/2.0/{endpoint}",
            std_headers, f"v2.0/{endpoint}", results, "API v2.0", args.verify_ssl
        )

    # =========================================================================
    # TEST 5: ServerHost Header Variations
    # =========================================================================
    print_header("5. SERVERHOST HEADER VARIATIONS")

    serverhost_tests = [
        ("No ServerHost", {}),
        ("Empty ServerHost", {"ServerHost": ""}),
        ("Original", {"ServerHost": args.nodename}),
        ("Lowercase", {"ServerHost": args.nodename.lower()}),
        ("Uppercase", {"ServerHost": args.nodename.upper()}),
    ]

    for test_name, extra_headers in serverhost_tests:
        headers = {**std_headers, **extra_headers}
        print_subheader(f"ServerHost: {test_name}")
        test_http_request(
            session, f"{base_url}/1.0/servers",
            headers, test_name, results, "ServerHost", args.verify_ssl
        )

    # =========================================================================
    # TEST 6: List Available Servers
    # =========================================================================
    print_header("6. AVAILABLE SERVERS")

    # Try to get server list
    try:
        resp = session.get(
            f"{base_url}/1.0/servers",
            headers=std_headers,
            timeout=10,
            verify=args.verify_ssl
        )
        if resp.status_code == 200:
            servers = resp.json()
            print(ok(f"Found {len(servers)} server(s):"))
            for server in servers:
                caption = server.get("Caption", "Unknown")
                hostname = server.get("HostName", "Unknown")
                server_id = server.get("Id", "Unknown")
                state = server.get("State", "Unknown")
                print(f"\n  {Colors.BOLD}{caption}{Colors.END}")
                print(f"    HostName: {hostname}")
                print(f"    ID: {server_id}")
                print(f"    State: {state}")

                # Check if this matches the provided nodename
                if caption.lower() == args.nodename.lower():
                    if caption == args.nodename:
                        print(f"    {ok('Matches provided nodename (exact)')}")
                    else:
                        print(f"    {warn(f'Matches but case differs! Use: {caption}')}")
        else:
            print(fail(f"Could not retrieve server list (HTTP {resp.status_code})"))
            try:
                print(f"  Response: {resp.json()}")
            except:
                print(f"  Response: {resp.text[:200]}")
    except Exception as e:
        print(fail(f"Error retrieving server list: {e}"))

    # =========================================================================
    # SUMMARY AND RECOMMENDATIONS
    # =========================================================================
    results.print_summary()

    print_header("RECOMMENDATIONS")

    # Analyze results and give recommendations
    recommendations = []

    # Check auth issues
    auth_results = [r for r in results.results if r[0] == "Auth"]
    if any(r[2] == "FAIL" and "Correct" in r[1] for r in auth_results):
        recommendations.append("- Check username and password are correct")
        recommendations.append("- Verify the user has REST API access permissions in DataCore")

    # Check ServerHost issues
    sh_results = [r for r in results.results if r[0] == "ServerHost"]
    working_sh = [r[1] for r in sh_results if r[2] == "PASS"]
    if working_sh:
        if "No ServerHost" in working_sh:
            recommendations.append("- ServerHost header is NOT required for this API")
        elif "Original" not in working_sh:
            for w in working_sh:
                if w != "No ServerHost":
                    recommendations.append(f"- Use ServerHost value: {w}")
                    break
    else:
        recommendations.append("- All ServerHost variations failed - check if the nodename exists")
        recommendations.append(f"- Verify '{args.nodename}' matches a server Caption exactly")

    # Check API version issues
    v1_results = [r for r in results.results if r[0] == "API v1.0"]
    v2_results = [r for r in results.results if r[0] == "API v2.0"]

    v1_failed = all(r[2] == "FAIL" for r in v1_results)
    v2_ok = any(r[2] == "PASS" for r in v2_results)

    if v1_failed and v2_ok:
        recommendations.append("- API v1.0 endpoints fail but v2.0 works")
        recommendations.append("- Consider using API v2.0 for server lookup in special agent")

    if not recommendations:
        recommendations.append("- All tests passed! If issues persist, check DataCore server logs")

    for rec in recommendations:
        print(rec)

    print()
    session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
