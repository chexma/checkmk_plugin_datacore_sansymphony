#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
"""
DataCore REST API Debug Script

This script helps diagnose 400 Bad Request errors when connecting to
the DataCore SANsymphony REST API.

Usage:
    python3 debug_datacore_api.py --host 10.64.36.41 --user USERNAME --password PASSWORD --nodename SERVERNAME
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib3
from typing import Optional

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("ERROR: 'requests' module not found. Install with: pip install requests")
    sys.exit(1)


def print_separator(title: str = "") -> None:
    """Print a visual separator."""
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)


def print_response(response: requests.Response, test_name: str) -> None:
    """Print detailed response information."""
    print(f"\n--- {test_name} ---")
    print(f"Status Code: {response.status_code}")
    print(f"Status: {'OK' if response.ok else 'FAILED'}")
    print(f"Headers received:")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")

    print(f"\nResponse Body ({len(response.content)} bytes):")
    try:
        # Try to parse as JSON for pretty printing
        json_response = response.json()
        print(json.dumps(json_response, indent=2))
    except json.JSONDecodeError:
        # If not JSON, print raw text
        print(response.text if response.text else "(empty)")


def test_api_call(
    session: requests.Session,
    url: str,
    headers: dict,
    test_name: str,
    verify_ssl: bool = False,
) -> Optional[requests.Response]:
    """Make an API call and print results."""
    print(f"\nTesting: {test_name}")
    print(f"URL: {url}")
    print(f"Headers sent:")
    for key, value in headers.items():
        if key.lower() == "authorization":
            print(f"  {key}: Basic ***HIDDEN***")
        else:
            print(f"  {key}: {value}")

    try:
        response = session.get(url, headers=headers, timeout=10, verify=verify_ssl)
        print_response(response, test_name)
        return response
    except requests.RequestException as e:
        print(f"ERROR: Request failed - {e}")
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Debug DataCore REST API connection issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 debug_datacore_api.py --host 10.64.36.41 --user admin --password secret --nodename SSV1
    python3 debug_datacore_api.py --host datacore.local --user admin --password secret --nodename DataCoreServer01
        """,
    )
    parser.add_argument("--host", required=True, help="DataCore server IP or hostname")
    parser.add_argument("--user", required=True, help="Username for authentication")
    parser.add_argument("--password", required=True, help="Password for authentication")
    parser.add_argument("--nodename", required=True, help="DataCore server nodename (Caption)")
    parser.add_argument("--proto", default="https", choices=["http", "https"], help="Protocol (default: https)")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate")

    args = parser.parse_args()

    # Build base URL
    base_url = f"{args.proto}://{args.host}/RestService/rest.svc"

    # Create auth header
    auth_string = f"{args.user}:{args.password}"
    auth_bytes = base64.b64encode(auth_string.encode()).decode()
    auth_header = f"Basic {auth_bytes}"

    # Create session
    session = requests.Session()

    print_separator("DataCore REST API Debug Script")
    print(f"Target: {base_url}")
    print(f"User: {args.user}")
    print(f"Nodename: {args.nodename}")
    print(f"SSL Verification: {args.verify_ssl}")

    results = {}

    # =========================================================================
    # TEST 1: Without ServerHost header
    # =========================================================================
    print_separator("TEST 1: Without ServerHost header")
    headers1 = {
        "Authorization": auth_header,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    resp1 = test_api_call(
        session, f"{base_url}/1.0/servers", headers1,
        "GET /1.0/servers (no ServerHost)", args.verify_ssl
    )
    results["no_serverhost"] = resp1.status_code if resp1 else "FAILED"

    # =========================================================================
    # TEST 2: With ServerHost header (as provided)
    # =========================================================================
    print_separator("TEST 2: With ServerHost header (as provided)")
    headers2 = {
        "ServerHost": args.nodename,
        "Authorization": auth_header,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    resp2 = test_api_call(
        session, f"{base_url}/1.0/servers", headers2,
        f"GET /1.0/servers (ServerHost: {args.nodename})", args.verify_ssl
    )
    results["with_serverhost"] = resp2.status_code if resp2 else "FAILED"

    # =========================================================================
    # TEST 3: With ServerHost header (lowercase)
    # =========================================================================
    print_separator("TEST 3: With ServerHost header (lowercase)")
    headers3 = {
        "ServerHost": args.nodename.lower(),
        "Authorization": auth_header,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    resp3 = test_api_call(
        session, f"{base_url}/1.0/servers", headers3,
        f"GET /1.0/servers (ServerHost: {args.nodename.lower()})", args.verify_ssl
    )
    results["lowercase"] = resp3.status_code if resp3 else "FAILED"

    # =========================================================================
    # TEST 4: With ServerHost header (uppercase)
    # =========================================================================
    print_separator("TEST 4: With ServerHost header (uppercase)")
    headers4 = {
        "ServerHost": args.nodename.upper(),
        "Authorization": auth_header,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    resp4 = test_api_call(
        session, f"{base_url}/1.0/servers", headers4,
        f"GET /1.0/servers (ServerHost: {args.nodename.upper()})", args.verify_ssl
    )
    results["uppercase"] = resp4.status_code if resp4 else "FAILED"

    # =========================================================================
    # TEST 5: API Version 2.0
    # =========================================================================
    print_separator("TEST 5: API Version 2.0")
    resp5 = test_api_call(
        session, f"{base_url}/2.0/servers", headers2,
        f"GET /2.0/servers (ServerHost: {args.nodename})", args.verify_ssl
    )
    results["api_v2"] = resp5.status_code if resp5 else "FAILED"

    # =========================================================================
    # TEST 6: Minimal headers (only Authorization)
    # =========================================================================
    print_separator("TEST 6: Minimal headers (only Authorization)")
    headers6 = {
        "Authorization": auth_header,
    }
    resp6 = test_api_call(
        session, f"{base_url}/1.0/servers", headers6,
        "GET /1.0/servers (minimal headers)", args.verify_ssl
    )
    results["minimal"] = resp6.status_code if resp6 else "FAILED"

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print_separator("SUMMARY")
    print("\nTest Results:")
    print("-" * 50)
    for test_name, status in results.items():
        status_text = "OK" if status == 200 else f"FAILED ({status})"
        print(f"  {test_name:20s}: {status_text}")

    # Analysis
    print("\n" + "-" * 50)
    print("Analysis:")

    if results.get("no_serverhost") == 200:
        print("  ✓ ServerHost header is NOT required")
        print("    → The issue might be the ServerHost value itself")
    elif results.get("with_serverhost") == 200:
        print("  ✓ ServerHost header with provided value works")
    elif results.get("lowercase") == 200:
        print("  ✓ ServerHost needs to be LOWERCASE")
        print(f"    → Use: {args.nodename.lower()}")
    elif results.get("uppercase") == 200:
        print("  ✓ ServerHost needs to be UPPERCASE")
        print(f"    → Use: {args.nodename.upper()}")
    elif results.get("api_v2") == 200:
        print("  ✓ API version 2.0 works, but 1.0 doesn't")
        print("    → Consider using API 2.0 for server lookup")
    elif results.get("minimal") == 200:
        print("  ✓ Minimal headers work - ServerHost might be causing issues")
    else:
        print("  ✗ All tests failed")
        print("    Possible causes:")
        print("    - Wrong username/password")
        print("    - Network/firewall issues")
        print("    - DataCore REST service not running")
        print("    - ServerHost value doesn't match any known server")

    print("\n" + "=" * 70)

    # If test without ServerHost worked, try to list servers
    if resp1 and resp1.status_code == 200:
        print("\nAvailable servers (from response without ServerHost):")
        try:
            servers = resp1.json()
            for server in servers:
                caption = server.get("Caption", "Unknown")
                hostname = server.get("HostName", "Unknown")
                server_id = server.get("Id", "Unknown")
                print(f"  - Caption: {caption}")
                print(f"    HostName: {hostname}")
                print(f"    Id: {server_id}")
                print()
        except (json.JSONDecodeError, TypeError):
            print("  (Could not parse server list)")
    elif resp6 and resp6.status_code == 200:
        print("\nAvailable servers (from response with minimal headers):")
        try:
            servers = resp6.json()
            for server in servers:
                caption = server.get("Caption", "Unknown")
                hostname = server.get("HostName", "Unknown")
                server_id = server.get("Id", "Unknown")
                print(f"  - Caption: {caption}")
                print(f"    HostName: {hostname}")
                print(f"    Id: {server_id}")
                print()
        except (json.JSONDecodeError, TypeError):
            print("  (Could not parse server list)")

    session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
