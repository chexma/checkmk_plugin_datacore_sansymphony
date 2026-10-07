#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# (c) Andre Eckstein <andre.eckstein@bechtle.com>

# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  check_mk is  distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.

import argparse
import base64
import json
import logging
import sys
from collections import namedtuple
from collections.abc import Callable, Sequence
from typing import Any

import requests
import urllib3

# CheckMK 2.5+: unstable helpers that replace the deprecated
# cmk.special_agents.v0_unstable and cmk.utils.password_store (removed in 3.1.0).
# On 2.3/2.4 they don't exist, so we fall back to the legacy API.
try:
    from cmk.password_store.v1_unstable import dereference_secret
except ImportError:  # CheckMK 2.3/2.4
    dereference_secret = None  # type: ignore[assignment]

try:
    from cmk.server_side_programs.v1_unstable import report_agent_crashes, vcrtrace
except ImportError:  # CheckMK 2.3/2.4
    report_agent_crashes = None  # type: ignore[assignment]
    vcrtrace = None  # type: ignore[assignment]

AGENT_VERSION = "2.5.0"


def create_argument_parser() -> argparse.ArgumentParser:
    """Parser with the common special agent options --debug, --verbose, --vcrtrace"""
    if vcrtrace is None:  # CheckMK 2.3/2.4
        from cmk.special_agents.v0_unstable.argument_parsing import (
            create_default_argument_parser,
        )

        return create_default_argument_parser(description=__doc__)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.formatter_class = argparse.RawTextHelpFormatter
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Enable debug mode (keep some exceptions unhandled)",
    )
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument(
        "--vcrtrace",
        "--tracefile",
        default=False,
        action=vcrtrace(filter_headers=[("authorization", "****")]),
    )
    return parser


def parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    sections = [
        "alerts",
        "hosts",
        "hostgroups",
        "physicaldisks",
        "pools",
        "ports",
        "servergroups",
        "servers",
        "snapshots",
        "virtualdisks",
    ]

    parser = create_argument_parser()

    parser.add_argument(
        "-u", "--user", help="Username for DataCore Sansymphony V Login", required=True
    )
    parser.add_argument(
        "-s",
        "--password_id",
        help="Password store reference '<id>:<store path>' for DataCore Sansymphony V Login",
        required=True,
    )
    parser.add_argument("-n", "--nodename", help="DataCore Node to fetch data for", required=True)
    parser.add_argument(
        "-P",
        "--proto",
        default="https",
        help="Use 'http' or 'https' (default=https)",
    )
    parser.add_argument(
        "-m",
        "--sections",
        default=sections,
        help=f"Comma separated list of data to query. "
        f"Possible values: {','.join(sections)} (default: all)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        dest="verify_ssl",
        action="store_false",
        default=True,
        help="Disable SSL certificate verification (not recommended for production)",
    )
    parser.add_argument(
        "host",
        metavar="HOSTNAME",
        help="IP address or hostname of your DataCore Server",
    )

    return parser.parse_args(argv)


def lookup_password(password_ref: str) -> str:
    """Resolve a password store reference '<id>:<store path>' to the plaintext"""
    if dereference_secret is not None:
        return dereference_secret(password_ref).reveal()

    # CheckMK 2.3/2.4
    from pathlib import Path

    from cmk.utils import password_store

    pw_id, pw_path = password_ref.split(":", 1)
    return password_store.lookup(Path(pw_path), pw_id)


def write_section(name: str, items: Sequence[Any]) -> None:
    """Write an agent section with one JSON object per line"""
    sys.stdout.write(f"<<<datacore_rest_{name}:sep(0)>>>\n")
    for item in items:
        sys.stdout.write(json.dumps(item, sort_keys=True) + "\n")
    sys.stdout.flush()


def get_session(args, password: str) -> requests.Session:
    """Create requests session"""
    session = requests.Session()
    session.auth = (args.user, password)
    session.verify = args.verify_ssl
    return session


def get_objects(object_name, api_url_base, headers, session, args):
    """Get section data e.g. virtualdisk, pools"""
    try:
        logging.debug(
            "Fetching the whole section %s : %s/%s",
            object_name,
            api_url_base,
            object_name,
        )
        response = session.get(
            f"{api_url_base}/{object_name}",
            headers=headers,
            timeout=15,
            verify=args.verify_ssl,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error("Error fetching %s section: %s", object_name, e)
        if "400" in str(e):
            logging.error(
                "Hint: A 400 Bad Request often indicates an incorrect 'nodename' parameter. "
                "Ensure the nodename exactly matches the DataCore server Caption (case-sensitive)."
            )
        sys.exit(1)


def request_object_perfdata(data_object, api_url_base, headers, session, args):
    """Get perfdata for specific objects"""
    try:
        logging.debug(
            "Fetching performance data of single object: %s/performance/%s",
            api_url_base,
            data_object["Id"],
        )
        response = session.get(
            f'{api_url_base}/performance/{data_object["Id"]}',
            headers=headers,
            timeout=15,
            verify=args.verify_ssl,
        )
        response.raise_for_status()
        perfdata = response.json()

        if perfdata:
            data_object["PerformanceData"] = perfdata[0]
        else:
            logging.warning("No performance data returned for object ID: %s", data_object["Id"])
            data_object["PerformanceData"] = None

        return data_object
    except requests.RequestException as e:
        logging.error("Error fetching performance data for object ID %s: %s", data_object["Id"], e)
        data_object["PerformanceData"] = None
        return data_object


def add_perfdata(objects, api_url_base, headers, session, args):
    """Add Perfdata to objects"""
    result = []
    for item in objects:
        updated_object = request_object_perfdata(item, api_url_base, headers, session, args)
        result.append(updated_object)
    return result


def caption_from_id(data_id, json_data):
    """Get Caption for a given ID"""
    for item in json_data:
        if item["Id"] == data_id:
            return str(item["Caption"])


def get_id_of_servername(servername, api_url_base, headers, session, args):
    """Get Server ID for a given SSV Servername"""
    servers = get_objects("servers", api_url_base, headers, session, args)
    for server in servers:
        if server["Caption"].lower() == servername.lower():
            logging.debug("Servername: %s - Server ID: %s", server["Caption"], server["Id"])
            return server["Id"]


def agent_datacore_rest_main(args: Any = None) -> int:
    """Main Special Agent"""

    Section = namedtuple("Section", ["name", "api_version", "has_perfdata", "item_identifier"])
    sections = [
        Section(name="alerts", api_version=1, has_perfdata=False, item_identifier=None),
        Section(name="hosts", api_version=2, has_perfdata=True, item_identifier=None),
        Section(name="hostgroups", api_version=1, has_perfdata=True, item_identifier=None),
        Section(
            name="physicaldisks",
            api_version=2,
            has_perfdata=True,
            item_identifier="HostId",
        ),
        Section(name="pools", api_version=2, has_perfdata=True, item_identifier="ServerId"),
        Section(name="ports", api_version=1, has_perfdata=True, item_identifier="HostId"),
        Section(name="servergroups", api_version=1, has_perfdata=False, item_identifier=None),
        Section(name="servers", api_version=2, has_perfdata=True, item_identifier="Id"),
        Section(name="snapshots", api_version=1, has_perfdata=False, item_identifier=None),
        Section(name="virtualdisks", api_version=2, has_perfdata=True, item_identifier=None),
    ]

    password = lookup_password(args.password_id)

    # Create session
    session = get_session(args, password)

    # Create proper Base64 encoded auth header
    auth_string = f"{args.user}:{password}"
    auth_bytes = base64.b64encode(auth_string.encode()).decode()
    headers = {
        "ServerHost": args.nodename,
        "Authorization": f"Basic {auth_bytes}",
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    base_api_url = f"{args.proto}://{args.host}/RestService/rest.svc"

    my_server_id = get_id_of_servername(
        args.nodename, f"{base_api_url}/1.0", headers, session, args
    )

    # Validate server ID was found
    if my_server_id is None:
        logging.error("Server '%s' not found in SANsymphony", args.nodename)
        session.close()
        sys.exit(1)

    resources_dict = {}

    for section in sections:
        if section.name in args.sections:
            api_url_base = f"{base_api_url}/{section.api_version}.0"
            whole_section = get_objects(section.name, api_url_base, headers, session, args)

            if section.has_perfdata and section.api_version == 1:
                resources_dict[section.name] = add_perfdata(
                    whole_section, api_url_base, headers, session, args
                )

            # physicaldisks api version is 2 but its perfdata is only available in 1.0
            if section.name == "physicaldisks":
                api_url_base = f"{args.proto}://{args.host}/RestService/rest.svc/1.0"
                resources_dict[section.name] = add_perfdata(
                    whole_section, api_url_base, headers, session, args
                )
            else:
                resources_dict[section.name] = whole_section

    for section in sections:
        if section.name not in resources_dict:
            continue
        objects = resources_dict[section.name]
        if section.name in ["alerts", "snapshots"]:
            # whole list as a single JSON line
            write_section(section.name, [objects])
        elif section.name == "virtualdisks":
            write_section(
                section.name,
                [
                    item
                    for item in objects
                    if not item["IsSnapshotVirtualDisk"]
                    and my_server_id in (item["FirstHostId"], item["SecondHostId"])
                ],
            )
        elif section.name == "ports":
            write_section(
                section.name,
                [
                    item
                    for item in objects
                    if item[section.item_identifier] == my_server_id
                    and "Loopback" not in item["Caption"]
                ],
            )
        elif section.item_identifier:
            write_section(
                section.name,
                [item for item in objects if item[section.item_identifier] == my_server_id],
            )
        else:
            write_section(section.name, objects)

    # Close session
    session.close()
    return 0


def _run(main_fn: Callable[[argparse.Namespace], int], argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        format="%(levelname)s %(asctime)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level={0: logging.WARN, 1: logging.INFO}.get(args.verbose, logging.DEBUG),
    )
    if not args.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)
    logging.getLogger("vcr").setLevel(logging.WARN)

    if report_agent_crashes is not None and not args.debug:
        # 2.5+: unhandled exceptions become a crash report in the GUI
        return report_agent_crashes("datacore_rest", AGENT_VERSION)(main_fn)(args)

    try:
        return main_fn(args)
    except Exception:
        if args.debug:
            raise
        logging.exception("Unhandled exception in DataCore special agent")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point to be used"""
    return _run(agent_datacore_rest_main, argv)


if __name__ == "__main__":
    sys.exit(main())
