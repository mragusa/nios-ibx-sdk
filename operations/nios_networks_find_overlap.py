#!/usr/bin/env python3

import getpass
import sys
import ipaddress
import csv
import click
from click_option_group import optgroup
from ibx_sdk.logger.ibx_logger import init_logger, increase_log_level
from ibx_sdk.nios.exceptions import WapiRequestException
from ibx_sdk.nios.gift import Gift
from rich.console import Console
from rich.table import Table

log = init_logger(
    logfile_name="wapi.log",
    logfile_mode="a",
    console_log=True,
    level="info",
    max_size=100000,
    num_logs=1,
)

wapi = Gift()

help_text = """
Infoblox script to compare import data to current prodution data to find overlaps
Use flags to change the type of file checking done
Currently can check for networks, fixed addresses, and DHCP ranges
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-f", "--file", required=True, help="NIOS Import file")
@optgroup.option(
    "-n",
    "--network-check",
    required=True,
    is_flag=True,
    default=False,
    show_default=True,
    help="NIOS Network Import file",
)
@optgroup.option(
    "-r",
    "--range-check",
    required=True,
    is_flag=True,
    default=False,
    show_default=True,
    help="NIOS Range Import file",
)
@optgroup.option(
    "-s",
    "--fixed-check",
    required=True,
    is_flag=True,
    default=False,
    show_default=True,
    help="NIOS Fixed Import file",
)
@optgroup.group("Optional Parameters")
@optgroup.option(
    "-u",
    "--username",
    default="admin",
    show_default=True,
    help="Infoblox admin username",
)
@optgroup.option(
    "-w",
    "--wapi-ver",
    default="2.12.3",
    show_default=True,
    help="Infoblox WAPI version",
)
@optgroup.group("Logging Parameters")
@optgroup.option(
    "--debug",
    is_flag=True,
    default=False,
    show_default=True,
    help="enable verbose debug output",
)
def main(
    grid_mgr: str,
    username: str,
    wapi_ver: str,
    file: str,
    network_check: bool,
    range_check: bool,
    fixed_check: bool,
    debug: bool,
) -> None:
    if debug:
        increase_log_level()
    wapi.grid_mgr = grid_mgr
    wapi.wapi_ver = wapi_ver
    wapi.timeout = 600
    password = getpass.getpass(f"Enter password for [{username}]: ")
    try:
        wapi.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        if debug:
            log.info(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
        print(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
    if network_check:
        # TODO: Fix code duplication
        new_imports = []
        networks = get_network(debug)
        with open(file, newline="") as nios_network_file:
            new_networks = csv.DictReader(nios_network_file)
            for n in new_networks:
                import_check = ipaddress.IPv4Network(
                    f"{n["address"]}/{n["netmask"]}", strict=False
                )
                new_imports.append(
                    {
                        "network": str(import_check),
                        "comment": n["comment"],
                        "network_view": n["network_view"],
                    }
                )
        if networks:
            grid_by_net = {net["network"]: net for net in networks}
            import_by_net = {net["network"]: net for net in new_imports}
            overlap_networks = grid_by_net.keys() & import_by_net.keys()
            only_in_grid = grid_by_net.keys() - import_by_net.keys()
            only_in_import = import_by_net.keys() - grid_by_net.keys()
            table = Table(
                "Network",
                "Grid Network View",
                "Import Network View",
                "Grid Comment",
                "Import Comment",
                title="Overlapping Networks: Grid vs Import",
            )
            for net in overlap_networks:
                g = grid_by_net[net]
                i = import_by_net[net]
                table.add_row(
                    net,
                    g.get("network_view"),
                    i.get("network_view"),
                    g.get("comment"),
                    i.get("comment"),
                )
            Console().print(table)
            table = Table("Network", "Comment", title="NIOS Only")
            for net in only_in_grid:
                g = grid_by_net[net]
                table.add_row(net, g.get("comment"))
            Console().print(table)
            table = Table("Network", "Comment", title="Import Only")
            for net in only_in_import:
                i = import_by_net[net]
                table.add_row(net, i.get("comment"))
            Console().print(table)
        else:
            print("Error: Review network retreival")
    elif range_check:
        # TODO: Display differences from both places (grid vs import file)
        # FIXME: rearrange compare logic and reverse logic for checking
        new_range_imports = []
        ranges = get_range(debug)
        with open(file, newline="") as nios_range_file:
            new_ranges = csv.DictReader(nios_range_file)
            for n in new_ranges:
                new_range_imports.append(
                    {
                        "start_addr": n["start_address"],
                        "end_addr": n["end_address"],
                        "network_view": n["network_view"],
                    }
                )
        if ranges:
            for r in ranges:
                overlap = any(
                    r["start_addr"] in range["start_addr"]
                    for range in new_range_imports
                )
                if overlap:
                    overlap_end = any(
                        r["end_addr"] in range["end_addr"]
                        for range in new_range_imports
                    )
                    if overlap_end:
                        print(
                            f"Potential Range Overlap: {r["start_addr"]} {r["end_addr"]} {r["network_view"]}"
                        )
                    else:
                        print(
                            f"Dhcp Range sized differently: {r["start_addr"]} {r["end_addr"]}"
                        )
                else:
                    if debug:
                        print(f"No Overlap Found: {r["start_addr"]} {r["end_addr"]}")
    elif fixed_check:
        # FIXME: rearrange compare logic and reverse logic for checking
        new_fixed_imports = []
        fixed_addresses = get_fixed(debug)
        with open(file, newline="") as nios_fixed_file:
            new_fixed = csv.DictReader(nios_fixed_file)
            for n in new_fixed:
                new_fixed_imports.append(
                    {
                        "ipv4addr": n["ip_address"],
                        "name": n["name"],
                        "mac": n["mac_address"],
                        "comment": n["comment"],
                    }
                )
        if fixed_addresses:
            for f in fixed_addresses:
                overlap = any(
                    f["ipv4addr"] in fixed["ipv4addr"] for fixed in new_fixed_imports
                )
                if overlap:
                    if "name" in f:
                        print(
                            f"Potential Overlap Found: {f["name"]} {f["ipv4addr"]} {f["network_view"]}"
                        )
                    else:
                        print(
                            f"Potential Overlap Found: {f["mac"]} {f["ipv4addr"]} {f["network_view"]}"
                        )
                else:
                    if debug:
                        print(f"No Overlap {f["ipv4addr"]}")
    else:
        print("Invalid option provided")
    sys.exit()


def get_network(debug):
    try:
        nios_network = wapi.get(
            "network",
            params={
                "_max_results": 150000,
                "_return_fields": ["network", "netmask", "comment", "network_view"],
            },
        )
        if nios_network.status_code != 200:
            if debug:
                print(
                    f"{nios_network.status_code}: {nios_network.json().get('code')}: {nios_network.json().get('text')}"
                )
            log.error(
                f"{nios_network.status_code}: {nios_network.json().get('code')}: {nios_network.json().get('text')}"
            )
        else:
            if debug:
                log.info(nios_network.json())
            return nios_network.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def get_range(debug):
    try:
        nios_range = wapi.get(
            "range",
            params={
                "_max_results": 150000,
                "_return_fields": [
                    "network",
                    "start_addr",
                    "end_addr",
                    "comment",
                    "network_view",
                ],
            },
        )
        if nios_range.status_code != 200:
            if debug:
                print(
                    f"{nios_range.status_code}: {nios_range.json().get('code')}: {nios_range.json().get('text')}"
                )
            log.error(
                f"{nios_range.status_code}: {nios_range.json().get('code')}: {nios_range.json().get('text')}"
            )
        else:
            if debug:
                log.info(nios_range.json())
            return nios_range.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def get_fixed(debug):
    try:
        nios_fixed = wapi.get(
            "fixedaddress",
            params={
                "_max_results": 150000,
                "_return_fields": [
                    "name",
                    "ipv4addr",
                    "comment",
                    "network_view",
                    "mac",
                ],
            },
        )
        if nios_fixed.status_code != 200:
            if debug:
                print(
                    f"{nios_fixed.status_code}: {nios_fixed.json().get('code')}: {nios_fixed.json().get('text')}"
                )
            log.error(
                f"{nios_fixed.status_code}: {nios_fixed.json().get('code')}: {nios_fixed.json().get('text')}"
            )
        else:
            if debug:
                log.info(nios_fixed.json())
            return nios_fixed.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


if __name__ == "__main__":
    main()
