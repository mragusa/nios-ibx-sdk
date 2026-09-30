#!/usr/bin/env python3
# TODO: Add additional debug output
# TODO: Improve console output


import getpass
import json
import sys

import click
from click_option_group import optgroup
from ibx_sdk.logger.ibx_logger import increase_log_level, init_logger
from ibx_sdk.nios.exceptions import WapiRequestException
from ibx_sdk.nios.gift import Gift
from rich import box
from rich.console import Console
from rich.table import Table

log = init_logger(
    logfile_name="wapi.log",
    logfile_mode="a",
    console_log=False,
    level="info",
    max_size=100000,
    num_logs=1,
)

wapi = Gift()
console = Console()

help_text = """
Script to get/add/delete/update extensible attributes on NIOS Network Objects
"""


def get_networks(debug, count, filter):
    try:
        # Retrieve networks from Infoblox appliance
        if filter:
            networks = wapi.get(
                "network",
                params={
                    "ipv4addr": filter,
                    "_max_results": count,
                    "_return_fields": ["ipv4addr", "comment", "extattrs"],
                },
            )
        else:
            networks = wapi.get(
                "network",
                params={
                    "_max_results": count,
                    "_return_fields": ["ipv4addr", "comment", "extattrs"],
                },
            )
        if networks.status_code != 200:
            if debug:
                print(
                    f"{networks.status_code}: {networks.json().get('code')}: {networks.json().get('text')}"
                )
            log.error(
                f"{networks.status_code}: {networks.json().get('code')}: {networks.json().get('text')}"
            )
        else:
            if debug:
                log.info(networks.json())
            return networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_networks(grid_mgr, networks):
    table_column = ["IPv4 Address", "Comment", "Extensible Attributes"]
    table = Table(
        title=f"Infoblox Grid: {grid_mgr} Networks",
        box=box.SIMPLE,
        row_styles=["dim", ""],
    )
    for c in table_column:
        table.add_column(header=f"{c}", justify="center", no_wrap=True, highlight=True)
    for n in networks:
        extattrs = []
        if "comment" not in n:
            n["comment"] = "None"
        if "extattrs" in n:
            for e in n["extattrs"]:
                extattrs.append(f"{e} : {n['extattrs'][e]['value']}")
        table.add_row(
            n["ipv4addr"],
            n["comment"],
            str(("\n").join(extattrs)),
        )
    console.print(table)


def add_network_ea(filter, extattr):
    ea = {}
    nios_ea = dict(extattr)
    for e, value in nios_ea.items():
        ea[e] = {"value": value}
    network = wapi.get(
        "network",
        params={
            "ipv4addr": filter,
            "_return_fields": ["ipv4addr", "extattrs"],
        },
    )
    if network.status_code != 200:
        print(network.status_code, network.text)
    else:
        nios_network = network.json()
        extattr_status = wapi.put(
            nios_network[0]["_ref"], data=json.dumps({"extattrs+": ea})
        )
        if extattr_status.status_code != 200:
            print(f"Error: {extattr_status.status_code} {extattr_status.text}")
        else:
            print(f"Extensible Attribute Applied: {extattr_status.json()}")


def del_network_ea(filter, extattr):
    nios_ea = dict(extattr)
    network = wapi.get(
        "network",
        params={"ipv4addr": filter, "_return_fields": ["ipv4addr", "extattrs"]},
    )
    if network.status_code != 200:
        print(network.status_code, network.text)
    else:
        net = network.json()
        for e in nios_ea:
            ea_removal = wapi.put(
                net[0]["_ref"], data=json.dumps({"extattrs-": {e: {}}})
            )
            if ea_removal.status_code != 200:
                print(f"Error: {ea_removal.status_code} {ea_removal.text}")
            else:
                print(f"{e} removed from {filter}")


@click.command(
    help=help_text,
    context_settings={"max_content_width": 95, "help_option_names": ["-h", "--help"]},
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
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
    default="2.13.5",
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
@optgroup.group("List Options")
@optgroup.option(
    "-l", "--get", is_flag=True, default=False, help="List NIOS Network Objects"
)
@optgroup.option(
    "-c",
    "--count",
    default=100,
    show_default=True,
    help="NIOS Return Network Objects Count",
)
@optgroup.option(
    "-f", "--filter", help="Filter network based on Address block ie 10.0.0.0"
)
@optgroup.group("Add/Delete Options")
@optgroup.option(
    "-a",
    "--add",
    is_flag=True,
    default=False,
    help="Add Extensible Attribute or update if attribute is already assigned to object",
)
@optgroup.option(
    "-d",
    "--delete",
    is_flag=True,
    default=False,
    help="Delete Extensible Attribute",
)
@optgroup.option("-e", "--extattr", type=(str, str), multiple=True, help="NIOS ExtAttr")
def main(
    grid_mgr: str,
    username: str,
    wapi_ver: str,
    debug: bool,
    get: bool,
    count: int,
    filter: str,
    add: bool,
    delete: bool,
    extattr: str,
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
    if get:
        networks = get_networks(debug, count, filter)
        report_networks(grid_mgr, networks)
    if add:
        add_network_ea(filter, extattr)
    if delete:
        del_network_ea(filter, extattr)
    sys.exit()


if __name__ == "__main__":
    main()
