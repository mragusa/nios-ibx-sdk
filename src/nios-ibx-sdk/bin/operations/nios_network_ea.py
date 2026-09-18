#!/usr/bin/env python3


import getpass
import sys
import click
from click_option_group import optgroup
from ibx_sdk.logger.ibx_logger import init_logger, increase_log_level
from ibx_sdk.nios.exceptions import WapiRequestException
from ibx_sdk.nios.gift import Gift
from rich.console import Console
from rich.table import Column, Table
from rich import box

log = init_logger(
    logfile_name="wapi.log",
    logfile_mode="a",
    console_log=True,
    level="info",
    max_size=100000,
    num_logs=1,
)

wapi = Gift()
console = Console()

help_text = """
Script to add / delete extensible attributes from networks
"""


def get_networks(debug):
    try:
        # Retrieve dns view from Infoblox appliance
        networks = wapi.get(
            "network",
            params={
                "_max_results": 50000,
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
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="IPv4 Address", justify="center"),
        Column(header="Comment", justify="center"),
        Column(header="Extensible Attributes", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} Networks",
        box=box.SIMPLE,
    )
    for n in networks:
        if "comment" not in n:
            n["comment"] = "None"
        table.add_row(n["_ref"], n["ipv4addr"], n["comment"], str(n["extattrs"]))
    console.print(table)


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
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
def main(grid_mgr: str, username: str, wapi_ver: str, debug: bool) -> None:
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
    networks = get_networks(debug)
    report_networks(grid_mgr, networks)
    sys.exit()


if __name__ == "__main__":
    main()
