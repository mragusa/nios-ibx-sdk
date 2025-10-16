#!/usr/bin/env python3
# TODO
# Add ability to check network containers

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

help_text = """
Display Network Discovery configuration for an Infoblox grid
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option(
    "-t",
    "--type",
    type=click.Choice(["report", "scan_status"]),
    default="report",
    show_default=True,
    help="Reporting Type",
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
def main(grid_mgr: str, username: str, wapi_ver: str, debug: bool, type: str) -> None:
    discovery_results = {
        "report": [
            "network",
            "comment",
            "enable_discovery",
            "use_enable_discovery",
            "discovery_member",
            "discovery_engine_type",
        ],
        "scan_status": ["network", "comment", "discover_now_status"],
    }
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
            log.info("Connected to Infoblox grid manager %s", wapi.grid_mgr)
        print(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
    networks = get_network(discovery_results[type], debug)
    report_network(grid_mgr, networks, type)
    sys.exit()


def get_network(type: list, debug):
    try:
        # Retrieve dns view from Infoblox appliance
        ibx_networks = wapi.get(
            "network",
            params={
                "_max_results": 100000,
                "_return_fields": type,
            },
        )
        if ibx_networks.status_code != 200:
            if debug:
                print(ibx_networks.status_code, ibx_networks.text)
            log.error(ibx_networks.status_code, ibx_networks.text)
        else:
            if debug:
                log.info(ibx_networks.json())
            return ibx_networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_network(grid_mgr: str, network, type: str):
    enDiscovery = ""
    enFlagDiscovery = ""
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Network", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} Network Discovery {type}",
        box=box.SIMPLE,
    )
    if type == "report":
        table.add_column("Discovery Enabled", justify="center")
        table.add_column("Discovery Use Flag", justify="center")
        table.add_column("Discovery Member", justify="center")
        table.add_column("Discovery Engine", justify="center")
    if type == "scan_status":
        table.add_column("Discovery Status", justify="center")
    for n in network:
        match (n["enable_discovery"], n["use_enable_discovery"]):
            case (True, True):
                enDiscovery = "[green]True"
                enFlagDiscovery = "[green]True"
            case (True, False):
                enDiscovery = "[green]True"
                enFlagDiscovery = "[red]False"
            case (False, True):
                enDiscovery = "[red]False"
                enFlagDiscovery = "[green]True"
            case (False, False):
                enDiscovery = "[red]False"
                enFlagDiscovery = "[red]False"
        if type == "report":
            table.add_row(
                n["_ref"],
                n["network"],
                enDiscovery,
                enFlagDiscovery,
                n["discovery_member"],
                n["discovery_engine_type"],
            )
        if type == "scan_status":
            table.add_row(n["_ref"], n["network"], n["discover_now_status"])
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
