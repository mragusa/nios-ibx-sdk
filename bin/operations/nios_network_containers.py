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

help_text = """
Infoblox script using to retrieve network containers from Infoblox grid
"""


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
            log.info("Connected to Infoblox grid manager %s", wapi.grid_mgr)
        print("Connected to Infoblox grid manager %s", wapi.grid_mgr)
    network_containers = get_network_containers(debug)
    report_network_containers(grid_mgr, network_containers)
    sys.exit()


def get_network_containers(debug):
    try:
        # Retrieve dns view from Infoblox appliance
        net_containers = wapi.get(
            "networkcontainers",
            params={
                "_max_results": 5000,
                "_return_fields": ["network", "comment", "network_view"],
            },
        )
        if net_containers.status_code != 200:
            if debug:
                print(net_containers.status_code, net_containers.text)
            log.error(net_containers.status_code, net_containers.text)
        else:
            if debug:
                log.info(net_containers.json())
            return net_containers.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_network_containers(grid_mgr, network_containers):
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Network", justify="center"),
        Column(header="Comment", justify="center"),
        Column(header="Network View", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} Network Containers",
        box=box.SIMPLE,
    )
    for nc in network_containers:
        table.add_row(nc["_ref"], nc["network"], nc["comment"], nc["network_view"])
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
