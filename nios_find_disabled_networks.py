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
Basic Infoblox script using to retrieve DNS views from Infoblox grid
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
    networks = get_network(debug)
    report_network(grid_mgr, networks)
    sys.exit()


def get_network(debug):
    try:
        # Retrieve networks from Infoblox appliance
        networks = wapi.get(
            "network",
            params={
                "_max_results": 100000,
                "_return_fields": ["network", "comment", "disable", "members"],
            },
        )
        if networks.status_code != 200:
            if debug:
                print(networks.status_code, networks.text)
            log.error(networks.status_code, networks.text)
        else:
            if debug:
                log.info(networks.json())
            return networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_network(grid_mgr, networks):
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Network", justify="center"),
        Column(header="Comment", justify="center"),
        Column(header="Disabled", justify="center"),
        Column(header="Members", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} DNS Views",
        box=box.SIMPLE,
    )
    for n in networks:
        if n["disable"]:
            disabled = "[green]True"
        else:
            disabled = "[red]False"
        if n["comment"]:
            comment = n["comment"]
        else:
            comment = "None"
        table.add_row(n["_ref"], n["network"], comment, disabled, str(n["members"]))
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
