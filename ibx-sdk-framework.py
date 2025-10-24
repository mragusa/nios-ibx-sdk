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
            log.info(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
        print(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
    views = get_view(debug)
    report_view(grid_mgr, views)
    sys.exit()


def get_view(debug):
    try:
        # Retrieve dns view from Infoblox appliance
        dns_view = wapi.get(
            "view",
            params={
                "_max_results": 5000,
                "_return_fields": ["name", "comment", "recursion"],
            },
        )
        if dns_view.status_code != 200:
            if debug:
                print(dns_view.status_code, dns_view.text)
            log.error(dns_view.status_code, dns_view.text)
        else:
            if debug:
                log.info(dns_view.json())
            return dns_view.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_view(grid_mgr, view):
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Name", justify="center"),
        Column(header="Recursion", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} DNS Views",
        box=box.SIMPLE,
    )
    for v in view:
        recursion = ""
        if v["recursion"]:
            recursion = "[green]True"
        else:
            recursion = "[red]False"
        table.add_row(v["_ref"], v["name"], recursion)
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
