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
Enable Network Discovery on Infoblox networks and containers
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
    networks = get_networks(debug)
    enable_nd_network(networks)
    networks = get_networks(debug)
    report_network(grid_mgr, networks)
    sys.exit()


def get_networks(debug):
    try:
        # Retrieve dns view from Infoblox appliance
        nios_networks = wapi.get(
            "network",
            params={
                "_max_results": 5000,
                "_return_fields": [
                    "network",
                    "comment",
                    "enable_discovery",
                    "discovery_member",
                ],
            },
        )
        if nios_networks.status_code != 200:
            if debug:
                print(nios_networks.status_code, nios_networks.text)
            log.error(nios_networks.status_code, nios_networks.text)
        else:
            if debug:
                log.info(nios_networks.json())
            return nios_networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def enable_nd_network(networks):
    if networks:
        for n in networks:
            enable_status = wapi.put(
                n["_ref"],
                params={
                    "discovery_member": "sripaplt21usb05.net.us.corp",
                    "enable_discovery": True,
                },
            )
            if enable_status.status_code != 200:
                log.error(enable_status.status_code, enable_status.text)
            else:
                print(f"Network discovery enabled on {n["network"]}")
    else:
        log.error("Network object not provided")


def report_network(grid_mgr, network):
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Network", justify="center"),
        Column(header="Discovery Member", justify="center"),
        Column(header="Enable Discovery", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} Networks",
        box=box.SIMPLE,
    )
    for n in network:
        discovery_enabled = ""
        if n["enable_discovery"]:
            discovery_enabled = "[green]True"
        else:
            discovery_enabled = "[red]False"
        table.add_row(n["_ref"], n["network"], n["discovery_member"], discovery_enabled)
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
