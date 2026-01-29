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
Infoblox script to create/remove/update NIOS host records 
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
@optgroup.group("Host Record Options")
@optgroup.option("-n", "--name", help="Hostname of host record")
@optgroup.option("--ipv4", help="IPv4 address for host record")
@optgroup.group("Host Record Actions")
@optgroup.option(
    "-g", "--get", is_flag=True, default=False, help="Get host record information"
)
@optgroup.option(
    "-a", "--add", is_flag=True, default=False, help="Add NIOS host record"
)
@optgroup.option(
    "-d", "--delete", is_flag=True, default=False, help="Delete NIOS host record"
)
@optgroup.option(
    "-u", "--update", is_flag=True, default=False, help="Update NIOS host record"
)
@optgroup.option(
    "-c",
    "--convert",
    is_flag=True,
    default=False,
    help="Convert existing A/PTR/CNAME to Host Record",
)
def main(
    grid_mgr: str,
    username: str,
    wapi_ver: str,
    debug: bool,
    name: str,
    get: bool,
    add: bool,
    delete: bool,
    convert: bool,
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
        host = get_host(debug, name)
        report_host(grid_mgr, host)
    sys.exit()


def get_host(debug, name):
    try:
        # Retrieve host records from Infoblox appliance
        nios_host = wapi.get(
            "record:host",
            params={
                "_max_results": 5000,
                "_return_fields": [
                    "name",
                    "comment",
                    "aliases",
                    "network_view",
                    "view",
                ],
                "name": name,
            },
        )
        if nios_host.status_code != 200:
            if debug:
                print(
                    f"{nios_host.status_code}: {nios_host.json().get('code')}: {nios_host.json().get('text')}"
                )
            log.error(
                f"{nios_host.status_code}: {nios_host.json().get('code')}: {nios_host.json().get('text')}"
            )
        else:
            if debug:
                log.info(nios_host.json())
            return nios_host.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_host(grid_mgr, host):
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Name", justify="center"),
        Column(header="Comment", justify="center"),
        Column(header="Alias", justify="center"),
        Column(header="Network View", justify="center"),
        Column(header="View", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} Host Record",
        box=box.SIMPLE,
    )
    for h in host:
        table.add_row(
            h["_ref"],
            h["name"],
            h["comment"],
            h["aliases"],
            h["network_view"],
            h["view"],
        )
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
