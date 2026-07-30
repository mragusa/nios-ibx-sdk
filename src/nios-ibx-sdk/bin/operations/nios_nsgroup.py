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
Basic Infoblox script using to list and assign/unassign nsgroups to zones 
"""
# TODO:
# 1. assign / unassign to auth zones, fwd, delegated zones
# 2. list out all nsgroups
# 3. create nsgroups
# 4. delete nsgroups
# 5. fix help message


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
    nsgroups = get_nsgroup(debug)
    report_nsgroup(grid_mgr, nsgroups)
    sys.exit()


def get_nsgroup(debug):
    try:
        # Retrieve dns nsgroup from Infoblox appliance
        nsgroup = wapi.get(
            "nsgroup",
            params={
                "_max_results": 5000,
                "_return_fields": [
                    "name",
                    "comment",
                    "grid_primary",
                    "grid_secondaries",
                    "external_primaries",
                    "external_secondaries",
                    "use_external_primary",
                    "is_multimaster",
                    "is_grid_defaut",
                ],
            },
        )
        if nsgroup.status_code != 200:
            if debug:
                print(
                    f"{nsgroup.status_code}: {nsgroup.json().get('code')}: {nsgroup.json().get('text')}"
                )
            log.error(
                f"{nsgroup.status_code}: {nsgroup.json().get('code')}: {nsgroup.json().get('text')}"
            )
        else:
            if debug:
                log.info(nsgroup.json())
            return nsgroup.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_nsgroup(grid_mgr, nsgroup):
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Name", justify="center"),
        Column(header="Comment", justify="center"),
        Column(header="Grid Primary", justify="center"),
        Column(header="Grid Secondaries", justify="center"),
        Column(header="External Primary", justify="center"),
        Column(header="External Secondaries", justify="center"),
        Column(header="Use External Primary", justify="center"),
        Column(header="Multimaster", justify="center"),
        Column(header="Grid Default", justify="center"),
        title=f"Infoblox Grid : {grid_mgr} NSGroups",
        box=box.SIMPLE,
    )
    for n in nsgroup:
        table.add_row(
            n["_ref"],
            n["name"],
            n["comment"],
            n["grid_primary"],
            n["grid_secondaries"],
            n["external_primaries"],
            n["external_secondaries"],
            n["use_external_primary"],
            n["is_multimaster"],
            n["is_grid_defaut"],
        )
    console = Console()
    console.print(table)


if __name__ == "__main__":
    main()
