#!/usr/bin/env python3


import getpass
import sys
import click
from click_option_group import optgroup
from ibx_sdk.logger.ibx_logger import init_logger, increase_log_level
from ibx_sdk.nios.exceptions import WapiRequestException
from ibx_sdk.nios.gift import Gift

log = init_logger(
    logfile_name="wapi.log",
    logfile_mode="a",
    console_log=True,
    level="info",
    max_size=100000,
    num_logs=1,
)

old_grid = Gift()
new_grid = Gift()

help_text = """
Basic Infoblox script to compare networks between Infoblox grids
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--new-grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-o", "--old-grid-mgr", required=True, help="Infoblox Grid Manager")
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
    old_grid_mgr: str, new_grid_mgr: str, username: str, wapi_ver: str, debug: bool
) -> None:
    if debug:
        increase_log_level()
    old_grid.grid_mgr = old_grid_mgr
    old_grid.wapi_ver = wapi_ver
    old_grid.timeout = 600

    new_grid.grid_mgr = new_grid_mgr
    new_grid.wapi_ver = wapi_ver
    new_grid.timeout = 600
    password = getpass.getpass(f"Enter password for [{username}]: ")
    try:
        old_grid.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        if debug:
            log.info(f"Connected to Infoblox grid manager {old_grid.grid_mgr}")
        print(f"Connected to Infoblox grid manager {old_grid.grid_mgr}")

    try:
        new_grid.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        if debug:
            log.info(f"Connected to Infoblox grid manager {new_grid.grid_mgr}")
        print(f"Connected to Infoblox grid manager {new_grid.grid_mgr}")

    old_grid_networks = get_networks(old_grid, debug)
    new_grid_networks = get_networks(new_grid, debug)
    if old_grid_networks and new_grid_networks:
        print("Origin Grid: ", len(old_grid_networks))
        print("Destination Grid: ", len(new_grid_networks))
        old_networks = {n["network"] for n in old_grid_networks}
        new_networks = {n["network"] for n in new_grid_networks}
        only_in_old = old_networks - new_networks
        old_in_new = new_networks - old_networks
        # in_both = old_networks & new_networks
        print("Only in Origin: ", only_in_old)
        print("Only in Destination: ", old_in_new)
        # print("In Both: ", in_both)
    sys.exit()


def get_networks(wapi, debug):
    try:
        # Retrieve networks from Infoblox appliance
        nios_networks = wapi.get(
            "network",
            params={
                "_max_results": 110000,
                "_return_fields": ["network", "network_view", "comment"],
            },
        )
        if nios_networks.status_code != 200:
            if debug:
                print(
                    f"{nios_networks.status_code}: {nios_networks.json().get('code')}: {nios_networks.json().get('text')}"
                )
            log.error(
                f"{nios_networks.status_code}: {nios_networks.json().get('code')}: {nios_networks.json().get('text')}"
            )
        else:
            if debug:
                log.info(nios_networks.json())
            return nios_networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


if __name__ == "__main__":
    main()
