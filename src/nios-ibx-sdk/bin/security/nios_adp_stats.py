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

wapi = Gift()

help_text = """
Infoblox ADP Statistics
Retreieve grid statistics for the last 30 mins
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
    "-w", "--wapi-ver", default="2.11", show_default=True, help="Infoblox WAPI version"
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
    password = getpass.getpass(f"Enter password for [{username}]: ")
    try:
        wapi.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        log.info("connected to Infoblox grid manager %s", wapi.grid_mgr)
    try:
        # Retrieve ADP threat protection statistics
        adp_statistics = wapi.get("threatprotection:statistics")
        if adp_statistics.status_code != 200:
            if debug:
                print(f"threat protection statistics not found: {adp_statistics.text}")
            log.error("threat protection statistics not found %s", adp_statistics.text)
        else:
            if debug:
                print(f"threat protection statistics found: {adp_statistics.json()}")
            log.info("threat protection statistics found: %s", adp_statistics.json())
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)

    sys.exit()


if __name__ == "__main__":
    main()
