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
Upload NIOS BIN file to Infoblox appliance and initate the file distribution and upgrade
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-f", "--file", required=True, help="NIOS BIN file")
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
def main(grid_mgr: str, file: str, username: str, wapi_ver: str, debug: bool) -> None:
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
    upgrade_bin_token = wapi.file_upload(file)
    print(f"Setting upgrade BIN file {file}")
    wapi.post(
        "fileop", params={"_function": "set_upgrade_file", "token": upgrade_bin_token}
    )
    print(f"Initating upload on {grid_mgr}")
    wapi.post("grid", params={"_function": "UPLOAD"})
    print(f"Beginning file distribution on {grid_mgr}")
    wapi.post("grid", params={"_function": "DISTRIBUTION_START"})
    print(f"Beginning upgrade test distribution on {grid_mgr}")
    wapi.post("grid", params={"_function": "UPGRADE_TEST_START"})
    print(f"Starting upgrade on {grid_mgr}")
    wapi.post("grid", params={"_function": "UPGRADE"})
    sys.exit()


if __name__ == "__main__":
    main()
