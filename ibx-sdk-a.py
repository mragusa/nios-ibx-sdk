#!/usr/bin/env python3


import getpass
import sys
import click
from click_option_group import optgroup
fromt datetime import date

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
Edit as Needed
"""
current_time = date.today()

@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("--add", is_flag=True, help="Add record"))
@optgroup.option("--delete", is_flag=True, help="Delete record"))
@optgroup.option("--update", is_flag=True, help="Update record"))

@optgroup.option("-f", "--fqdn", show_default=True, help="FQDN")
@optgroup.option("-i", "--ip", show_default=True, help="IP address")
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
@optgroup.option("-t", "--ttl", default=600, help="TTL in seconds") 
@optgroup.option("-d", "--disable", is_flag=False, help="Disable record")
@optgroup.option("-c", "--comment", default="created on {current_time}", help="comment for record")

@optgroup.group("Logging Parameters")
@optgroup.option("--debug", is_flag=True, help="enable verbose debug output")

def main(grid_mgr: str, add: bool, delete: bool, update: bool, username: str, wapi_ver: str, debug: bool, fqdn: str, ip: str, ttl: int, disable: bool, comment: str) -> None:
    if debug:
        increase_log_level()
    wapi.grid_mgr = grid_mgr
    wapi.wapi_ver = wapi_ver
    password = getpass.getpass(f"Enter password for [{username}]: ")
    try:
        wapi.connect(username=username, password=password)
    except WapiRequest as err:
        log.error(err)
        sys.exit(1)
    else:
        log.info("connected to Infoblox grid manager %s", wapi.grid_mgr)
    if add:
	    try:
	        # Retrieve network view from Infoblox appliance
	        a_record = wapi.post("record:a", json={"name": fqdn, "ipv4addr": ip, "comment": comment, "disable": disable, "ttl": ttl})
	        if a_record.status_code != 201:
	            print(f"Record creation failed {a_record.text}")
	        else:
	            print(f"Record creation successful {a_record.json()}")
	    except WapiRequestException as err:
	        log.error(err)
	        sys.exit(1)
    if delete:
    if update

    sys.exit()


if __name__ == "__main__":
    main()
