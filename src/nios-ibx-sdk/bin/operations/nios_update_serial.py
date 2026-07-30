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
Update SOA serial number on auth zone objects
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
@optgroup.option("-s", "--serial", default=1, help="New serial for auth zone object")
@optgroup.option(
    "-w",
    "--wapi-ver",
    default="2.12.3",
    show_default=True,
    help="Infoblox WAPI version",
)
@optgroup.group("Logging Parameters")
@optgroup.option("--debug", is_flag=True, help="enable verbose debug output")
def main(grid_mgr: str, username: str, serial: int, wapi_ver: str, debug: bool) -> None:
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
        log.info("Connected to Infoblox grid manager %s", wapi.grid_mgr)

    try:
        auth_zone = wapi.get(
            "zone_auth",
            params={"fqdn": "192.168.1.0/24", "_return_fields": ["soa_serial_number"]},
        )
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)

    if auth_zone.status_code != 200:
        print(auth_zone.status_code, auth_zone.text)
    else:
        updated_serial = {"soa_serial_number": serial, "set_soa_serial_number": True}
        zone = auth_zone.json()
        print(zone[0]["_ref"], zone[0]["soa_serial_number"])
        updated_zone = wapi.put(zone[0]["_ref"], json=updated_serial)
        if updated_zone.status_code != 200:
            print(updated_zone.status_code, updated_zone.text)
        else:
            print("Zone Updated", updated_zone.json())

    sys.exit()


if __name__ == "__main__":
    main()
