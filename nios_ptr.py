#!/usr/bin/env python3


import getpass
import sys
import click
from click_option_group import optgroup
from datetime import date

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
Script to interface with PTR records inside of an Infoblox grid.
Operations:
    Add
    Delete
    Update

Script operations are logged to wapi.log inside of present working directory. 
Update operations support modifying TTL, FQDN, and IP address.
TTL defaults to 600 seconds for new records and 5 seconds for IP address updates.
"""
current_time = date.today()


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-f", "--fqdn", required=True, show_default=True, help="ptrdname FQDN")
@optgroup.option("-i", "--ip", required=True, show_default=True, help="IP address")
@optgroup.group("Operationational Parameters")
@optgroup.option("--add", is_flag=True, help="Add record")
@optgroup.option("--delete", is_flag=True, help="Delete record")
@optgroup.option("--update", is_flag=True, help="Update record")
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
@optgroup.option("-d", "--disable", is_flag=True, help="Disable record")
@optgroup.option(
    "-c",
    "--comment",
    default=current_time,
    help="Comment for record: default is creation date",
)
@optgroup.option("-v", "--view", default="default", help="DNS view")
@optgroup.group("Update Parameters")
@optgroup.option("--newname", help="New Hostname")
@optgroup.option("--newip", help="New IP Address")
@optgroup.option("--newttl", default=5, help="New TTL")
@optgroup.group("Logging Parameters")
@optgroup.option("--debug", is_flag=True, help="enable verbose debug output")
def main(
    grid_mgr: str,
    add: bool,
    delete: bool,
    update: bool,
    username: str,
    wapi_ver: str,
    debug: bool,
    fqdn: str,
    ip: str,
    ttl: int,
    disable: bool,
    comment: str,
    view: str,
    newname: str,
    newip: str,
    newttl: int,
) -> None:
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
            # Add PTR record to infoblox dns zone
            ptr_record = wapi.post(
                "record:ptr",
                json={
                    "ptrdname": fqdn,
                    "ipv4addr": ip,
                    "comment": comment,
                    "disable": disable,
                    "ttl": ttl,
                },
            )
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if ptr_record.status_code != 201:
            print(f"Record creation failed {ptr_record.text}")
        else:
            print(f"Record creation successful {ptr_record.json()}")
    if delete:
        try:
            # Delete PTR record from infoblox zone
            ptr_record_ref = wapi.getone(
                "record:ptr", json={"ptrdname": fqdn, "ipv4addr": ip, "view": view}
            )
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
            ptr_record_delete = wapi.delete(ptr_record_ref)
        if ptr_record_delete.status_code != 200:
            print(f"Record deletion failed {ptr_record_delete.text}")
        else:
            print(f"Record deletion successful {ptr_record_delete.json()}")
    if update:
        try:
            # Update existing PTR record
            ptr_record_ref = wapi.getone(
                "record:ptr", json={"ptrdname": fqdn, "ipv4addr": ip, "view": view}
            )
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if newip and newttl:
            updated_rdata = {"ttl": newttl, "ipv4addr": newip}
        if newname:
            updated_rdata = {"ptrdname": newname}
            ptr_record = wapi.put(ptr_record_ref, json=updated_rdata)
        if ptr_record.status_code != 200:
            print(f"Record update failed {ptr_record.text}")
        else:
            print(f"Record update successful {ptr_record.json()}")

    sys.exit()


if __name__ == "__main__":
    main()
