#!/usr/bin/env python3
# TODO: clean up sucess print messages


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
Script to interface with A records inside of an Infoblox grid.

Operations: \n
    - Add \n
    - Delete \n
    - Update \n

Script operations are logged to wapi.log inside of current working directory. \n
Update operations support modifying TTL, FQDN, and IP address. \n
TTL defaults to 600 seconds for new records and 5 seconds for IP address updates. \n
"""
current_time = date.today()


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-f", "--fqdn", required=True, show_default=True, help="FQDN")
@optgroup.option("-i", "--ip", required=True, show_default=True, help="IP address")
@optgroup.group("Operationational Parameters")
@optgroup.option("--add", is_flag=True, default=False, help="Add A record")
@optgroup.option("--delete", is_flag=True, default=False, help="Delete A record")
@optgroup.option("--update", is_flag=True, default=False, help="Update A record")
@optgroup.group("Optional Parameters")
@optgroup.option(
    "-u",
    "--username",
    default="admin",
    show_default=True,
    help="Infoblox admin username",
)
@optgroup.option(
    "-w", "--wapi-ver", default="2.13", show_default=True, help="Infoblox WAPI version"
)
@optgroup.option("-t", "--ttl", show_default=True, default=600, help="TTL in seconds")
@optgroup.option(
    "-d",
    "--disable",
    is_flag=True,
    default=False,
    show_default=True,
    help="Disable record",
)
@optgroup.option(
    "-c",
    "--comment",
    show_default=True,
    default=current_time,
    help="Comment for record: default is creation date",
)
@optgroup.option("-v", "--view", show_default=True, default="default", help="DNS view")
@optgroup.group("Update Parameters")
@optgroup.option("--newname", help="New Hostname")
@optgroup.option("--newip", help="New IP Address")
@optgroup.option("--newttl", show_default=True, default=5, help="New TTL")
@optgroup.group("Logging Parameters")
@optgroup.option(
    "--debug", is_flag=True, default=False, help="enable verbose debug output"
)
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
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        log.info("connected to Infoblox grid manager %s", wapi.grid_mgr)
    if add:
        add_arecord(fqdn, ip, comment, disable, ttl)
    if delete:
        del_arecord(fqdn, ip, view)
    if update:
        update_arecord(fqdn, ip, view, newip, newname, newttl)
    sys.exit()


def add_arecord(fqdn, ip, comment, disable, ttl):
    print(f"Creating {fqdn} {ip} {comment} Disabled: {disable}")
    log.info(f"Creating {fqdn} {ip} {comment} Disabled: {disable}")
    try:
        # Add A record to infoblox dns zone
        a_record = wapi.post(
            "record:a",
            json={
                "name": fqdn,
                "ipv4addr": ip,
                "comment": comment,
                "disable": disable,
                "ttl": ttl,
            },
        )
        if a_record.status_code != 201:
            print(
                f"Record creation failed: {a_record.status_code} {a_record.json().get('code')} {a_record.json().get('text')}"
            )
            log.error(
                f"Record creation failed: {a_record.status_code} {a_record.json().get('code')} {a_record.json().get('text')}"
            )
        else:
            print(f"Record creation successful {a_record.json()}")
            log.info(f"Record creation successful {a_record.json()}")
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def del_arecord(fqdn, ip, view):
    print(f"Deleting {fqdn} {ip} View: {view}")
    log.info(f"Deleting {fqdn} {ip} View: {view}")
    try:
        # Delete A record from infoblox zone
        a_record_ref = wapi.getone(
            "record:a", json={"name": fqdn, "ipv4addr": ip, "view": view}
        )
        a_record_delete = wapi.delete(a_record_ref)
        if a_record_delete.status_code != 200:
            print(
                f"Record deletion failed: {a_record_delete.status_code} {a_record_delete.json().get('code')} {a_record_delete.json().get('text')}"
            )
            log.error(
                f"Record deletion failed: {a_record_delete.status_code} {a_record_delete.json().get('code')} {a_record_delete.json().get('text')}"
            )
        else:
            print(f"Record deletion successful {a_record_delete.json()}")
            log.info(f"Record deletion successful {a_record_delete.json()}")
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def update_arecord(fqdn, ip, view, newip, newname, newttl):
    print(f"Updating {fqdn} {ip} View: {view}")
    log.info(f"Updating {fqdn} {ip} View: {view}")
    updated_rdata = ""
    try:
        # Update existing A record
        a_record_ref = wapi.getone(
            "record:a", json={"name": fqdn, "ipv4addr": ip, "view": view}
        )
        if newip and newttl:
            updated_rdata = {"ttl": newttl, "ipv4addr": newip}
        if newname:
            updated_rdata = {"name": newname}
        if updated_rdata:
            try:
                a_record_update = wapi.put(a_record_ref, json=updated_rdata)
                if a_record_update.status_code != 200:
                    print(
                        f"Record update failed: {a_record_update.status_code} {a_record_update.json().get('code')} {a_record_update.json().get('text')}"
                    )
                    log.error(
                        f"Record update failed: {a_record_update.status_code} {a_record_update.json().get('code')} {a_record_update.json().get('text')}"
                    )
                else:
                    print(f"Record update successful {a_record_update.json()}")
                    log.info(f"Record update successful {a_record_update.json()}")
            except WapiRequestException as err:
                print(err)
                log.error(err)
        else:
            print("Updated Rdata not provided")
            log.info("Updated Rdata not provided")
            sys.exit(1)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


if __name__ == "__main__":
    main()
