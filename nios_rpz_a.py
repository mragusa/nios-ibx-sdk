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
Interact with RPZ A records in NIOS grid

An RPZ Substitute (A Record) Rule maps a domain name to a substitute IPv4 address. To define a specific name-to-address mapping, add an Substitute (A Record) Rule to a previously defined Response Policy Zone.

This record represents the substitution rule for DNS A records.

WAPI Documentation: https://ipam.illinois.edu/wapidoc/objects/record.rpz.a.html 
Admin Documentation: https://docs.infoblox.com/space/nios90/280400764/Infoblox+DNS+Firewall
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option(
    "-rz", "--rpzone", help="response policy zone in which the record resides"
)
@optgroup.option("-n", "--name", help="The name for a record in FQDN format")
@optgroup.option("-i", "--ipv4addr", help="IPv4 Address of the substitute rule")
@optgroup.option("-a", "--add", is_flag=True, help="Add RPZ A record")
@optgroup.option("-u", "--update", is_flag=True, help="Update RPZ A record")
@optgroup.option("-d", "--delete", is_flag=True, help="Delete RPZ A record")
@optgroup.group("Optional Parameters")
@optgroup.option("--use_ttl", is_flag=True, help="Use flag for: ttl")
@optgroup.option(
    "--ttl",
    help="Time To Live (TTL) value for record. A 32-bit unsigned integer that represents the duration, in seconds, for which the record is valid (cached)",
)
@optgroup.option("--view", help="name of the DNS View in which the record resides")
@optgroup.option("--zone", help="name of the zone in which the record resides")
@optgroup.option("--comment", help="comment for the record")
@optgroup.option(
    "--disable", is_flag=True, help="Determines if the record is disabled or not"
)
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
@optgroup.option("--debug", is_flag=True, help="enable verbose debug output")
def main(
    grid_mgr: str,
    username: str,
    wapi_ver: str,
    debug: bool,
    rpzone: str,
    name: str,
    ipv4addr: str,
    use_ttl: bool,
    ttl: int,
    view: str,
    zone: str,
    comment: str,
    disable: bool,
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

    payload = {"name": name,}

    if rpzone:
        payload.update({"rp_zone": rpzone})
    if ipv4addr:
        payload.update({"ipv4addr": ipv4addr})
    if comment:
        payload.update({"comment": comment})
    if disable:
        payload.update({"disable": True})
    if ttl:
        payload.update({"ttl": ttl})
    if use_ttl:
        payload.update({"use_ttl": True})
    if view:
        payload.update({"view": view})
    if zone:
        payload.update({"zone": zone})

    if add:
        try:
            add_rpz_a = wapi.post(
                "record:rpz:a", json=payload
            )
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if add_rpz_a.status_code != 201:
            log.error("RPZ record failed: %s", name)
        else:
            log.info("RPZ record added: %s", name)
    if update or delete:
        try:
            # Retrieve RPZ A record from Infoblox appliance
            rpz_a = wapi.get("record:rpz:a", params={"name": name})
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if rpz_a.status_code != 200:
            log.error("RPZ record not found: %s", rpz_a.text)
        else:
            log.info("RPZ record found: %s", rpz_a.json())
            rpz_a_record = rpz_a.json()
            if update:
                try:
                    update_rpz_a = wapi.put(rpz_a_record["_ref"], json={payload})
                except WapiRequestException as err:
                    log.error(err)
                    sys.exit(1)
                if update_rpz_a.status_code != 200:
                    log.error("RPZ record update failed: %s". update_rpz_a.text)
                else:
                    log.info("RPZ record update completed: %s". update_rpz_a.json())
            if delete:
                try:
                    del_rpz_a = wapi.delete(rpz_a_record["_ref"])
                except WapiRequestException as err:
                    log.error(err)
                    sys.exit(1)

    sys.exit()


if __name__ == "__main__":
    main()
