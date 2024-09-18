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
Interact with RPZ CNAME records in NIOS grid

An RPZ CNAME record represents different RPZ rules, depending on the value of the canonical name. The intention of this object is to support QNAME Trigger policy. The QNAME policy trigger applies to requested domain names (QNAME). This record represents Passthru Domain Name Rule, Block Domain Name (No Such Domain) Rule, Block Domain Name (No Data) Rule and Substitute (Domain Name) Rule.

If canonical name is empty, it is a Block Domain Name (No Such Domain) Rule.

If canonical name is asterisk, it is a Block Domain Name (No Data) Rule.

If canonical name is the same as record name, it is a Passthru Domain Name Rule. If name of object starts with wildcard you must specify special value ‘infoblox-passthru’ in canonical name in order to create Wildcard Passthru Domain Name Rule, for more details please see the Infoblox Administrator Guide.

If canonical name is not Block Domain Name (No Such Domain) Rule, Block Domain Name (No Data) Rule, or Passthru Domain Name Rule, it is a substitution rule.

WAPI Documentation: https://ipam.illinois.edu/wapidoc/objects/record.rpz.cname.html

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
@optgroup.option("-c", "--canonical", help="The canonical name in FQDN format")
@optgroup.option("-a", "--add", is_flag=True, help="Add RPZ CNAME record")
@optgroup.option("-u", "--update", is_flag=True, help="Update RPZ CNAME record")
@optgroup.option("-d", "--delete", is_flag=True, help="Delete RPZ CNAME record")
@optgroup.group("Optional Parameters")
@optgroup.option("--use_ttl", is_flag=True, help="Use flag for: ttl")
@optgroup.option(
    "--ttl",
    type=int,
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
    canonical: str,
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

    payload = {
        "name": name,
    }

    if rpzone:
        payload.update({"rp_zone": rpzone})
    if ipv4addr:
        payload.update({"canonical": canonical})
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
            add_rpz_cname = wapi.post("record:rpz:cname", json=payload)
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if add_rpz_cname.status_code != 201:
            log.error("RPZ record failed: %s", name)
        else:
            log.info("RPZ record added: %s", name)
    if update or delete:
        try:
            # Retrieve RPZ CNAME record from Infoblox appliance
            rpz_cname = wapi.get("record:rpz:cname", params={"name": name})
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if rpz_cname.status_code != 200:
            log.error("RPZ record not found: %s", rpz_cname.text)
        else:
            log.info("RPZ record found: %s", rpz_cname.json())
            rpz_cname_record = rpz_cname.json()
            if update:
                try:
                    update_rpz_cname = wapi.put(
                        rpz_cname_record["_ref"], json={payload}
                    )
                except WapiRequestException as err:
                    log.error(err)
                    sys.exit(1)
                if update_rpz_cname.status_code != 200:
                    log.error("RPZ record update failed: %s".update_rpz_cname.text)
                else:
                    log.info("RPZ record update completed: %s".update_rpz_cname.json())
            if delete:
                try:
                    del_rpz_cname = wapi.delete(rpz_cname_record["_ref"])
                except WapiRequestException as err:
                    log.error(err)
                    sys.exit(1)

    sys.exit()


if __name__ == "__main__":
    main()
