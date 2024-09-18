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
Interact with RPZ NAPTR records in NIOS grid

An RPZ Substitute (NAPTR Record) Rule object represents the substitution rule for DNS Naming Authority Pointer (NAPTR) records. This rule specifies a regular expression-based rewrite rule that, when applied to an existing string, produces a new domain name or URI.

WAPI Documentation: https://ipam.illinois.edu/wapidoc/objects/record.rpz.naptr.html 

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
@optgroup.option("-f", "--flags", type=click.Choice(['U', 'S', 'P', 'A'], case_sensitive=True)), help="The flags used to control the interpretation of the fields for a Substitute (NAPTR Record) Rule object. Supported values for the flags field are “U”, “S”, “P” and “A”.")
@optgroup.option("-o", "--order", type=int, help="The order parameter of the Substitute (NAPTR Record) Rule records. This parameter specifies the order in which the NAPTR rules are applied when multiple rules are present. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format.")
@optgroup.option("-p", "--preference", type=int, help="The preference of the Substitute (NAPTR Record) Rule record. The preference field determines the order NAPTR records are processed when multiple records with the same order parameter are present. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format.")
@optgroup.option("-r", "--replacement", help="The replacement field of the Substitute (NAPTR Record) Rule object. For nonterminal NAPTR records, this field specifies the next domain name to look up. This value can be in unicode format.")
@optgroup.option("-a", "--add", is_flag=True, help="Add RPZ A record")
@optgroup.option("-u", "--update", is_flag=True, help="Update RPZ A record")
@optgroup.option("-d", "--delete", is_flag=True, help="Delete RPZ A record")
@optgroup.group("Optional Parameters")
@optgroup.options("--services", help="The services field of the Substitute (NAPTR Record) Rule object; maximum 128 characters. The services field contains protocol and service identifiers, such as “http+E2U” or “SIPS+D2T”.")
@optgroup.options("--regex", help="The regular expression-based rewriting rule of the Substitute (NAPTR Record) Rule record. This should be a POSIX compliant regular expression, including the substitution rule and flags. Refer to RFC 2915 for the field syntax details.")
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
    flags: str,
    order: int,
    preference: int,
    regexp: str,
    replacement: str,
    services: str,
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
    if flags:
        payload.update({"flags": flags})
    if order:
        payload.update({"order": order})
    if prefernce:
        payload.update({"preference": preference})
    if regexp:
        payload.update({"regexp": regexp})
    if replacement:
        payload.update({"replacement": replacement})
    if services:
        payload.update({"services": services})
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
            add_rpz_naptr = wapi.post("record:rpz:naptr", json=payload)
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if add_rpz_naptr.status_code != 201:
            log.error("RPZ record failed: %s", name)
        else:
            log.info("RPZ record added: %s", name)
    if update or delete:
        try:
            # Retrieve RPZ NAPTR record from Infoblox appliance
            rpz_naptr = wapi.get("record:rpz:naptr", params={"name": name})
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if rpz_naptr.status_code != 200:
            log.error("RPZ record not found: %s", rpz_naptr.text)
        else:
            log.info("RPZ record found: %s", rpz_naptr.json())
            rpz_naptr_record = rpz_naptr.json()
            if update:
                try:
                    update_rpz_naptr = wapi.put(rpz_naptr_record["_ref"], json={payload})
                except WapiRequestException as err:
                    log.error(err)
                    sys.exit(1)
                if update_rpz_naptr.status_code != 200:
                    log.error("RPZ record update failed: %s".update_rpz_naptr.text)
                else:
                    log.info("RPZ record update completed: %s".update_rpz_naptr.json())
            if delete:
                try:
                    del_rpz_naptr = wapi.delete(rpz_naptr_record["_ref"])
                except WapiRequestException as err:
                    log.error(err)
                    sys.exit(1)

    sys.exit()


if __name__ == "__main__":
    main()
