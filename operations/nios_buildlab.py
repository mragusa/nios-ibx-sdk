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
Build basic record types inside of a lab for testing Grid/API functionality.
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.group("Optional Parameters")
@optgroup.option("-p", "--primary", help="Auth zone grid primary")
@optgroup.option("-s", "--secondary", help="Auth zone grid secondary")
@optgroup.option("-n", "--nsgroup", help="Auth zone name server group")
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
    primary: str,
    secondary: str,
    nsgroup: str,
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
    try:
        # Retrieve network view from Infoblox appliance
        network_view = wapi.get("view")
        print(network_view.json())
    except WapiRequestException as err:
        log.error(err)
        sys.exit(2)

    # Common record types
    record_types = [
        {
            "zone_auth": {
                "fqdn": "lab.domain.local",
                "comment": "This is a example forward zone",
            }
        },
        {
            "zone_auth": {
                "fqdn": "192.168.200.0/24",
                "zone_format": "IPV4",
                "comment": "This is an example reverse zone",
            }
        },
        {
            "record:a": {
                "name": "lab.domain.local",
                "ipv4addr": "192.168.200.100",
                "comment": "Example A record",
            }
        },
        {
            "record:a": {
                "name": "database.lab.domain.local",
                "ipv4addr": "192.168.200.200",
                "comment": "Example A record",
            }
        },
        {
            "record:a": {
                "name": "smtp1.lab.domain.local",
                "ipv4addr": "192.168.200.150",
                "comment": "Example A record",
            }
        },
        {
            "record:a": {
                "name": "smtp2.lab.domain.local",
                "ipv4addr": "192.168.200.151",
                "comment": "Example A record",
            }
        },
        {
            "record:a": {
                "name": "smtp3.lab.domain.local",
                "ipv4addr": "192.168.200.152",
                "comment": "Example A record",
            }
        },
        {
            "record:a": {
                "name": "smtp4.lab.domain.local",
                "ipv4addr": "192.168.200.153",
                "comment": "Example A record",
            }
        },
        {
            "record:cname": {
                "name": "www.lab.domain.local",
                "canonical": "lab.domain.local",
                "comment": "This is an example CNAME record",
            }
        },
        {
            "record:cname": {
                "name": "db.lab.domain.local",
                "canonical": "database.domain.local",
                "comment": "This is an example CNAME record",
            }
        },
        {
            "record:mx": {
                "name": "lab.domain.local",
                "preference": 20,
                "mail_exchanger": "smtp1.lab.domain.local",
                "comment": "This is an example MX record",
            }
        },
        {
            "record:mx": {
                "name": "lab.domain.local",
                "preference": 20,
                "mail_exchanger": "smtp2.lab.domain.local",
                "comment": "This is an example MX record",
            }
        },
        {
            "record:mx": {
                "name": "lab.domain.local",
                "preference": 40,
                "mail_exchanger": "smtp3.lab.domain.local",
                "comment": "This is an example MX record",
            }
        },
        {
            "record:mx": {
                "name": "lab.domain.local",
                "preference": 40,
                "mail_exchanger": "smtp4.lab.domain.local",
                "comment": "This is an example MX record",
            }
        },
        {
            "record:ptr": {
                "ipv4addr": "192.168.200.100",
                "ptrdname": "lab.domain.local",
                "comment": "This is an example PTR",
            }
        },
        {
            "record:ptr": {
                "ipv4addr": "192.168.200.200",
                "ptrdname": "database.lab.domain.local",
                "comment": "This is an example PTR",
            }
        },
        {
            "record:ptr": {
                "ipv4addr": "192.168.200.150",
                "ptrdname": "smtp1.lab.domain.local",
                "comment": "This is an example PTR",
            }
        },
        {
            "record:ptr": {
                "ipv4addr": "192.168.200.151",
                "ptrdname": "smtp2.lab.domain.local",
                "comment": "This is an example PTR",
            }
        },
        {
            "record:ptr": {
                "ipv4addr": "192.168.200.152",
                "ptrdname": "smtp3.lab.domain.local",
                "comment": "This is an example PTR",
            }
        },
        {
            "record:ptr": {
                "ipv4addr": "192.168.200.153",
                "ptrdname": "smtp4.lab.domain.local",
                "comment": "This is an example PTR",
            }
        },
    ]

    if primary:
        for entry in record_types:
            if "zone_auth" in entry:
                entry["zone_auth"]["grid_primary"] = [{"name": primary}]
    if secondary:
        for entry in record_types:
            if "zone_auth" in entry:
                entry["zone_auth"]["grid_secondaries"] = [{"name": secondary}]
    if nsgroup:
        for entry in record_types:
            if "zone_auth" in entry:
                entry["zone_auth"]["ns_group"] = nsgroup

    for record in record_types:
        for data in record:
            try:
                # Create DNS zone object
                response = wapi.post(data, json=record[data])
                # Post requests return 201 status if successful: https://ipam.illinois.edu/wapidoc/index.html?highlight=response%20code#post
                if response.status_code != 201:
                    print(f"{data} creation error: {response.text}")
                else:
                    print(f"{data} creation successful: {response.json()}")
            except WapiRequestException as err:
                log.error(err)
                sys.exit(1)

    sys.exit()


if __name__ == "__main__":
    main()
