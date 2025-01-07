#!/usr/bin/env python3


import getpass
import sys
import click
from click_option_group import optgroup

from ibx_sdk.logger.ibx_logger import init_logger, increase_log_level

from ibx_sdk.nios.exceptions import WapiRequestException
from ibx_sdk.nios.gift import Gift

from rich.progress import Progress
from rich.console import Console
from rich.table import Table


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
Perform tests via the WAPI to verify Infoblox functionality post upgrade
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
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
    #try:
        # Retrieve network view from Infoblox appliance
        #network_view = wapi.get("view")
        #print(network_view.json())
    #except WapiRequestException as err:
    #    log.error(err)
    #    sys.exit(2)

    # Common record types
    standard_record_types = [
        {
            "zone_auth": {
                "fqdn": "lab.domain.com",
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
                "name": "lab.domain.com",
                "ipv4addr": "192.168.200.100",
                "comment": "Example A record",
            }
        },
        {
            "record:cname": {
                "name": "www.lab.domain.com",
                "canonical": "lab.domain.com",
                "comment": "This is an example CNAME record",
            }
        },
        {
            "record:mx": {
                "name": "lab.domain.com",
                "preference": 20,
                "mail_exchanger": "smtp1.lab.domain.com",
                "comment": "This is an example MX record",
            }
        },
        {
            "record:ptr": {
                "ipv4addr": "192.168.200.100",
                "ptrdname": "lab.domain.com",
                "comment": "This is an example PTR",
            }
        },
    ]

    security_record_Types = []

    print("Checking Grid Members")
    members(wapi)

    with Progress() as progress:
        test1 = progress.add_task("[green]Successful:", total=len(standard_record_types)*2)
        test2 = progress.add_task("[red]Partial Failure:", total=len(standard_record_types)*2)
        test3 = progress.add_task("[cyan]Failed:", total="100")
        while not progress.finished:
            # check if record types are successfully added and deleted
            result = add_record(wapi, standard_record_types)
            if result == "success":
                progress.update(test1, advance=1)
                result2 = delete_record(wapi, something)
                if result2 == "success":
                    progress.update(test1, advance=1)
                else:
                    progress.update(test2, advance=1)
            else:
                progress.update(test3, advance=1)

    sys.exit()


#    if primary:
#        for entry in record_types:
#            if "zone_auth" in entry:
#                entry["zone_auth"]["grid_primary"] = [{"name": primary}]
#    if secondary:
#        for entry in record_types:
#            if "zone_auth" in entry:
#                entry["zone_auth"]["grid_secondaries"] = [{"name": secondary}]
#    if nsgroup:
#        for entry in record_types:
#            if "zone_auth" in entry:
#                entry["zone_auth"]["ns_group"] = nsgroup

# Add records to test add, delete ability
def add_record(wapi, record_types):
    for record in record_types:
        for data in record:
            try:
                # Create DNS zone object
                response = wapi.post(data, json=record[data])
                # Post requests return 201 status if successful: https://ipam.illinois.edu/wapidoc/index.html?highlight=response%20code#post
                if response.status_code != 201:
                    #print(f"{data} creation error: {response.text}")
                    return("fail")
                else:
                    #print(f"{data} creation successful: {response.json()}")
                    return("success")
            except WapiRequestException as err:
                log.error(err)
                #sys.exit(1)

def delete_record(wapi, ref):
    response = wapi.post(data, ref)
    try:
        if response.status_code != 200:
            return("fail")
        else:
            return("success")
    except WapiRequestException as err:
        log.error(err)


def members(wapi):
    table = Table(title="Infoblox Grid Member: Service Status")
    table.add_column("Grid Hostname", justify="center", style="cyan", no_wrap=True)
    table.add_column("Grid Service", justify="center", style="purple", no_wrap=True)
    table.add_column("Service Status", justify="center", style="blue", no_wrap=True)
    response = wapi.get("member")
    if response.status_code != 200:
        print(response.status_code, response.text) 
    else:
        print(response.json())
        members = response.json()
        for grd_mem in members["results"]:
            #print(grid_mem["host_name"], grid_mem["comment"])
            #print(grid_mem["service_status"])
            for service in grid_mem["service_status"]:
                table.add_row(grid_mem["host_name"], service["service"], service["status"])
    console = Console()
    console.print(table)

if __name__ == "__main__":
    main()
