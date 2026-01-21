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

origin_grid = Gift()
new_grid = Gift()

help_text = """
Infoblox script to compare networks between Infoblox grids
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--new-grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-o", "--origin-grid-mgr", required=True, help="Infoblox Grid Manager")
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
def main(
    origin_grid_mgr: str, new_grid_mgr: str, username: str, wapi_ver: str, debug: bool
) -> None:
    if debug:
        increase_log_level()
    origin_grid.grid_mgr = origin_grid_mgr
    origin_grid.wapi_ver = wapi_ver
    origin_grid.timeout = 600

    new_grid.grid_mgr = new_grid_mgr
    new_grid.wapi_ver = wapi_ver
    new_grid.timeout = 600
    password = getpass.getpass(f"Enter password for [{username}]: ")
    try:
        origin_grid.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        if debug:
            log.info(f"Connected to Infoblox grid manager {origin_grid.grid_mgr}")
        print(f"Connected to Infoblox grid manager {origin_grid.grid_mgr}")

    try:
        new_grid.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        if debug:
            log.info(f"Connected to Infoblox grid manager {new_grid.grid_mgr}")
        print(f"Connected to Infoblox grid manager {new_grid.grid_mgr}")

    nios_dns_objects = [
        "zone_auth",
        "view",
        "record:host",
        "record:a",
        "record:aaaa",
        "record:ptr",
        "record:cname",
        "record:mx",
        "record:srv",
        "record:txt",
        "vlan",
    ]
    nios_network_objects = ["network", "networkcontainer"]
    for n in nios_network_objects:
        origin_grid_networks = get_networks(origin_grid, n, debug)
        destination_grid_networks = get_networks(new_grid, n, debug)
        if origin_grid_networks and destination_grid_networks:
            print(f"{n} Differences Report")
            print("Origin Grid: ", len(origin_grid_networks))
            print("Destination Grid: ", len(destination_grid_networks))
            origin_networks = {n["network"] for n in origin_grid_networks}
            destination_networks = {n["network"] for n in destination_grid_networks}
            only_in_origin = origin_networks - destination_networks
            origin_in_destination = destination_networks - origin_networks
            # in_both = origin_networks & destination_networks
            print("Only in Origin: ", only_in_origin)
            print("Only in Destination: ", origin_in_destination)
            # print("In Both: ", in_both)
    for d in nios_dns_objects:
        origin_grid_dns = get_dns(origin_grid, d, debug)
        destination_grid_dns = get_dns(new_grid, d, debug)
        if origin_grid_dns and destination_grid_dns:
            print(f"{d} Differences Report")
            print("Origin Grid: ", len(origin_grid_dns))
            print("Destination Grid: ", len(destination_grid_dns))
            if d == "zone_auth":
                origin_dns = {d["fqdn"] for d in origin_grid_dns}
                destination_dns = {d["fqdn"] for d in destination_grid_dns}
            elif d == "record:ptr":
                origin_dns = {d["ptrdname"] for d in origin_grid_dns}
                destination_dns = {d["ptrdname"] for d in destination_grid_dns}
            else:
                origin_dns = {d["name"] for d in origin_grid_dns}
                destination_dns = {d["name"] for d in destination_grid_dns}
            only_in_origin = origin_dns - destination_dns
            only_in_destination = destination_dns - origin_dns
            # in_both = origin_dns & destination_dns
            print("Only in Origin: ", only_in_origin)
            print("Only in Destination: ", only_in_destination)
            # print("In Both", in_both)
    sys.exit()


def get_networks(wapi, net_obj, debug):
    try:
        # Retrieve networks from Infoblox appliance
        nios_networks = wapi.get(
            net_obj,
            params={
                "_max_results": 110000,
                "_return_fields": ["network", "network_view", "comment"],
            },
        )
        if nios_networks.status_code != 200:
            if debug:
                print(
                    f"{nios_networks.status_code}: {nios_networks.json().get('code')}: {nios_networks.json().get('text')}"
                )
            log.error(
                f"{nios_networks.status_code}: {nios_networks.json().get('code')}: {nios_networks.json().get('text')}"
            )
        else:
            if debug:
                log.info(nios_networks.json())
            return nios_networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def get_dns(wapi, dns_obj, debug):
    if dns_obj == "zone_auth":
        obj_return_field = ["fqdn", "comment"]
    elif dns_obj == "record:ptr":
        obj_return_field = ["ptrdname", "comment"]
    else:
        obj_return_field = ["name", "comment"]
    try:
        # Retrieve dns objects from Infoblox appliance
        nios_dns = wapi.get(
            dns_obj,
            params={"_max_results": 110000, "_return_fields": obj_return_field},
        )
        if nios_dns.status_code != 200:
            if debug:
                print(
                    f"{nios_dns.status_code}: {nios_dns.json().get('code')}: {nios_dns.json().get('text')}"
                )
            log.error(
                f"{nios_dns.status_code}: {nios_dns.json().get('code')}: {nios_dns.json().get('text')}"
            )
        else:
            if debug:
                log.info(nios_dns.json())
            return nios_dns.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


if __name__ == "__main__":
    main()
