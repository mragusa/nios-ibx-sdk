#!/usr/bin/env python3
# TODO

import getpass
import sys
import click
from click_option_group import optgroup
from ibx_sdk.logger.ibx_logger import init_logger, increase_log_level
from ibx_sdk.nios.exceptions import WapiRequestException
from ibx_sdk.nios.gift import Gift
from rich.console import Console
from rich.table import Column, Table
from rich import box

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
Display Network Discovery configuration for an Infoblox grid
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option(
    "-t",
    "--type",
    type=click.Choice(["report", "scan_status", "global", "member"]),
    required=True,
    default="report",
    show_default=True,
    help="Reporting Type",
)
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
def main(grid_mgr: str, username: str, wapi_ver: str, debug: bool, type: str) -> None:
    discovery_results = {
        "report": [
            "network",
            "comment",
            "enable_discovery",
            "use_enable_discovery",
            "discovery_member",
            "discovery_engine_type",
        ],
        "scan_status": ["network", "comment", "discover_now_status"],
        "global": [
            "advanced_polling_settings",
            "advanced_sdn_polling_settings",
            "advisor_settings",
            "auto_conversion_settings",
            "basic_polling_settings",
            "basic_sdn_polling_settings",
            "cli_credentials",
            "discovery_blackout_setting",
            "dns_lookup_option",
            "dns_lookup_throttle",
            "enable_advisor",
            "enable_auto_conversion",
            "enable_auto_updates",
            "grid_name",
            "ignore_conflict_duration",
            "port_control_blackout_setting",
            "ports",
            "same_port_control_discovery_blackout",
            "snmpv1v2_credentials",
            "snmpv3_credentials",
            "unmanaged_ips_limit",
            "unmanaged_ips_timeout",
            "vrf_mapping_policy",
            "vrf_mapping_rules",
        ],
        "member": [
            "address",
            "cli_credentials",
            "default_seed_routers",
            "discovery_member",
            "enable_service",
            "gateway_seed_routers",
            "is_sa",
            "role",
            "scan_interfaces",
            "sdn_configs",
            "seed_routers",
            "snmpv1v2_credentials",
            "snmpv3_credentials",
            "use_cli_credentials",
            "use_snmpv1v2_credentials",
            "use_snmpv3_credentials",
        ],
    }
    if debug:
        increase_log_level()
    wapi.grid_mgr = grid_mgr
    wapi.wapi_ver = wapi_ver
    wapi.timeout = 600
    password = getpass.getpass(f"Enter password for [{username}]: ")
    try:
        wapi.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        if debug:
            log.info("Connected to Infoblox grid manager %s", wapi.grid_mgr)
        print(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
    if type == "report" or type == "scan_status":
        network_container = get_network_container(discovery_results[type], debug)
        report_network(grid_mgr, network_container, type, "Network Containers")
        networks = get_network(discovery_results[type], debug)
        report_network(grid_mgr, networks, type, "Networks")
    elif type == "global":
        nd_global_config = get_nd_global(discovery_results[type], debug)
        report_config(grid_mgr, nd_global_config, type, "Global")
    elif type == "member":
        nd_member_config = get_nd_member(discovery_results[type], debug)
        report_config(grid_mgr, nd_member_config, type, "Member")
    else:
        print("Option unknown")
    sys.exit()


def get_nd_member(type: list, debug):
    try:
        nd_member = wapi.get(
            "discovery:memberproperties", params={"_return_fields": type}
        )
        if nd_member.status_code != 200:
            if debug:
                print(nd_member.status_code, nd_member.text)
            log.error(nd_member.status_code, nd_member.text)
        else:
            if debug:
                log.info(nd_member.json())
            return nd_member.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def get_nd_global(type: list, debug):
    try:
        nd_global = wapi.get(
            "discovery:gridproperties", params={"_return_fields": type}
        )
        if nd_global.status_code != 200:
            if debug:
                print(nd_global.status_code, nd_global.text)
            log.error(nd_global.status_code, nd_global.text)
        else:
            if debug:
                log.info(nd_global.json())
            return nd_global.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def get_network_container(type: list, debug):
    try:
        ibx_networks = wapi.get(
            "networkcontainer",
            params={
                "_max_results": 100000,
                "_return_fields": type,
            },
        )
        if ibx_networks.status_code != 200:
            if debug:
                print(ibx_networks.status_code, ibx_networks.text)
            log.error(ibx_networks.status_code, ibx_networks.text)
        else:
            if debug:
                log.info(ibx_networks.json())
            return ibx_networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def get_network(type: list, debug):
    try:
        ibx_networks = wapi.get(
            "network",
            params={
                "_max_results": 100000,
                "_return_fields": type,
            },
        )
        if ibx_networks.status_code != 200:
            if debug:
                print(ibx_networks.status_code, ibx_networks.text)
            log.error(ibx_networks.status_code, ibx_networks.text)
        else:
            if debug:
                log.info(ibx_networks.json())
            return ibx_networks.json()
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def report_config(grid_mgr: str, config, type: str, object_type: str):
    table = Table(
        title=f"Infoblox Grid: {grid_mgr} {type} {object_type} Configuration",
        box=box.SIMPLE,
    )
    if type == "global":
        table.add_column("Grid")
        table.add_column("Basic Polling Settings")
        table.add_column("Advanced Polling Settings")
        table.add_column("Advanced SDN Polling Settings")
        table.add_column("CLI Credentials")
        table.add_column("SNMP v1/v2 Credentials")
        table.add_column("SNMP v3 Credentials")
        table.add_column("Ports")
    if type == "member":
        table.add_column("Discovery Member")
        table.add_column("Address")
        table.add_column("Default Seed Routers")
        table.add_column("Seed Routers")
        table.add_column("Scan Interfaces")
        table.add_column("SNMP v1/v2 Credentials")
        table.add_column("SNMP v3 Credentials")
        table.add_column("Use SNMP v1/v2")
        table.add_column("Use SNMP v3")
    for c in config:
        if type == "global":
            table.add_row(
                c["grid_name"],
                str(c["basic_polling_settings"]),
                str(c["advanced_polling_settings"]),
                str(c["advanced_sdn_polling_settings"]),
                str(c["cli_credentials"]),
                str(c["snmpv1v2_credentials"]),
                str(c["snmpv3_credentials"]),
                str(c["ports"]),
            )
        if type == "member":
            table.add_row(
                c["discovery_member"],
                c["address"],
                str(c["default_seed_routers"]),
                str(c["seed_routers"]),
                str(c["scan_interfaces"]),
                str(c["snmpv1v2_credentials"]),
                str(c["snmpv3_credentials"]),
                str(c["use_snmpv1v2_credentials"]),
                str(c["use_snmpv3_credentials"]),
            )
    console = Console()
    console.print(table)


def report_network(grid_mgr: str, network, type: str, object_type: str):
    network_with_discovery = 0
    network_without_discovery = 0
    enDiscovery = ""
    enFlagDiscovery = ""
    disMember = ""
    discoverStatus = ""
    table = Table(
        Column(header="Reference", justify="center"),
        Column(header="Network", justify="center"),
        title=f"Infoblox Grid: {grid_mgr} Network Discovery {type} : {object_type}",
        box=box.SIMPLE,
    )
    if type == "report":
        table.add_column("Discovery Enabled", justify="center")
        table.add_column("Discovery Use Flag", justify="center")
        table.add_column("Discovery Member", justify="center")
        table.add_column("Discovery Engine", justify="center")
    if type == "scan_status":
        table.add_column("Discovery Status", justify="center")
    for n in network:
        if "enable_discovery" in n:
            match (n["enable_discovery"], n["use_enable_discovery"]):
                case (True, True):
                    enDiscovery = "[green]True"
                    enFlagDiscovery = "[green]True"
                    network_with_discovery += 1
                case (True, False):
                    enDiscovery = "[green]True"
                    enFlagDiscovery = "[red]False"
                    network_with_discovery += 1
                case (False, True):
                    enDiscovery = "[red]False"
                    enFlagDiscovery = "[green]True"
                    network_without_discovery += 1
                case (False, False):
                    enDiscovery = "[red]False"
                    enFlagDiscovery = "[red]False"
                    network_without_discovery += 1
            if "discovery_member" in n:
                disMember = n["discovery_member"]
            else:
                disMember = "[red]None"
        if "discover_now_status" in n:
            if n["discover_now_status"] == "COMPLETE":
                discoverStatus = f"[green] {n["discover_now_status"]}"
            elif n["discover_now_status"] == "FAILED":
                discoverStatus = f"[red] {n["discover_now_status"]}"
            elif n["discover_now_status"] == "PENDING":
                discoverStatus = f"[yellow] {n["discover_now_status"]}"
            elif n["discover_now_status"] == "RUNNING":
                discoverStatus = f"[light blue] {n["discover_now_status"]}"
            else:
                discoverStatus = n["discover_now_status"]
        if type == "report":
            table.add_row(
                n["_ref"],
                n["network"],
                enDiscovery,
                enFlagDiscovery,
                disMember,
                n["discovery_engine_type"],
            )
        if type == "scan_status":
            table.add_row(n["_ref"], n["network"], discoverStatus)
    console = Console()
    console.print(table)
    table = Table(
        "Networks with Discovery",
        "Networks Without Discovery",
        title="Networks with Discovery Summary",
    )
    table.add_row(str(network_with_discovery), str(network_without_discovery))
    console.print(table)
    sys.exit()


if __name__ == "__main__":
    main()
