#!/usr/bin/env python3
"""
TODO: Enable CPU snmp queries
"""


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
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        log.info("connected to Infoblox grid manager %s", wapi.grid_mgr)

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

    record_references = []

    print("Checking Grid Members")
    members(wapi)
    print("Retreiving IPAM Statistics")
    ipam_stats(wapi)
    print("Retreiving Capacity Report")
    capacityreport(wapi, debug)

    print("Testing API Functionality")
    with Progress() as progress:
        create_results = progress.add_task(
            "[green]Record Creation API:", total=len(standard_record_types)
        )
        failure_results = progress.add_task(
            "[red]API Failures:", total=len(standard_record_types) * 2
        )
        for record in standard_record_types:
            for data in record:
                result, ref = add_record(wapi, data, record[data])
                if result == "success":
                    record_references.append(ref)
                    progress.update(create_results, advance=1)
                else:
                    progress.update(failure_results, advance=1)
            record_references = record_references[:-4]
            delete_results = progress.add_task(
                "[blue]Record Delete API:", total=len(record_references)
            )
            for ref in record_references:
                result2 = delete_record(wapi, ref)
                if result2 == "success":
                    progress.update(delete_results, advance=1)
                else:
                    progress.update(failure_results, advance=1)

    sys.exit()


# Add records to test add, delete ability
def add_record(wapi, record_type, data):
    try:
        response = wapi.post(record_type, json=data)
        # Post requests return 201 status if successful: https://ipam.illinois.edu/wapidoc/index.html?highlight=response%20code#post
        if response.status_code != 201:
            return "fail"
        else:
            record_ref = response.json()
            return ("success", record_ref)
    except WapiRequestException as err:
        log.error(err)


def delete_record(wapi, ref):
    try:
        response = wapi.delete(ref)
        if response.status_code != 200:
            return "fail"
        else:
            return "success"
    except WapiRequestException as err:
        log.error(err)


def members(wapi):
    table = Table(title="Infoblox Grid Member: Service Status")
    table.add_column("Grid Hostname", justify="center", no_wrap=True)
    table.add_column("Grid Service", justify="center", no_wrap=True)
    table.add_column("Service Status", justify="center", no_wrap=True)
    table.add_column("Description", justify="center", no_wrap=True)
    response = wapi.get(
        "member",
        params={
            "_return_fields": [
                "host_name",
                "service_status",
                "vip_setting",
                "node_info",
            ]
        },
    )
    if response.status_code != 200:
        print(response.status_code, response.text)
    else:
        members = response.json()
        for grd_mem in members:
            for service in grd_mem["service_status"]:
                if service["status"] == "INACTIVE" and "description" in service:
                    table.add_row(
                        grd_mem["host_name"],
                        service["service"],
                        service["status"],
                        service["description"],
                        style="grey54",
                    )
                elif service["status"] == "WORKING" and "description" in service:
                    table.add_row(
                        grd_mem["host_name"],
                        service["service"],
                        service["status"],
                        service["description"],
                        style="green1",
                    )
                elif service["status"] == "WARNING" and "description" in service:
                    table.add_row(
                        grd_mem["host_name"],
                        service["service"],
                        service["status"],
                        service["description"],
                        style="yellow",
                    )
                else:
                    table.add_row(
                        grd_mem["host_name"],
                        service["service"],
                        service["status"],
                        "None",
                        style="dark_red",
                    )

    console = Console()
    console.print(table)


def ipam_stats(wapi):
    statistics = wapi.get(
        "ipam:statistics",
        params={"_return_fields": ["network", "cidr", "network_view", "utilization"]},
    )
    if statistics.status_code != 200:
        print(statistics.statis_code, statistics.text)
    else:
        table = Table(title="IPAM Statistics")
        table.add_column("Network", justify="center", style="green3")
        table.add_column("CIDR", justify="center", style="bright_white")
        table.add_column("Network View", justify="center", style="green3")
        table.add_column("Utilization", justify="center", style="bright_white")
        stats = statistics.json()
        for s in stats:
            table.add_row(
                s["network"],
                str(s["cidr"]),
                s["network_view"],
                str(float(s["utilization"] / 10)),
            )
        console = Console()
        console.print(table)


def capacityreport(wapi, debug):
    members = wapi.get("member", params={"_return_fields": ["host_name"]})
    if members.status_code != 200:
        print(members.status_code, members.text)
    else:
        print("Grid Members Found")
        grd_members = members.json()
        for grdmems in grd_members:
            # print(grdmems["host_name"])
            cap_report = wapi.get(
                "capacityreport",
                params={
                    "name": grdmems["host_name"],
                    "_return_fields": [
                        "name",
                        "hardware_type",
                        "max_capacity",
                        "object_counts",
                        "percent_used",
                        "role",
                        "total_objects",
                    ],
                },
            )
            if cap_report.status_code != 200:
                print(cap_report.status_code, cap_report.text)
            else:
                if debug:
                    print(cap_report.json())
                report = cap_report.json()
                for r in report:
                    table = Table(
                        title=f"{r["name"]} {r["role"]} Capacity Report: {r["hardware_type"]}",
                        highlight=True,
                        caption="Total Capacity: " + str(r["max_capacity"]),
                    )
                    table.add_column("Type", justify="center")
                    table.add_column("Count", justify="center")
                    for x in r["object_counts"]:
                        table.add_row(x["type_name"], str(x["count"]))
                    table.add_row("Percent Used", str(r["percent_used"]))
                    table.add_row("Total Objects", str(r["total_objects"]))
                    console = Console()
                    console.print(table)
                    print()


if __name__ == "__main__":
    main()
