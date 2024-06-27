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
Pre-provision a member to an Infoblox Grid

Platforms avaiable: CISCO, IBVM, INFOBLOX, RIVERBED, VNIOS

License Types: cloud_api,dhcp,dns,dtc,enterprise,fireeye,ms_management,nios,rpz,sw_tp,tp_sub,vnios

Hardware Model: CP-V1400,CP-V2200,CP-V800,IB-VM-100,IB-VM-1410,IB-VM-1420,IB-VM-2210,IB-VM-2220,IB-VM-4010,IB-VM-810,IB-VM-820,IB-VM-RSP,Rev1,Rev2

Note that you cannot specify hwmodel for following hardware types: IB-FLEX, IB-V2215, IB-V1425, IB-V4025, IB-V4015, IB-V1415, IB-V815, IB-V825, IB-V2225, CP-V805, CP-V1405, CP-V2205, ‘IB-2215, IB-2225.

Hardware Type: CP-V1405,CP-V2205,CP-V805,IB-100,IB-1410,IB-1415,IB-1420,IB-1425,IB-2210,IB-2215,IB-2220,IB-2225,IB-4010,IB-4015,IB-4020,IB-4025,IB-4030,IB-4030-10GE,IB-810,IB-815,IB-820,IB-825,IB-FLEX,IB-RSP2,IB-V1415,IB-V1425,IB-V2215,IB-V2225,IB-V4015,IB-V4025,IB-V815,IB-V825,IB-VNIOS,PT-1400,PT-1405,PT-2200,PT-2205,PT-4000,PT-4000-10GE
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.group("Optional Parameters")
@optgroup.option("-p", "--platform", type=click.Choice(['CISCO', 'IBVM', 'INFOBLOX', 'RIVERBED', 'VNIOS'], case_sensitive=True), help="Infoblox platform")
@optgroup.option("-l", "--license", type=click.Choice(['cloudapi', 'dhcp', 'dns', 'dtc', 'enterprise', 'fireeye', 'ms_management', 'nios', 'rpz', 'sw_tp', 'tp_sub', 'vnios'], case_sensitive=True), help="License types the pre-provisioned member should have in order to join the Grid")
@optgroup.option("-m", "--model", type=click.Choice(["CP-V1400","CP-V2200","CP-V800","IB-VM-100","IB-VM-1410","IB-VM-1420","IB-VM-2210","IB-VM-2220","IB-VM-4010","IB-VM-810","IB-VM-820","IB-VM-RSP","Rev1","Rev2"]), help="Hardware model")
@optgroup.option("-t", "--type", type=click.Choice(["CP-V1405","CP-V2205","CP-V805","IB-100","IB-1410","IB-1415","IB-1420","IB-1425","IB-2210","IB-2215","IB-2220","IB-2225","IB-4010","IB-4015","IB-4020","IB-4025","IB-4030","IB-4030-10GE","IB-810","IB-815","IB-820","IB-825","IB-FLEX","IB-RSP2","IB-V1415","IB-V1425","IB-V2215","IB-V2225","IB-V4015","IB-V4025","IB-V815","IB-V825","IB-VNIOS","PT-1400","PT-1405","PT-2200","PT-2205","PT-4000","PT-4000-10GE"]), help="Hardware type")
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
def main(grid_mgr: str, username: str, wapi_ver: str, debug: bool) -> None:
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
        sys.exit(1)

    sys.exit()


if __name__ == "__main__":
    main()
