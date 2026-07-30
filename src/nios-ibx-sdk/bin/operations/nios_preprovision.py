#!/usr/bin/env python3


import getpass
import random
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

Note that you cannot specify hwmodel for following hardware types: IB-FLEX, IB-V2215, IB-V1425, IB-V4025, IB-V4015, IB-V1415, IB-V815, IB-V825, IB-V2225, CP-V805, CP-V1405, CP-V2205, ‘IB-2215, IB-2225.

Hardware Type: CP-V1405,CP-V2205,CP-V805,IB-1415,IB-1425,IB-1516,IB-1526,IB-2215,IB-2225,IB-2326,IB-4015,IB-4025,IB-4126,IB-815,IB-825,IB-926,IB-FLEX,IB-V1415,IB-V1425,IB-V1516,IB-V1526,IB-V2215,IB-V2225,IB-V2326,IB-V4015,IB-V4025,IB-V4126,IB-815,IB-V825,IB-V926
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option(
    "-p",
    "--platform",
    required=True,
    type=click.Choice(
        ["CISCO", "IBVM", "INFOBLOX", "RIVERBED", "VNIOS"], case_sensitive=True
    ),
    help="Infoblox platform",
)
@optgroup.option(
    "-l",
    "--licenses",
    required=True,
    multiple=True,
    type=click.Choice(
        [
            "cloudapi",
            "dhcp",
            "dns",
            "dtc",
            "enterprise",
            "fireeye",
            "ms_management",
            "nios",
            "rpz",
            "sw_tp",
            "tp_sub",
            "vnios",
        ],
        case_sensitive=True,
    ),
    help="License types the pre-provisioned member should have in order to join the Grid",
)
@optgroup.option(
    "-t",
    "--hwtype",
    type=click.Choice(
        [
            "CP-V1405",
            "CP-V2205",
            "CP-V805",
            "IB-1415",
            "IB-1425",
            "IB-1516",
            "IB-1526",
            "IB-2215",
            "IB-2225",
            "IB-2326",
            "IB-4015",
            "IB-4025",
            "IB-4126",
            "IB-815",
            "IB-825",
            "IB-926",
            "IB-FLEX",
            "IB-V1415",
            "IB-V1425",
            "IB-V1516",
            "IB-V1526",
            "IB-V2215",
            "IB-V2225",
            "IB-V2326",
            "IB-V4015",
            "IB-V4025",
            "IB-V4126",
            "IB-V815",
            "IB-V825",
            "IB-V926",
        ]
    ),
    help="Hardware type",
)
@optgroup.option("-n", "--name", help="FQDN of Infoblox member")
@optgroup.option("--vip", required=True, help="VIP address of NIOS member")
@optgroup.option("--subnetmask", required=True, help="Subnet mask of NIOS member")
@optgroup.option("--gateway", required=True, help="Gateway for VIP")
@optgroup.option(
    "-u",
    "--username",
    default="admin",
    show_default=True,
    help="Infoblox admin username",
)
@optgroup.group("High Availability Parameters")
@optgroup.option("--highavailability", is_flag=True, help="Enable HA ports")
@optgroup.option("--lanha", help="HA LAN IP address")
@optgroup.option("--lanhasubnet", help="HA LAN subnet mask")
@optgroup.option("--lanhagateway", help="HA LAN gateway")
@optgroup.group("MGMT Port Parameters")
@optgroup.option("--mgmt", is_flag=True, help="Enable MGMT port")
@optgroup.option("--mgmtvpn", is_flag=True, help="Enable VPN on MGMT port")
@optgroup.option("--mgmtip", help="MGMT port IP")
@optgroup.option("--mgmtsubnet", help="MGMT port subnet")
@optgroup.option("--mgmtgw", help="MGMT port gateway")
@optgroup.group("Optional Parameters")
@optgroup.option(
    "-w", "--wapi-ver", default="2.11", show_default=True, help="Infoblox WAPI version"
)
@optgroup.group("Logging Parameters")
@optgroup.option("--debug", is_flag=True, help="enable verbose debug output")
def main(
    grid_mgr: str,
    username: str,
    wapi_ver: str,
    name: str,
    vip: str,
    subnetmask: str,
    gateway: str,
    platform: str,
    hwtype: str,
    licenses: list,
    highavailability: bool,
    lanha: str,
    lanhasubnet: str,
    lanhagateway: str,
    mgmt: bool,
    mgmtvpn: bool,
    mgmtip: str,
    mgmtsubnet: str,
    mgmtgw: str,
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
    payload = {
        "host_name": name,
        "platform": platform,
        "config_addr_type": "IPV4",
        "vip_setting": {"address": vip, "subnet_mask": subnetmask, "gateway": gateway},
    }
    if mgmt:
        payload.update(
            {
                "node_info": [
                    {
                        "mgmt_network_setting": {
                            "address": mgmtip,
                            "subnet_mask": mgmtsubnet,
                            "gateway": mgmtgw,
                        },
                    }
                ],
                "mgmt_port_setting": {"enabled": True, "vpn_enabled": mgmtvpn},
            }
        )
    if highavailability:
        router_id = random.randint(1, 255)
        payload.update(
            {
                "router_id": router_id,
                "enable_ha": True,
                "node_info": [
                    {
                        "lan_ha_port_setting": {
                            "address": lanha,
                            "subnet_mask": lanhasubnet,
                            "gateway": lanhagateway,
                        },
                    }
                ],
            }
        )
    if mgmt and highavailability:
        router_id = random.randint(1, 255)
        payload.update(
            {
                "mgmt_port_setting": {"enabled": True, "vpn_enabled": mgmtvpn},
                "router_id": router_id,
                "enable_ha": True,
                "node_info": [
                    {
                        "lan_ha_port_setting": {
                            "address": lanha,
                            "subnet_mask": lanhasubnet,
                            "gateway": lanhagateway,
                        },
                        "mgmt_network_setting": {
                            "address": mgmtip,
                            "subnet_mask": mgmtsubnet,
                            "gateway": mgmtgw,
                        },
                    }
                ],
            }
        )

    log.info("Current member payload: %s", payload)
    try:
        # Create member prior to preprovisioning the licenses
        member_creation = wapi.post(
            "member",
            json=payload,
        )
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    if member_creation.status_code != 201:
        log.error("member %s creation failed: %s", name, member_creation.text)
    else:
        log.info("member %s creation was successful: %s", name, member_creation.json())

    # utilize member reference from creation
    new_member = member_creation.json()

    # Assign hardware type to new json object for updating new member
    provision = {}
    if hwtype:
        provision = {
            "pre_provisioning": {
                "hardware_info": [{"hwtype": hwtype}],
                "licenses": licenses,
            }
        }

    # Setup preprovisioning for Infoblox member
    try:
        member_preprovision = wapi.put(new_member, json=provision)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)

    if member_preprovision.status_code != 200:
        log.error("license preprovisioning failed: %s", member_preprovision.text)
    else:
        log.info("license provisioning completed: %s", member_preprovision.json())

    sys.exit()


if __name__ == "__main__":
    main()
