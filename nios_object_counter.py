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
print(
    r"""
▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐                                                                                       ▌
▐     <-. (`-')_  _                 (`-').->                                            ▌
▐        \( OO) )(_)         .->    ( OO)_                                              ▌
▐     ,--./ ,--/ ,-(`-')(`-')----. (_)--\_)                                             ▌
▐     |   \ |  | | ( OO)( OO).-.  '/    _ /                                             ▌
▐     |  . '|  |)|  |  )( _) | |  |\_..`--.                                             ▌
▐     |  |\    |(|  |_/  \|  |)|  |.-._)   \                                            ▌
▐     |  | \   | |  |'->  '  '-'  '\       /                                            ▌
▐     `--'  `--' `--'      `-----'  `-----'                                             ▌
▐      (`-')  _ (`-')      _  (`-')              (`-') (`-')      (`-')  _   (`-')      ▌
▐      ( OO).-/ (OO )_.->  \-.(OO )     .->   <-.(OO ) ( OO).->   ( OO).-/<-.(OO )      ▌
▐     (,------. (_| \_)--. _.'    \(`-')----. ,------,)/    '._  (,------.,------,)     ▌
▐      |  .---' \  `.'  / (_...--''( OO).-.  '|   /`. '|'--...__) |  .---'|   /`. '     ▌
▐     (|  '--.   \    .') |  |_.' |( _) | |  ||  |_.' |`--.  .--'(|  '--. |  |_.' |     ▌
▐      |  .--'   .'    \  |  .___.' \|  |)|  ||  .   .'   |  |    |  .--' |  .   .'     ▌
▐      |  `---. /  .'.  \ |  |       '  '-'  '|  |\  \    |  |    |  `---.|  |\  \      ▌
▐      `------'`--'   '--'`--'        `-----' `--' '--'   `--'    `------'`--' '--'     ▌
▐                                                                                       ▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌
"""
)
help_text = "Infoblox NIOS Exporter"

infoblox_obj_types = [
    "ad_auth_service",
    "admingroup",
    "adminrole",
    "adminuser",
    "allendpoints",
    "allnsgroup",
    # "allrecords",
    # "allrpzrecords",
    "approvalworkflow",
    "authpolicy",
    "awsrte53taskgroup",
    "awsuser",
    # "azurednstaskgroup",
    # "azureuser",
    "bfdtemplate",
    "bulkhost",
    "bulkhostnametemplate",
    "cacertificate",
    # "capacityreport",
    "captiveportal",
    "certificate:authservice",
    "csvimporttask",
    "datacollectioncluster",
    # "db_objects",
    "dbsnapshot",
    "ddns:principalcluster",
    "ddns:principalcluster:group",
    # "deleted_objects",
    # "dhcp:statistics",
    "dhcpfailover",
    "dhcpoptiondefinition",
    "dhcpoptionspace",
    # "discovery",
    "discovery:credentialgroup",
    # "discovery:device",
    "discovery:devicecomponent",
    "discovery:deviceinterface",
    "discovery:deviceneighbor",
    "discovery:devicesupportbundle",
    "discovery:diagnostictask",
    "discovery:gridproperties",
    "discovery:memberproperties",
    "discovery:sdnnetwork",
    "discovery:status",
    "discovery:vrf",
    "discoverytask",
    "distributionschedule",
    "dns64group",
    "dtc",
    "dtc:allrecords",
    "dtc:certificate",
    "dtc:lbdn",
    "dtc:monitor",
    "dtc:monitor:http",
    "dtc:monitor:icmp",
    "dtc:monitor:pdp",
    "dtc:monitor:sip",
    "dtc:monitor:snmp",
    "dtc:monitor:tcp",
    "dtc:object",
    "dtc:pool",
    "dtc:record:a",
    "dtc:record:aaaa",
    "dtc:record:cname",
    "dtc:record:naptr",
    "dtc:record:srv",
    "dtc:server",
    "dtc:topology",
    "dtc:topology:label",
    "dtc:topology:rule",
    "dxl:endpoint",
    "extensibleattributedef",
    "federatedrealms",
    "fedipamop",
    "fileop",
    "filterfingerprint",
    "filtermac",
    "filternac",
    "filteroption",
    "filterrelayagent",
    "fingerprint",
    "fixedaddress",
    "fixedaddresstemplate",
    "ftpuser",
    "gcpdnstaskgroup",
    "gcpuser",
    "gmcgroup",
    "gmcschedule",
    "grid",
    "grid:cloudapi",
    "grid:cloudapi:cloudstatistics",
    "grid:cloudapi:tenant",
    "grid:cloudapi:vm",
    "grid:cloudapi:vmaddress",
    "grid:dashboard",
    "grid:dhcpproperties",
    "grid:dns",
    "grid:filedistribution",
    "grid:license_pool",
    "grid:license_pool_container",
    "grid:maxminddbinfo",
    "grid:member:cloudapi",
    "grid:servicerestart:group",
    "grid:servicerestart:group:order",
    "grid:servicerestart:request",
    "grid:servicerestart:request:changedobject",
    "grid:servicerestart:status",
    "grid:threatinsight",
    "grid:threatprotection",
    "grid:x509certificate",
    "hostnamerewritepolicy",
    "hsm:allgroups",
    "hsm:entrustnshieldgroup",
    "hsm:safenetgroup",
    "hsm:thalesgroup",
    "hsm:thaleslunagroup",
    "ipam:statistics",
    "ipv4address",
    "ipv6address",
    "ipv6dhcpoptiondefinition",
    "ipv6dhcpoptionspace",
    "ipv6filteroption",
    "ipv6fixedaddress",
    "ipv6fixedaddresstemplate",
    "ipv6network",
    "ipv6networkcontainer",
    "ipv6networktemplate",
    "ipv6range",
    "ipv6rangetemplate",
    "ipv6sharednetwork",
    "kerberoskey",
    "ldap_auth_service",
    "lease",
    "license:gridwide",
    "localuser:authservice",
    "macfilteraddress",
    "mastergrid",
    "member",
    "member:dhcpproperties",
    "member:dns",
    "member:filedistribution",
    "member:license",
    "member:parentalcontrol",
    "member:threatinsight",
    "member:threatprotection",
    "membercloudsync",
    "memberdfp",
    "msserver",
    "msserver:adsites:domain",
    "msserver:adsites:site",
    "msserver:dhcp",
    "msserver:dns",
    "mssuperscope",
    "multiregions",
    "namedacl",
    "natgroup",
    "network",
    "network_discovery",
    "networkcontainer",
    "networktemplate",
    "networkuser",
    "networkview",
    "notification:rest:endpoint",
    "notification:rest:template",
    "notification:rule",
    "nsgroup",
    "nsgroup:delegation",
    "nsgroup:forwardingmember",
    "nsgroup:forwardstubserver",
    "nsgroup:stubmember",
    "orderedranges",
    "orderedresponsepolicyzones",
    "outbound:cloudclient",
    "parentalcontrol:avp",
    "parentalcontrol:blockingpolicy",
    "parentalcontrol:subscriber",
    "parentalcontrol:subscriberrecord",
    "parentalcontrol:subscribersite",
    "permission",
    "pxgrid:endpoint",
    "radius:authservice",
    "range",
    "rangetemplate",
    "record:a",
    "record:aaaa",
    "record:alias",
    "record:caa",
    "record:cname",
    "record:dhcid",
    "record:dname",
    "record:dnskey",
    "record:ds",
    "record:dtclbdn",
    "record:host",
    "record:host_ipv4addr",
    "record:host_ipv6addr",
    "record:mx",
    "record:naptr",
    "record:ns",
    "record:nsec",
    "record:nsec3",
    "record:nsec3param",
    "record:ptr",
    "record:rpz:a",
    "record:rpz:a:ipaddress",
    "record:rpz:aaaa",
    "record:rpz:aaaa:ipaddress",
    "record:rpz:cname",
    "record:rpz:cname:clientipaddress",
    "record:rpz:cname:clientipaddressdn",
    "record:rpz:cname:ipaddress",
    "record:rpz:cname:ipaddressdn",
    "record:rpz:mx",
    "record:rpz:naptr",
    "record:rpz:ptr",
    "record:rpz:srv",
    "record:rpz:txt",
    "record:rrsig",
    "record:srv",
    "record:tlsa",
    "record:txt",
    "record:unknown",
    "recordnamepolicy",
    "request",
    "restartservicestatus",
    "rir",
    "rir:organization",
    "roaminghost",
    "ruleset",
    "saml:authservice",
    "scavengingtask",
    "scheduledtask",
    "search",
    "sharednetwork",
    "sharedrecord:a",
    "sharedrecord:aaaa",
    "sharedrecord:cname",
    "sharedrecord:mx",
    "sharedrecord:srv",
    "sharedrecord:txt",
    "sharedrecordgroup",
    "smartfolder:children",
    "smartfolder:global",
    "smartfolder:personal",
    "snmpuser",
    "superhost",
    "superhostchild",
    "syslog:endpoint",
    "tacacsplus:authservice",
    "taxii",
    "tftpfiledir",
    "threatinsight:allowlist",
    "threatinsight:cloudclient",
    "threatinsight:insight_allowlist",
    "threatinsight:moduleset",
    "threatprotection:grid:rule",
    "threatprotection:profile",
    "threatprotection:profile:rule",
    "threatprotection:rule",
    "threatprotection:rulecategory",
    "threatprotection:ruleset",
    "threatprotection:ruletemplate",
    "threatprotection:statistics",
    "upgradegroup",
    "upgradeschedule",
    "upgradestatus",
    "userprofile",
    "vdiscoverytask",
    "view",
    "vlan",
    "vlanrange",
    "vlanview",
    "zone_auth",
    "zone_auth_discrepancy",
    "zone_delegated",
    "zone_forward",
    "zone_rp",
    "zone_stub",
]


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
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
@optgroup.option("--debug", is_flag=True, help="enable verbose debug output")
def main(grid_mgr: str, username: str, wapi_ver: str, debug: bool) -> None:
    if debug:
        increase_log_level()
    wapi.grid_mgr = grid_mgr
    wapi.wapi_ver = wapi_ver
    wapi.timeout = 600
    # password = getpass.getpass(f"Enter password for [{username}]: ")
    password = "123@BLOXlab"
    try:
        wapi.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        log.info("Connected to Infoblox grid manager %s", wapi.grid_mgr)
    for x in infoblox_obj_types:
        try:
            # Retrieve network view from Infoblox appliance
            ibx_objects = wapi.get(
                x, params={"_max_results": 100000, "_return_as_object": 1}
            )
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if ibx_objects.status_code != 200:
            print(ibx_objects.status_code, ibx_objects.text)
        else:
            ibx_obj_results = ibx_objects.json()
            print(x, len(ibx_obj_results["result"]))

    sys.exit()


if __name__ == "__main__":
    main()
