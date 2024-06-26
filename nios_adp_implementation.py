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
Infoblox ADP Inital Configuration Tool
Enables inital ADP rules based on the Infoblox Professional Services runbook

For more information, please engage your Infoblox Professional Services Engineer
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.group("Optional Parameters")
@optgroup.option("-n", "--name", default="Internal-Test", help="ADP Profile Name")
@optgroup.option(
    "-m",
    "--members",
    help="Infoblox Grid Members to ADP profile (multiple members should be added in a quoted comma seperated list",
)
@optgroup.option(
    "-r", "--recursive", is_flag=True, help="Infoblox members are recursive"
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
    name: str,
    members: str,
    recursive: bool,
    debug: bool,
) -> None:
    grid_members_dns = []
    recursive_sids = []
    authoritative_sids = []
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
        # Find grid members running DNS
    if members:
        grid_members_dns.append(members)
    else:
        log.info("Searching for members with the DNS service")
        try:
            grid_members = wapi.get(
                "member",
                params={
                    "_return_fields": [
                        "host_name",
                        "active_position",
                        "master_candidate",
                        "service_status",
                    ]
                },
            )
        except WapiRequest as err:
            log.error(err)
            sys.exit(1)
        if grid_members.status_code != 200:
            log.error("no members found: %s", grid_members.text)
        else:
            log.info("grid members found")
            found_members = grid_members.json()
            for gm in found_members:
                for service in gm["service_status"]:
                    if (
                        service["service"] == "DNS"
                        and service["status"] == "WORKING"
                    ):
                        log.info(
                            "Host: %s DNS Service: %s", gm["host_name"], service
                        )
                        grid_members_dns.apped(gm["host_name"])
                    else:
                        log.error(
                            "Host: %s DNS Service: %s", gm["host_name"], service
                        )
    # Determine existing ruleset
    try:
        ruleset = wapi.get(
            "grid:threatprotection", params={"_return_fields": "current_ruleset"}
        )
    except WapiRequest as err:
        log.error(err)
        sys.exit(1)
    if ruleset.status_code != 200:
        log.error("no adp rules found: %s", ruleset.text)
    else:
        # Create ADP profile
        rs = ruleset.json()
        try:
            new_adp_profile = wapi.post(
                "threatprotection:profile",
                params={
                    "name": name,
                    "members": grid_members_dns,
                    "use_current_ruleset": True,
                    "current_ruleset": rs[0]["current_ruleset"],
                },
            )
        except WapiRequest as err:
            log.error(err)
            sys.exit(1)
        if new_adp_profile != 201:
            log.error("adp profile creation failed: %s", new_adp_profile.text)
        else:
            log.info("adp profile %s created: %s", name, new_adp_profile.json())
        # Find SIDs for specific categories
        # Tunneling Category (Recursive DNS)
        # Malware Category (Recursive DNS)
        # Disable RR Types not defined (Authoritative Only DNS)
    try:
        grid_rules = wapi.get(
            "threatprotection:grid:rule",
            params={"_return_fields": ["name", "sid", "category"]},
        )
    except WapiRequest as err:
        log.error(err)
        sys.exit(1)
    if grid_rules.status_code != 200:
        log.error("grid rules not found: %s", grid_rules.text)
    else:
        # Retreieve current rules assigned to profile
        grid_rules_default = grid_rules.json()
        for rules in grid_rules_default:
            category = rules["category"].split("/")
            cat_name = category[2].replace("%2F", "/")
            plain_cat_name = cat_name.replace("%2F", "/")
            if recursive:
                recursive_server_search = re.compile(
                    r"Malware|Tunnel", re.IGNORECASE
                )
                recursive_server_search = re.compile(
                    r"Malware|Tunnel", re.IGNORECASE
                )
                recursive_server_category = recursive_server_search.findall(
                    plain_cat_name
                )
                if recursive_server_category:
                    recursive_sids.append(rules["sid"])
            #                   # TODO determine how to disable specific record types (maybe from predefined list)
            #                if authoritative:
            #                    authoritative_server_search = re.compile(r"DNS Message Types", re.IGNORECASE)
            #                    authoritative_server_category = authoritative_server_search.findall(
            #                        plain_cat_name
            #                    )
            #                if authoritative_server_category:
            #                    authoritative_sids.append(rules["sid"])
            try:
                profile_rules = wapi.get(
                    "threatprotection:profile:rule",
                    params={
                        "_return_fields": [
                            "profile",
                            "rule",
                            "disable",
                            "config",
                            "sid",
                            "use_config",
                            "use_disable",
                        ]
                    },
                )
            except WapiRequest as err:
                log.error(err)
                sys.exit(1)
                # Update profile rules
            if profile_rules.status_code != 200:
                log.error("no adp rules found: %s", profile_rules.text)
            else:
                rules = profile_rules.json()
                # ADP flood rules (130000200, 130000400)
                # Early pass UDP response (100000100)
                # DDoS rules (200000001, 200000002, 200000003)
                sid_rules = [
                    "130000200",
                    "130000400",
                    "100000100",
                    "200000001",
                    "200000002",
                    "200000003",
                ]
                for pr in rules:
                    if pr["sid"] in sid_rules:
                        log.info("Rules: %s SID: %s", pr["rule"], pr["sid"])
                        enable_rule(pr["rule"], pr["_ref"])
                    if recursive:
                        if pr["sid"] in recursive_sids:
                            log.info(
                                "Rules: %s, SID: %s", pr["rule"], pr["sid"]
                            )
                            enable_rule(pr["rule"], pr["_ref"])
                    if authoratative:
                        # TODO add logic
                        log.error("currently under construction")

    sys.exit()


# function to enable rules
# set use_disable True to avoid inheritence
def enable_rule(rule, ref):
    try:
        enabled_rule = wapi.update(ref, params={"disable": False, "use_disable": True})
    except WapiRequest as err:
        log.error(err)
        sys.exit(1)
    if enabled_rule.status_code != 200:
        log.error("%s rule enablement failed: %s", rule, enabled.rule.text)
    else:
        log.info("%s rule enabled", rule)


if __name__ == "__main__":
    main()
