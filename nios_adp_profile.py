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
Interface with Infoblox ADP profiles

Detailed Information on Infoblox ADP profiles: https://docs.infoblox.com/space/nios90/280760256/Configuring+Threat+Protection+Profiles
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-r", "--retrieve", is_flag=True, help="Display existing ADP profile")
@optgroup.option(
    "-c",
    "--create",
    default="Internal",
    help="Create ADP profile: default name is Internal",
)
@optgroup.option("-d", "--delete", help="Delete ADP profile")
@optgroup.group("Optional Parameters")
@optgroup.option(
    "-m",
    "--members",
    help="Members to assign to ADP profile: multiple members should be comma seperated enclosed in double quotes",
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
    retrieve: bool,
    create: str,
    delete: str,
    members: str,
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
    if retrieve:
        try:
            # Retrieve ADP profile from Infoblox appliance
            existing_adp_profiles = wapi.get("threatprotection:profile")
            ruleset = wapi.get(
                "grid:threatprotection",
                params={
                    "_return_fields": [
                        "current_ruleset",
                        "grid_name",
                        "last_rule_update_version",
                    ]
                },
            )
            if existing_adp_profiles.status_code != 200:
                print(
                    f"No existing ADP profiles found: {existing_adp_profiles.status_code}"
                )
                log.error("adp profiles not found")
            else:
                print(f"existing adp profile: {existing_adp_profiles.json()}")
                log.info("existing adp profile found: %s", existing_adp_profiles.text)

            if ruleset.status_code != 200:
                print(f"ADP ruleset not found: {ruleset.status_code}")
                log.error("adp ruleset not found")
            else:
                print(f"ruleset found: {ruleset.json()}") 
                log.info("ruleset found: %s", ruleset.json())

        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
    if create:
        try:
            current_ruleset = wapi.get(
                "grid:threatprotection", params={"_return_fields": ["current_ruleset"]}
            )
            if members:
                new_adp_profile = wapi.post(
                    "threatprotection:profile",
                    json={
                        "name": create,
                        "members": members,
                        " use_current_ruleset": True,
                        "current_ruleset": current_ruleset.json(),
                    },
                )
            else:
                new_adp_profile = wapi.post(
                    "threatprotection:profile",
                    json={
                        "name": create,
                        "use_current_ruleset": True,
                        "current_ruleset": current_ruleset.json(),
                    },
                )
            if new_adp_profile.status_code != 201:
                print(f"ADP profile creation failed: {new_adp_profile.text}")
                log.error("adp profile creation failed: %s", new_adp_profile.text)
            else:
                print(f"ADP profile {create} created: {new_adp_profile.json()}")
                log.info("adp profile created: %s", new_adp_profile.json())
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
    if delete:
        try:
            # Delete ADP profile
            adp_profile = wapi.get("threatprotection:profile", json={"name": delete})
            if adp_profile.status == 200:
                del_adp_profile = wapi.delete(adp_profile.text)
                if del_adp_profile.status != 200:
                    print(f"ADP profile removal failed: {del_adp_profile.text}")
                    log.error("adp profile removal failed: %s", del_adp_profile.text)
                else:
                    print(f"ADP profile removed: {del_adp_profile.json()}")
                    log.info("adp profile removed: %s", del_adp_profile.json())
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)

    sys.exit()


if __name__ == "__main__":
    main()
