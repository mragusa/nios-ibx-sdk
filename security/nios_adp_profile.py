#!/usr/bin/env python3


import getpass
import sys
import click
from click_option_group import optgroup
from datetime import date

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
current_time = date.today()
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
    is_flag=True,
    help="Create ADP profile: default name is Internal",
)
@optgroup.option("-d", "--delete", is_flag=True, help="Delete ADP profile")
@optgroup.group("Optional Parameters")
@optgroup.option(
    "-n",
    "--profilename",
    default="Internal",
    help="ADP profile name for creation or deletion",
)
@optgroup.option(
    "--comment",
    default=current_time,
    help="comment for adp profile: default is date of creation",
)
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
    create: bool,
    delete: bool,
    profilename: str,
    members: str,
    comment: str,
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
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if existing_adp_profiles.status_code != 200:
            log.error("adp profiles not found: %s", existing_adp_profiles.text)
        else:
            adp_profile = existing_adp_profiles.json()
            for x in adp_profile:
                log.info("existing adp profile found: %s", x["name"])

        if ruleset.status_code != 200:
            log.error("adp ruleset not found: %s", ruleset.text)
        else:
            adp_profile_ruleset = ruleset.json()
            for x in adp_profile_ruleset:
                log.info("current ruleset: %s", x["current_ruleset"])
    if create:
        try:
            current_ruleset = wapi.get(
                "grid:threatprotection", params={"_return_fields": ["current_ruleset"]}
            )
        except WapiRequestException as err:
            log.error(err)
            sys.exit(1)
        if current_ruleset.status_code != 200:
            log.error("no adp ruleset found: %s".current_ruleset.text)
        else:
            active_ruleset = current_ruleset.json()
            log.info("adp ruleset found: %s", active_ruleset[0]["current_ruleset"])
            if profilename:
                if members:
                    log.info("applying %s to adp profile %s", members, profilename)
                    try:
                        new_adp_profile = wapi.post(
                            "threatprotection:profile",
                            json={
                                "name": profilename,
                                "members": [members],
                                "use_current_ruleset": True,
                                "current_ruleset": active_ruleset[0][
                                    "current_ruleset"
                                ],
                                "comment": comment,
                            },
                        )
                    except WapiRequestException as err:
                        log.error(err)
                        sys.exit(1)
                else:
                    try:
                        new_adp_profile = wapi.post(
                            "threatprotection:profile",
                            json={
                                "name": profilename,
                                "use_current_ruleset": True,
                                "current_ruleset": active_ruleset[0][
                                    "current_ruleset"
                                ],
                                "comment": comment,
                            },
                        )
                    except WapiRequestException as err:
                        log.error(err)
                        sys.exit(1)
                if new_adp_profile.status_code != 201:
                    log.error(
                        "adp profile creation failed: %s", new_adp_profile.text
                    )
                else:
                    adp_profile = new_adp_profile.json()
                    log.info("adp profile created: %s %s", profilename, adp_profile)
            else:
               info.error("profilename not defined")
               sys.exit(1)
    if delete:
        if profilename:
            try:
                # Delete ADP profile
                log.info("searching for adp profile: %s", profilename)
                adp_profile = wapi.get(
                    "threatprotection:profile", params={"name": profilename}
                )
            except WapiRequestException as err:
                log.error(err)
                sys.exit(1)
            if adp_profile.status_code != 200:
                log.error("adp profile %s not found", profilename)
            else:
                adp_profile_removal = adp_profile.json()
                del_adp_profile = wapi.delete(adp_profile_removal[0]["_ref"])
                if del_adp_profile.status_code != 200:
                    log.error(
                        "adp profile removal failed: %s", del_adp_profile.text
                    )
                else:
                    log.info("adp profile removed: %s", del_adp_profile.json())
        else:
            log.error("adp profile name not defined")

    sys.exit()


if __name__ == "__main__":
    main()
