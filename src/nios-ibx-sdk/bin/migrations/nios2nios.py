#!/usr/bin/env python3
# TODO:
# Automatically downgrade required EA to optional for csv exports
# Add flag to automate entire migration
# Update help menu to allow piece meal migration ie user, role, zones
# Update Output to show step processing
# Determine what can be exported via CSV and reimported
# Determine what can be exported via CSV export and what requires API
# Find way to update data in transit, ie change member, nsgroup, discovery member
# Determine default view and see if view name needs to be changed
# Script Process
#   1. Migrate Extensible extensible attributes
#   2. Migrate roles, groups, users
#   3. Migrate network, dns, vlan (static and ranges) views
#   4. Migrate network containers and networks
#   5. Migrate DHCP Data
#   6. Migrate DNS Data
#       - Host records
#       - Standard Records
#   7. Compare object counts


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
newgrd = Gift()
print(
    r"""
.--------------------------------------------------------------------------------------------------------.
|                                                                                                        |
|                             <-. (`-')_   _                  (`-').->                                   |
|                                \( OO) ) (_)          .->    ( OO)_                                     |
|                             ,--./ ,--/  ,-(`-') (`-')----. (_)--\_)                                    |
|                             |   \ |  |  | ( OO) ( OO).-.  '/    _ /                                    |
|                             |  . '|  |) |  |  ) ( _) | |  |\_..`--.                                    |
|                             |  |\    | (|  |_/   \|  |)|  |.-._)   \                                   |
|                             |  | \   |  |  |'->   '  '-'  '\       /                                   |
|                             `--'  `--'  `--'       `-----'  `-----'                                    |
|     <-. (`-')    _                    (`-')   (`-')  _  (`-')        _                 <-. (`-')_      |
|        \(OO )_  (_)         .->    <-.(OO )   (OO ).-/  ( OO).->    (_)          .->      \( OO) )     |
|     ,--./  ,-.) ,-(`-')  ,---(`-') ,------,)  / ,---.   /    '._    ,-(`-') (`-')----. ,--./ ,--/      |
|     |   `.'   | | ( OO) '  .-(OO ) |   /`. '  | \ /`.\  |'--...__)  | ( OO) ( OO).-.  '|   \ |  |      |
|     |  |'.'|  | |  |  ) |  | .-, \ |  |_.' |  '-'|_.' | `--.  .--'  |  |  ) ( _) | |  ||  . '|  |)     |
|     |  |   |  |(|  |_/  |  | '.(_/ |  .   .' (|  .-.  |    |  |    (|  |_/   \|  |)|  ||  |\    |      |
|     |  |   |  | |  |'-> |  '-'  |  |  |\  \   |  | |  |    |  |     |  |'->   '  '-'  '|  | \   |      |
|     `--'   `--' `--'     `-----'   `--' '--'  `--' `--'    `--'     `--'       `-----' `--'  `--'      |
|                             (`-')                                                                      |
|                             ( OO).->        .->        .->      <-.                                    |
|                             /    '._   (`-')----. (`-')----.  ,--. )                                   |
|                             |'--...__) ( OO).-.  '( OO).-.  ' |  (`-')                                 |
|                             `--.  .--' ( _) | |  |( _) | |  | |  |OO )                                 |
|                                |  |     \|  |)|  | \|  |)|  |(|  '__ |                                 |
|                                |  |      '  '-'  '  '  '-'  ' |     |'                                 |
|                                `--'       `-----'    `-----'  `-----'                                  |
|                                                                                                        |
'--------------------------------------------------------------------------------------------------------'
"""
)

help_text = """
Migrate NIOS to NIOS: Using WAPI and CSV exports to directly move data from one grid to another.
"""

wapi_mapping = {
    "admins": "adminuser",
    "roles": "adminrole",
    "groups": "admingroup",
    "ea": "extensibleattributedef",
}


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-n", "--new-grid", required=True, help="New Infoblox Grid Manager")
@optgroup.group("Import Object Type")
@optgroup.option(
    "-c",
    "--choice",
    type=click.Choice(["admins", "roles", "groups", "ea"]),
    help="Configuration Data to Migrate",
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
    default="2.12.6",
    show_default=True,
    help="Infoblox WAPI version",
)
@optgroup.group("Logging Parameters")
@optgroup.option("--debug", is_flag=True, help="enable verbose debug output")
def main(
    grid_mgr: str,
    new_grid: str,
    username: str,
    wapi_ver: str,
    debug: bool,
    choice: str,
) -> None:
    if debug:
        increase_log_level()
    wapi.grid_mgr = grid_mgr
    wapi.wapi_ver = wapi_ver
    newgrd.grid_mgr = new_grid
    newgrd.wapi_ver = wapi_ver
    password = getpass.getpass(f"Enter password for [{username}]: ")
    new_grid_password = getpass.getpass(f"Enter new grid password for [{username}]: ")
    try:
        wapi.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        log.info("Connected to Infoblox grid manager %s", wapi.grid_mgr)

    try:
        newgrd.connect(username=username, password=new_grid_password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        log.info("Connected to New Infoblox grid manager %s", wapi.grid_mgr)
    # Add Roles, Groups, and then Users
    current = get_current_setup(wapi_mapping[choice])
    if current:
        for x in current:
            if debug:
                print(x)
            exists_check = exists_in_new(wapi_mapping[choice], x["name"])
            print(exists_check)
            if not exists_check:
                if choice == "ea" and x["namespace"] == "CLOUD":
                    continue
                if choice == "ea":
                    del x["namespace"]
                if choice == "ea" and x["default_value"] is None:
                    del x["default_value"]
                add_ibx_obj(wapi_mapping[choice], x)
            else:
                print("Exists in New Grid")
    else:
        print(
            "Unable to get current Infoblox values for {}".format(wapi_mapping[choice])
        )

    sys.exit()


def get_current_setup(selection):
    choice_return_fields = {
        "adminrole": ["name", "comment", "disable", "extattrs"],
        "admingroup": [
            "access_method",
            "admin_set_commands",
            "admin_set_commands",
            "admin_toplevel_commands",
            "cloud_set_commands",
            "cloud_show_commands",
            "comment",
            "database_set_commands",
            "database_show_commands",
            "dhcp_set_commands",
            "dhcp_show_commands",
            "disable",
            "disable_concurrent_login",
            "dns_set_commands",
            "dns_show_commands",
            "dns_toplevel_commands",
            "docker_set_commands",
            "docker_show_commands",
            "email_addresses",
            "enable_restricted_user_access",
            "extattrs",
            "grid_set_commands",
            "grid_show_commands",
            "inactivity_lockout_setting",
            "licensing_set_commands",
            "licensing_show_commands",
            "lockout_setting",
            "machine_control_toplevel_commands",
            "name",
            "networking_set_commands",
            "networking_show_commands",
            "password_setting",
            "roles",
            "saml_setting",
            "security_set_commands",
            "security_show_commands",
            "superuser",
            "trouble_shooting_toplevel_commands",
            "use_account_inactivity_lockout_enable",
            "use_disable_concurrent_login",
            "use_lockout_setting",
            "use_password_setting",
            "user_access",
        ],
        "adminuser": [
            "admin_groups",
            "auth_method",
            "auth_type",
            "ca_certificate_issuer",
            "client_certificate_serial_number",
            "comment",
            "disable",
            "email",
            "enable_certificate_authentication",
            "extattrs",
            "name",
            "ssh_keys",
            "time_zone",
            "use_ssh_keys",
            "use_time_zone",
        ],
        "extensibleattributedef": [
            "allowed_object_types",
            "comment",
            "default_value",
            "flags",
            "list_values",
            "max",
            "min",
            "name",
            "namespace",
            "type",
        ],
    }
    try:
        # Retrieve network view from Infoblox appliance
        roles = wapi.get(
            selection, params={"_return_fields": choice_return_fields[selection]}
        )
        if roles.status_code != 200:
            print(roles.status_code, roles.text)
        else:
            admin_roles = roles.json()
            return admin_roles
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def add_ibx_obj(selection, data):
    try:
        new_object = newgrd.post(selection, json=data)
        if new_object.status_code != 201:
            print(new_object.status_code, new_object.text)
        else:
            print(selection, new_object.json())
            log.info("Created Object: %s %s", selection, new_object.json())
    except WapiRequestException as err:
        print(err)


def exists_in_new(choice, name):
    try:
        existing = newgrd.get(choice, params={"name": name})
        if existing.status_code != 200:
            print(existing.status_code, existing.text)
        else:
            e = existing.json()
            if e:
                print("Exists", existing.json(), existing.status_code)
                return True
            else:
                return False
    except WapiRequestException as err:
        print(err)


if __name__ == "__main__":
    main()
