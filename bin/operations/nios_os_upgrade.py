#!/usr/bin/env python3
# TODO: Add downgrade/revert functions


import getpass
import sys
import click
from click_option_group import optgroup
from ibx_sdk.logger.ibx_logger import init_logger, increase_log_level
from ibx_sdk.nios.exceptions import WapiRequestException
from ibx_sdk.nios.gift import Gift
from rich.console import Console

log = init_logger(
    logfile_name="wapi.log",
    logfile_mode="a",
    console_log=True,
    level="info",
    max_size=100000,
    num_logs=1,
)

wapi = Gift()
console = Console()
upgrade_actions = {
    "upgrade": {"action": "UPGRADE"},
    "upgrade_pause": {"action": "UPGRADE_PAUSE"},
    "upgrade_resume": {"action": "UPLOAD_RESUME"},
    "distibution_pause": {"action": "DISTRIBUTION_PAUSE"},
    "distribution_resume": {"action": "DISTRIBUTION_RESUME"},
    "distribution_start": {"action": "DISTRIBUTION_START"},
    "distribution_stop": {"action": "DISTRIBUTION_STOP"},
    # "downgrade": {"action": "DOWNGRADE"},
    # "revert": {"action": "REVERT"},
    "upload": {"action": "UPLOAD"},
    "upgrade_test_start": {"action": "UPGRADE_TEST_START"},
    "upgrade_test_stop": {"action": "UPGRADE_TEST_STOP"},
}


help_text = """
Upload NIOS BIN file to Infoblox appliance and initate upgrade process 
"""


def get_grid_reference(wapi):
    try:
        grid_object = wapi.get("grid")
        if grid_object.status_code != 200:
            console.print("[red] Unable to retrieve grid object[/]")
            sys.exit(1)
        else:
            grid_reference = grid_object.json()
            console.print(f"[green]Grid Reference: {grid_reference[0]["_ref"]}[/]")
            return grid_reference[0]["_ref"]
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def upload_bin_file(wapi, file):
    try:
        console.print(f"[green]NIOS Upgrade BIN: {file}[/]")
        upgrade_bin_token = wapi.file_upload(file)
        console.print(f"[green]File: {file} \nToken: {upgrade_bin_token}[/]")
        upload_status = wapi.post(
            "fileop",
            json={"token": upgrade_bin_token},
            params={"_function": "set_upgrade_file"},
        )
        if upload_status.status_code != 200:
            console.print("[red] Unable to upload BIN file[/]")
        else:
            console.print("[green]Upgrade file set correctly[/]")
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def set_grid_upload(wapi, grid_mgr, gridref):
    try:
        console.print(f"[green]Initating upload on {grid_mgr}[/]")
        upload_response = wapi.post(
            gridref,
            json=upgrade_actions["upload"],
            params={"_function": "upgrade"},
        )
        if upload_response.status_code != 200:
            log.error(
                f"Unable to initiate upload: {upload_response.status_code} {upload_response.json().get('code')} {upload_response.json().get('text')}"
            )
            console.print(
                f"[red] Unable to initiate upload: {upload_response.status_code} {upload_response.json().get('code')} {upload_response.json().get('text')}[/]"
            )
        else:
            log.info(f"Upload initiated successfully on {grid_mgr}")
            console.print(f"[green]Upload initiated successfully on {grid_mgr}[/]")
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def set_grid_action(wapi, grid_mgr, gridref, action):
    try:
        console.print(f"[green]Initating {action} on {grid_mgr}[/]")
        action_response = wapi.post(
            gridref,
            json=upgrade_actions[action],
            params={"_function": "upgrade"},
        )
        if action_response.status_code != 200:
            log.error(
                f"Unable to {action} {action_response.status_code} {action_response.json().get('code')} {action_response.json().get('text')}"
            )
            console.print(
                f"[red]Unable to {action} {action_response.status_code} {action_response.json().get('code')} {action_response.json().get('text')}"
            )
        else:
            log.info(f"{action} successful on {grid_mgr}")
            console.print(f"[green]{action} successful on {grid_mgr}[/]")
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid-mgr", required=True, help="Infoblox Grid Manager")
@optgroup.option("-f", "--file", required=True, help="NIOS BIN file")
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
    default="2.13.7",
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
@optgroup.group("NIOS Upgrade Actions")
@optgroup.option(
    "-a",
    "--action",
    type=click.Choice(
        [
            "upgrade",
            "upgrade_pause",
            "upgrade_resume",
            "distribution_pause",
            "distribution_resume",
            "distribution_start",
            "distribution_stop",
            "downgrade",
            "revert",
            "upload",
            "upgrade_test_start",
            "upgrade_test_stop",
        ]
    ),
    help="NIOS Upgrade Actions",
)
def main(
    grid_mgr: str, file: str, username: str, wapi_ver: str, debug: bool, action: list
) -> None:
    if debug:
        increase_log_level()
    wapi.grid_mgr = grid_mgr
    wapi.wapi_ver = wapi_ver
    wapi.timeout = 1800
    password = getpass.getpass(f"Enter password for [{username}]: ")
    try:
        wapi.connect(username=username, password=password)
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)
    else:
        if debug:
            log.info(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
        print(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
    # Assign file and upload to grid
    reference = get_grid_reference(wapi)
    upload_bin_file(wapi=wapi, file=file)
    set_grid_upload(wapi=wapi, grid_mgr=grid_mgr, gridref=reference)
    # Assign action to begin upgrade process
    if action:
        set_grid_action(wapi=wapi, grid_mgr=grid_mgr, gridref=reference, action=action)
    sys.exit()


if __name__ == "__main__":
    main()
