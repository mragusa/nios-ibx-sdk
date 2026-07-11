#!/usr/bin/env python3


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

help_text = """
Upload NIOS BIN file to Infoblox appliance and initate the file distribution and upgrade
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
            params={"_function": "set_upgrade_file", "token": upgrade_bin_token},
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
        upload_body = {"action": "UPLOAD"}
        upload_response = wapi.post(
            gridref,
            json=upload_body,
            params={"_function": "upgrade"},
        )
        if upload_response.status_code != 200:
            log.error(
                f"Unable to initiate upload: {upload_response.status_code} {upload_response.code} {upload_response.text}"
            )
            console.print(
                f"[red] Unable to initiate upload: {upload_response.status_code} {upload_response.code} {upload_response.text}[/]"
            )
        else:
            log.info(f"Upload initiated successfully on {grid_mgr}")
            console.print(f"[green]Upload initiated successfully on {grid_mgr}[/]")
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def set_grid_distribution(wapi, grid_mgr, gridref):
    try:
        console.print(f"[green]Initating distribution on {grid_mgr}[/]")
        distribution_body = {"action": "DISTRIBUTION_START"}
        distribution_response = wapi.post(
            gridref,
            json=distribution_body,
            params={"_function": "upgrade"},
        )
        if distribution_response.status_code != 200:
            log.error(
                f"[red]Unable to start distribution {distribution_response.status_code} {distribution_response.code} {distribution_response.text}"
            )
            console.print(
                f"[red]Unable to start distribution {distribution_response.status_code} {distribution_response.code} {distribution_response.text}"
            )
        else:
            log.info(f"Distribution initiated successfully on {grid_mgr}")
            console.print(
                f"[green]Distribution initiated successfully on {grid_mgr}[/]"
            )
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def set_grid_upgrade_test(wapi, grid_mgr, gridref):
    try:
        console.print(f"[green]Initating upgrade test on {grid_mgr}[/]")
        upgrade_test_body = {"action": "UPGRADE_TEST_START"}
        upgrade_test_response = wapi.post(
            gridref,
            json=upgrade_test_body,
            params={"_function": "upgrade"},
        )
        if upgrade_test_response.status_code != 200:
            log.error(
                f"Unable to complete upgrade test {upgrade_test_response.status_code} {upgrade_test_response.code} {upgrade_test_response.text}"
            )
            console.print(
                f"[red]Unable to complete upgrade test {upgrade_test_response.status_code} {upgrade_test_response.code} {upgrade_test_response.text}[/]"
            )
        else:
            log.info(f"Upgrade test completed successfully on {grid_mgr}")
            console.print(
                f"[green]Upgrade test completed successfully on {grid_mgr}[/]"
            )
    except WapiRequestException as err:
        log.error(err)
        sys.exit(1)


def set_grid_upgrade(wapi, grid_mgr, gridref):
    try:
        console.print(f"[green]Initating upgrade on {grid_mgr}[/]")
        upgrade_body = {"action": "UPGRADE"}
        grid_upgrade_response = wapi.post(
            gridref,
            json=upgrade_body,
            params={"_function": "upgrade"},
        )
        if grid_upgrade_response.status_code != 200:
            log.error(
                f"Upgrade on {grid_mgr} failed: {grid_upgrade_response.status_code} {grid_upgrade_response.code} {grid_upgrade_response.text}"
            )
            console.print(
                f"[red]Upgrade on {grid_mgr} failed: {grid_upgrade_response.status_code} {grid_upgrade_response.code} {grid_upgrade_response.text}[/]"
            )
        else:
            log.info(f"Upgrade initiated successfully on {grid_mgr}")
            console.print(f"[green]Upgrade initiated successfully on {grid_mgr}[/]")
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
def main(grid_mgr: str, file: str, username: str, wapi_ver: str, debug: bool) -> None:
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
            log.info(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
        print(f"Connected to Infoblox grid manager {wapi.grid_mgr}")
    reference = get_grid_reference(wapi)
    upload_bin_file(wapi, file)
    set_grid_upload(wapi, grid_mgr, reference)
    sys.exit()


if __name__ == "__main__":
    main()
