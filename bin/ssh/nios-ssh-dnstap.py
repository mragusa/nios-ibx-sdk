#!/usr/bin/env python3

from pexpect import pxssh
import getpass

import click
from click_option_group import optgroup

prompt = r".* Infoblox > "

help_text = """
Interact with Infoblox members via ssh to enable, disable or show DNS Tap 

For more information:
    https://docs.infoblox.com/space/nios90/280760772/Configuring+dnstap
"""


@click.command(
    help=help_text,
    context_settings=dict(max_content_width=95, help_option_names=["-h", "--help"]),
)
@optgroup.group("Required Parameters")
@optgroup.option("-g", "--grid", required=True, help="Infoblox Grid Manager")
@optgroup.option(
    "-u", "--username", default="admin", required=True, help="Infoblox admin username"
)
@optgroup.group("Optional Parameters")
@optgroup.option("-e", "--enable", is_flag=True, default=False, help="Enable DNS Tap")
@optgroup.option("-d", "--disable", is_flag=True, default=False, help="Disable DNS Tap")
@optgroup.option(
    "-s", "--status", is_flag=True, default=False, help="Show DNS Tap status"
)
@optgroup.option(
    "--statistics", is_flag=True, default=False, help="Show DNS Tap statistics"
)
def main(
    grid: str,
    username: str,
    enable: bool,
    disable: bool,
    status: bool,
    statistics: bool,
) -> None:
    command = ""
    if enable:
        command = "set enable_dnstap on"
    if disable:
        command = "set enable_dnstap off"
    if status:
        command = "show dnstap-status"
    if statistics:
        command = "show dnstap-stats"

    try:
        s = pxssh.pxssh()
        hostname = grid
        username = username
        password = getpass.getpass("password: ")
        s.PROMPT = prompt
        s.login(hostname, username, password, auto_prompt_reset=False)
        s.prompt()  # match the prompt
        s.sendline(command)  # run a command
        s.prompt()  # match the prompt
        print(s.before.decode())  # print everything before the prompt.
        s.logout()
    except pxssh.ExceptionPxssh as e:
        print("pxssh failed on login.")
        print(e)


if __name__ == "__main__":
    main()
