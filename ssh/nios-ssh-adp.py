#!/usr/bin/env python3

from pexpect import pxssh
import getpass

import click
from click_option_group import optgroup

prompt = r".* Infoblox > "

help_text = """
Interact with Infoblox members via ssh to enable, disable or show ADP monitor-mode
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
@optgroup.option("-e", "--enable", is_flag=True, help="Enable ADP monitor mode")
@optgroup.option("-d", "--disable", is_flag=True, help="Disable ADP monitor mode")
@optgroup.option("-s", "--show", is_flag=True, help="Show ADP monitor mode status")
def main(grid: str, username: str, enable: bool, disable: bool, show: bool) -> None:
    if enable:
        command = "set adp monitor-mode on"
    if disable:
        command = "set adp monitor-mode off"
    if show:
        command = "show adp monitor-mode"

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
