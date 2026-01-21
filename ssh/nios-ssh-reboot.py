#!/usr/bin/env python3

from pexpect import pxssh
import getpass

import click
from click_option_group import optgroup

prompt = r".* Infoblox > "

help_text = """
Interact with Infoblox members via ssh to reboot or shutdown

For more information:
    https://docs.infoblox.com/space/nios85/35477821/Using+the+NIOS+CLI
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
@optgroup.option(
    "-r", "--reboot", is_flag=True, default=False, help="Reboot Grid Member"
)
@optgroup.option(
    "-s", "--shutdown", is_flag=True, default=False, help="Shutdown Grid Member"
)
def main(grid: str, username: str, reboot: bool, shutdown: bool) -> None:
    command = ""
    if reboot:
        command = "reboot"
    if shutdown:
        command = "shutdown"

    try:
        s = pxssh.pxssh()
        hostname = grid
        username = username
        password = getpass.getpass("password: ")
        s.PROMPT = prompt
        s.login(hostname, username, password, auto_prompt_reset=False)
        s.prompt()  # match the prompt
        s.sendline(command)  # run a command
        s.sendline("y")  # run a command
        s.prompt()  # match the prompt
        print(s.before.decode())  # print everything before the prompt.
        s.logout()
    except pxssh.ExceptionPxssh as e:
        print("pxssh failed on login.")
        print(e)


if __name__ == "__main__":
    main()
