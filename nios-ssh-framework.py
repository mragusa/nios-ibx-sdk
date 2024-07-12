#!/usr/bin/env python3

from pexpect import pxssh
import getpass

import click
from click_option_group import optgroup

# prompt = r'\r\n\r\n\r\n\s+Infoblox NIOS Release 9\.0\.3-50212-ee11d5834df9 \(64bit\)\r\n\s+Copyright \(c\) 1999-2023 Infoblox Inc. All Rights Reserved\.\r\n\r\n\s+type \'help\' for more information\r\n\r\n\r\nInfoblox > '

prompt = r".* Infoblox > "

help_text = """
Explaination of script
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
def main(grid: str, username: str) -> None:
    command = "show version"
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
