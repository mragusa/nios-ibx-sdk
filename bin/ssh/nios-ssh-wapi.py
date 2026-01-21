#!/usr/bin/env python3

from pexpect import pxssh
import getpass

import click
from click_option_group import optgroup

prompt = r".* Infoblox > "

help_text = """
Enable WAPI optimizations on NIOS Grid Master

For more information: https://blogs.infoblox.com/community/turbocharge-your-infoblox-restful-api-calls-part-1/
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
    "-e", "--enable", default=False, is_flag=True, help="Enable WAPI optimizations"
)
@optgroup.option(
    "-d", "--disable", default=False, is_flag=True, help="Disable WAPI optimizatons"
)
def main(grid: str, username: str, enable: bool, disable: bool) -> None:
    command = []
    if enable:
        command = [
            "set httpd_client keepalive on",
            "set httpd_client keepalivetime 5",
            "set httpd_client maxrequest 2048",
        ]
    if disable:
        command = ["set httpd_client keepalive off"]

    try:
        s = pxssh.pxssh()
        hostname = grid
        username = username
        password = getpass.getpass("password: ")
        s.PROMPT = prompt
        s.login(hostname, username, password, auto_prompt_reset=False)
        s.prompt()  # match the prompt
        for wapi in command:
            s.sendline(wapi)  # run a command
        s.prompt()  # match the prompt
        print(s.before.decode())  # print everything before the prompt.
        s.logout()
    except pxssh.ExceptionPxssh as e:
        print("pxssh failed on login.")
        print(e)


if __name__ == "__main__":
    main()
