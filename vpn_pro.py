"""
THIS VERSION IS NOT FINAL RESULT.
"""

import winreg
import os
import platform
import sys
from log_config import log
import subprocess

main_access_key = winreg.KEY_ALL_ACCESS

main_key_dir = winreg.HKEY_CURRENT_USER
sec_key_dir = winreg.HKEY_LOCAL_MACHINE

main_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"  # HKEY_CURRENT_USER (
sys_env_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"  # HKEY_LOCAL_MACHINE (key for sys env variables)
user_env_key = r"Environment"  # HKEY_CURRENT_USER (for user env variables)

proxy_ip_key = "ProxyServer"
proxy_enable_key = "ProxyEnable"
proxy_non_key = "ProxyOverride"

SZ_key = winreg.REG_SZ
REG_key = winreg.REG_DWORD

proxy = {
    "protocol": "http",
    "protocol_prx": "HTTP_PROXY",
    "host": "192.168.1.0",
    "port": "8080",
    "auth": False,
    "login": "",
    "password": "",
    "is_enable": "0",
    "nonproxies": "localhost, 127.0.0.1"
}

platform = platform.system()
print("Current Platform:", platform)

if not platform.startswith("Windows"):
    log("Sorry, but temporary this program only for Windows", "critical", OSError)
    log("Exiting...", "critical")
    sys.exit("Not Windows platform")


def ProxyChange(protocol="http", ip="localhost", port="8080", login=None, password=None,
                proxy_exceptions="localhost, 127.0.0.1"):
    """

    :param protocol: proxy protocol used (http, https, ftp)
    :param ip: IP proxy value
    :param port: port proxy value
    :param login: login proxy value
    :param password: password proxy value
    :param proxy_exceptions: Addresses that will be ignored by the proxy (separated by a comma)
    :return: full http/https string (like: http://login:password@ip:port)

    """

    global proxy

    log(("Start func, params:", protocol, ip, port, login, password, proxy_exceptions), "debug")

    protocol = protocol.upper() if protocol.lower() in "http https ftp socks" else "HTTP"
    proxy["protocol"] = protocol
    proxy["host"] = ip
    proxy["port"] = port
    proxy["login"] = login
    proxy["password"] = password
    proxy["nonproxies"] = proxy_exceptions

    if not login and not password:
        proxy["auth"] = False
        ip_auth = ""
    else:
        proxy["auth"] = True
        ip_auth = "{log}:{pas}".format(log=login, pas=password)

    ip_value = "{host}:{port_p}".format(host=ip, port_p=port)
    ip_value_prt = "{prt}={ip}".format(prt=protocol.lower(), ip=ip_value)

    http_proxy_value = "{prt}://".format(prt=protocol.lower())
    http_proxy_value += ip_value if not proxy["auth"] else f"{ip_auth}@{ip_value}"

    protocol_proxy_value = "{}_PROXY".format(protocol.upper())
    proxy["protocol_prx"] = protocol_proxy_value

    log(("Try to create proxy settings", http_proxy_value), "info")

    env_edit_key(main_key_dir, main_path, proxy_enable_key, REG_key, int("1"))
    proxy["is_enable"] = "1"

    if protocol.lower() != "http":
        env_edit_key(main_key_dir, main_path, proxy_ip_key, SZ_key, ip_value_prt)
    else:
        env_edit_key(main_key_dir, main_path, proxy_ip_key, SZ_key, ip_value)

    env_edit_key(main_key_dir, main_path, proxy_non_key, SZ_key, proxy["nonproxies"])

    env_create_key(main_key_dir, user_env_key, protocol_proxy_value, http_proxy_value)

    os.environ[protocol_proxy_value] = http_proxy_value
    log(os.environ[protocol_proxy_value], "info")

    return http_proxy_value


def env_create_key(branch, subdir, envname, value="None", type=winreg.REG_SZ):
    envname = envname.upper()
    value = str(value)

    try:
        key = winreg.OpenKeyEx(branch, subdir, 0, access=main_access_key)
        res = winreg.QueryValueEx(key, envname)
        log("Key {key} is already exist, canceling create key operation. {res}".format(key=envname, res=res), "debug")

    except FileNotFoundError:
        winreg.SetValueEx(key, envname, 0, type, value)
        res = winreg.QueryValueEx(key, envname)
        log("Successfully created key: {env}//{value}. {res}".format(env=envname, value=value, res=res), "debug")

    finally:
        if key:
            winreg.CloseKey(key)
            log("Key is closed", "debug")


def env_edit_key(branch=None, subdir=None, keyname=None, type=winreg.REG_SZ, value=None):
    if type != winreg.REG_DWORD:
        value = str(value)
    else:
        value = int(value)

    if branch is not None:
        key = winreg.OpenKeyEx(branch, subdir, 0, access=main_access_key)

    try:
        winreg.SetValueEx(key, keyname, 0, type, value)
    except SystemExit:
        log("Error edit key: {}//{}".format(keyname, value), "error")
    else:
        log("Successfully edit key: {}//{}".format(keyname, value), "debug")
    finally:
        if key:
            winreg.CloseKey(key)


def ProxyOff():
    try:
        key = winreg.OpenKey(main_key_dir, main_path, 0, access=main_access_key)

        proxy["is_enable"] = "0"
        env_edit_key(main_key_dir, main_path, proxy_enable_key, REG_key, int("0"))
        assert winreg.QueryValueEx(key, proxy_enable_key)[0] == 0

        key_env = winreg.OpenKey(main_key_dir, user_env_key, 0, access=main_access_key)
        winreg.DeleteValue(key_env, proxy["protocol_prx"])

    except FileNotFoundError:
        log("Key {} is already deleted".format(proxy["protocol_prx"]), "debug")

    else:
        log("Proxy Off operation success", "debug")

    finally:
        winreg.CloseKey(key)
        log("Key is closed", "debug")


if __name__ == "__main__":
    ip_con = input("IP: ")
    port_con = input("PORT: ")
    login = input("LOGIN: ")
    password = input("PASSWORD: ")
    # no_proxy = input("Proxy Overrides (optional, separated by a comma): ")
    ProxyChange(protocol="socks", ip=ip_con, port=port_con, login=login, password=password)
    input("ENTER TO DISABLE PROXY...")
    ProxyOff()
    # print(os.environ.get("HTTP_PROXY"))
