"""
THIS VERSION IS NOT FINAL RESULT.
"""

import winreg
import os
import platform
import sys
import subprocess

main_access_key = winreg.KEY_ALL_ACCESS

main_key_dir = winreg.HKEY_CURRENT_USER

main_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"  # HKEY_CURRENT_USER
sys_env_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
user_env_key = r"Environment"

proxy_ip_key = "ProxyServer"
proxy_enable_key = "ProxyEnable"
proxy_non_key = "ProxyOverride"
user_env_http_key = "HTTP_PROXY"
user_env_https_key = "HTTPS_PROXY"
user_env_ftp_key = "FTP_PROXY"

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
    print("Sorry, but temporary this program only for Windows")
    print("Exiting...")
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

    protocol = protocol.upper() if protocol in "http https ftp socks HTTP HTTPS FTP SOCKS" else "HTTP"
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

    print(proxy["protocol"], protocol_proxy_value)

    with winreg.OpenKey(main_key_dir, main_path, 0, access=main_access_key) as key:
        winreg.SetValueEx(key, proxy_enable_key, 0, REG_key, int("1"))
        proxy["is_enable"] = "1"

        if protocol.lower() != "http":
            winreg.SetValueEx(key, proxy_ip_key, 0, SZ_key, ip_value_prt)
        else:
            winreg.SetValueEx(key, proxy_ip_key, 0, SZ_key, ip_value)

        winreg.SetValueEx(key, proxy_non_key, 0, SZ_key, proxy["nonproxies"])

    env_create_key(main_key_dir, user_env_key, protocol_proxy_value, http_proxy_value)

    os.environ[protocol_proxy_value] = http_proxy_value
    print(os.environ[protocol_proxy_value])

    return http_proxy_value


def env_create_key(branch, subdir, envname, value="None", type=winreg.REG_SZ):
    envname = envname.upper()
    value = str(value)

    try:
        key = winreg.OpenKeyEx(branch, subdir, 0, access=main_access_key)
        res = winreg.QueryValueEx(key, envname)
        print("Key is already exist")

    except FileNotFoundError:
        winreg.SetValueEx(key, envname, 0, type, value)
        res = winreg.QueryValueEx(key, envname)
        print("Successfully created key: {env}//{value}".format(env=envname, value=value))

    finally:
        if key:
            winreg.CloseKey(key)


def ProxyOff():
    try:
        key = winreg.OpenKey(main_key_dir, main_path, 0, access=main_access_key)

        proxy["is_enable"] = "0"
        winreg.SetValueEx(key, proxy_enable_key, 0, REG_key, int("0"))
        assert winreg.QueryValueEx(key, proxy_enable_key)[0] == 0

        key_env = winreg.OpenKey(main_key_dir, user_env_key, 0, access=main_access_key)
        winreg.DeleteValue(key_env, proxy["protocol_prx"])

    except FileNotFoundError:
        print("Key is already deleted")

    else:
        print("All is okay")

    finally:
        winreg.CloseKey(key)


if __name__ == "__main__":
    ip_con = input("IP: ")
    port_con = input("PORT: ")
    login = input("LOGIN: ")
    password = input("PASSWORD: ")
    ProxyChange(protocol="http", ip=ip_con, port=port_con, login=login, password=password)
    input("ENTER TO DISABLE PROXY...")
    ProxyOff()
    # print(os.environ.get("HTTP_PROXY"))
