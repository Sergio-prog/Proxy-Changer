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
user_env_http_key = "HTTP_PROXY"

SZ_key = winreg.REG_SZ
REG_key = winreg.REG_DWORD

proxy = {
    "protocol": "http",
    "host": "192.168.1.0",
    "port": "3128",
    "auth": False,
    "login": "",
    "password": "",
    "is_enable": "0"
}

nonproxies = "localhost, 127.0.0.1"
http_proxy_value = "http://"

platform = platform.system()
print("Current Platform:", platform)

if not platform.startswith("Windows"):
    print("Sorry, but temporary this program only for Windows")
    print("Exiting...")
    sys.exit("Not Windows platform")


def ProxyChange(ip="localhost", port="8080", login=None, password=None):
    """

    :param ip: IP proxy value
    :param port: port proxy value
    :param login: login proxy value
    :param password: password proxy value
    :return: full http/https string (like: http://login:password@ip:port)

    """

    global proxy, http_proxy_value

    proxy["host"] = ip
    proxy["port"] = port
    proxy["login"] = login
    proxy["password"] = password

    if not login and not password:
        proxy["auth"] = False
    else:
        proxy["auth"] = True

    if proxy["auth"] and login and password:
        ip_auth = "{log}:{pas}".format(log=login, pas=password)
    else:
        ip_auth = ""

    ip_value = "{host}:{port_p}".format(host=ip, port_p=port)

    http_proxy_value += ip_value if not proxy["auth"] else f"{ip_auth}@{ip_value}"

    proxy["is_enable"] = "1"
    with winreg.OpenKey(main_key_dir, main_path, 0, access=main_access_key) as key:
        winreg.SetValueEx(key, proxy_enable_key, 0, REG_key, int(proxy["is_enable"]))
        winreg.SetValueEx(key, proxy_ip_key, 0, SZ_key, ip_value)

    env_create_key(main_key_dir, user_env_key, "HTTP_PROXY", http_proxy_value)

    os.environ["HTTP_PROXY"] = http_proxy_value
    print(os.environ["HTTP_PROXY"])

    return http_proxy_value


def env_create_key(branch, subdir, envname, value, type=winreg.REG_SZ):
    envname = envname.upper()
    value = str(value)

    try:
        key = winreg.OpenKeyEx(branch, subdir, 0, main_access_key)
        res = winreg.QueryValueEx(key, envname)

    except FileNotFoundError:
        winreg.SetValueEx(key, envname, 0, type, value)
        subprocess.run('setx ttt t > nul', shell=True)

    finally:
        if key:
            winreg.CloseKey(key)


def ProxyOff():
    try:
        key = winreg.OpenKeyEx(main_key_dir, main_path, 0, access=main_access_key)
        winreg.SetValueEx(key, proxy_enable_key, 0, REG_key, "0")
        key_env = winreg.OpenKeyEx(main_key_dir, user_env_key, 0, access=main_access_key)
        winreg.DeleteValue(key_env, "HTTP_PROXY")

    except FileNotFoundError:
        return print("Key is already deleted")

    finally:
        winreg.CloseKey(key)


if __name__ == "__main__":
    ip_con = input("IP: ")
    port_con = input("PORT: ")
    login = input("LOGIN: ")
    password = input("PASSWORD: ")
    ProxyChange(ip_con, port_con, login, password)
    input("ENTER TO DISABLE PROXY...")
    # ProxyOff()
    # print(os.environ.get("HTTP_PROXY"))
