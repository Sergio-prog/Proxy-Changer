"""
THIS VERSION IS NOT FINAL RESULT.
"""
import winreg
import os
import platform
import sys
from log_config import log
from typing import NoReturn

__ver__ = "0.37d"

main_access_key = winreg.KEY_ALL_ACCESS

main_key_dir = winreg.HKEY_CURRENT_USER
sec_key_dir = winreg.HKEY_LOCAL_MACHINE

main_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"  # HKEY_CURRENT_USER (for proxy settings)
sys_env_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"  # HKEY_LOCAL_MACHINE (key for sys env variables)
user_env_key = r"Environment"  # HKEY_CURRENT_USER (for user env variables)

# Key names
proxy_ip_key = "ProxyServer"
proxy_enable_key = "ProxyEnable"
proxy_non_key = "ProxyOverride"

# Win reg types
SZ_key = winreg.REG_SZ
REG_key = winreg.REG_DWORD

# Proxy settings
proxy = {
    "protocol": "http",
    "protocol_prx": "HTTP_PROXY",
    "host": "192.168.1.0",
    "port": "8080",
    "auth": False,
    "login": "",
    "password": "",
    "is_enable": "0",
    "nonproxies": "<local>,localhost,127.0.0.1"
}

# OS Check
platform = platform.system()

if platform.startswith("Windows"):
    log("Current OS: {os}".format(os=platform), "debug")
else:
    log("Sorry, but temporary this program only for Windows", "critical", is_print=True)
    log("Exiting...", "critical", is_print=True)
    sys.exit("OSError: Wrong OS [{os}]. (Needs Windows platform)".format(os=platform))


def ProxyChange(protocol="http", ip="192.0.0.1", port="8080", login: str = None, password: str = None,
                proxy_exceptions: str = "localhost, 127.0.0.1") -> str:
    """
    A function for changing the system proxy by editing the keys of the windows registry editor

    :param protocol: proxy protocol used (http, https, ftp)
    :param ip: IP proxy value
    :param port: port proxy value
    :param login: login proxy value
    :param password: password proxy value
    :param proxy_exceptions: Addresses that will be ignored by the proxy (separated by a comma)
    :returns: Full proxy string (with connection type) (like: https://login:password@ip:port)
    """

    global proxy

    assert (ip and port)

    log("Log init Proxy Changer {ver}".format(ver=__ver__), "debug")
    log(("Start func, params:", protocol, ip, port, login, password, proxy_exceptions), "debug")

    protocol = protocol.upper() if protocol.lower() in "http https ftp socks" else "HTTP"
    proxy["protocol"] = protocol
    proxy["host"] = ip
    proxy["port"] = port
    proxy["login"] = login
    proxy["password"] = password
    proxy["nonproxies"] = proxy_exceptions

    # Proxy login
    if not login and not password:
        proxy["auth"] = False
        ip_auth = ""
    else:
        proxy["auth"] = True
        ip_auth = "{log}:{pas}".format(log=proxy["login"], pas=proxy["password"])

    # Proxy strings for keys
    ip_value = "{host}:{port_p}".format(host=proxy["host"], port_p=proxy["port"])
    ip_value_prt = "{prt}={ip}".format(prt=protocol.lower(), ip=ip_value)

    # Full proxy string with protocol
    http_proxy_value = "{prt}://".format(prt=protocol.lower())
    http_proxy_value += ip_value if not proxy["auth"] else f"{ip_auth}@{ip_value}"

    # Protocol string for keys
    protocol_proxy_value = "{}_PROXY".format(protocol.upper())
    proxy["protocol_prx"] = protocol_proxy_value

    log(("Try to create proxy settings", http_proxy_value), "info")

    # Proxy enable in winreg
    env_edit_key(main_key_dir, main_path, proxy_enable_key, REG_key, int("1"))
    proxy["is_enable"] = "1"

    # Add proxy string to winreg with protocols
    if protocol.lower() != "http":
        env_edit_key(main_key_dir, main_path, proxy_ip_key, SZ_key, ip_value_prt)
    else:
        env_edit_key(main_key_dir, main_path, proxy_ip_key, SZ_key, ip_value)

    env_edit_key(main_key_dir, main_path, proxy_non_key, SZ_key, proxy["nonproxies"])  # Add non proxy

    # Create Env variable with protocol name
    env_create_key(main_key_dir, user_env_key, protocol_proxy_value, http_proxy_value)

    os.environ[protocol_proxy_value] = http_proxy_value
    log(os.environ[protocol_proxy_value], "info")

    return http_proxy_value


def env_create_key(branch=None, subdir=None, envname=None, value=None, type=winreg.REG_SZ) -> NoReturn:
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


def env_edit_key(branch=None, subdir=None, keyname=None, type=winreg.REG_SZ, value=None) -> NoReturn:
    if type == winreg.REG_DWORD:
        value = int(value)
    else:
        value = str(value)

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


def ProxyOff() -> NoReturn:
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


def ProxyCheck() -> bool:
    """:returns: Status of proxy enable."""
    key = winreg.OpenKey(main_key_dir, main_path, 0, access=main_access_key)

    value: int = winreg.QueryValueEx(key, proxy_enable_key)[0]
    winreg.CloseKey(key)

    return bool(value)


# Test Function
'''
def is_okay_ping(is_print=True, delay=10):
    time.sleep(delay)
    try:
        st = pyspeedtest.SpeedTest()
        ping = st.download() / (2 ** 20)
        log("\nPing: {0}".format(ping), "debug", is_print=is_print)

        if ping >= norm_ping:
            log("Looks like ping higher than normal value.", "debug", is_print=is_print)
    except Exception:
        log("Failed to find server for test connection. Try this: https://stackoverflow.com/questions/50999879/pyspeedtest-cannot-find-test-server",
            "error")
    except TimeoutError:
        log("Looks like proxy is not working. Program can't send request for test connection.", "warn", is_print=True)

    return ping
'''

if __name__ == "__main__":
    ip_con = input("IP: ")
    port_con = input("PORT: ")
    login = input("LOGIN: ")
    password = input("PASSWORD: ")
    no_proxy = input("Proxy Overrides (optional, separated by a comma): ")
    ProxyChange(protocol="socks", ip=ip_con, port=port_con, login=login, password=password)
    input("ENTER TO DISABLE PROXY...")
    ProxyOff()
