# Proxy-Changer

Version: 0.37c

Development Started: 10.10.22

Proxy Change Program (Temporary only for Windows)

Can take HTTP, HTTPS, FTP and (partially Socks5/4 proxy)

Support proxy overrides, ENV variables, logs

-------

Main class file: vpn_pro.py

File for GUI start: proxy.py

File for logs configure: log_config.py

# Example code

```python
from vpn_pro import ProxyChange, ProxyOff

ProxyChange(protocol="https", ip='192.0.0.1', port='8080', login=login, password=password)

# Do something
...

ProxyOff()
```

# Beta GUI version

For GUI version, you need to start proxy.py

```bash
python proxy.py
```

(Work in progress...)
