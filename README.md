# sing-box-vless-mikrotik

[sing-box](https://sing-box.sagernet.org) container for RouterOS, configured for VLESS with tun interface

- **Docker Hub**: <https://hub.docker.com/r/ani1ak/sing-box-vless-mikrotik>
- **Source**: <https://github.com/Anidetrix/sing-box-vless-mikrotik>

Required env variables:

```rosScript
/container envs
add name=vless key=REMOTE_ADDRESS value=example.com
add name=vless key=ID value=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
add name=vless key=SERVER_NAME value=www.example.com
add name=vless key=PUBLIC_KEY value=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
add name=vless key=SHORT_ID value=XXXXXXXXXXXXXXXX
```

Optional env variables:

```rosScript
/container envs
add name=vless key=LOG_LEVEL value=warn
add name=vless key=DNS value=8.8.8.8,8.8.4.4
add name=vless key=TUN_STACK value=system
add name=vless key=REMOTE_PORT value=443
add name=vless key=FLOW value=xtls-rprx-vision
add name=vless key=FINGER_PRINT value=chrome
```

Optional env variables for rules:

```rosScript
/container envs
add name=vless key=WHITELIST_MODE value=1
add name=vless key=RULESETS value=https://example.com/ruleset_bin.srs,https://example.com/ruleset_src.json
add name=vless key=DOMAINS value=domain1.com,domain2.net
```
