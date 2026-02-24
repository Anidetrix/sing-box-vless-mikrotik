#!/bin/sh
exec 2>&1
exec sing-box run -c /singbox.json --disable-color
