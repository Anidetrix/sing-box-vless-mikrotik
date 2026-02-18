#!/bin/sh
# log
LOG_LEVEL="${LOG_LEVEL:-warn}"

# dns
DNS="${DNS:-8.8.8.8}"

# tun
TUN_STACK="${TUN_STACK:-system}"

# vless
REMOTE_ADDRESS="${REMOTE_ADDRESS:-}"
REMOTE_PORT="${REMOTE_PORT:-443}"
ID="${ID:-}"
FLOW="${FLOW:-xtls-rprx-vision}"
SERVER_NAME="${SERVER_NAME:-}"
FINGER_PRINT="${FINGER_PRINT:-chrome}"
PUBLIC_KEY="${PUBLIC_KEY:-}"
SHORT_ID="${SHORT_ID:-}"

# rules
WHITELIST_MODE="${WHITELIST_MODE:-}"
RULESETS="${RULESETS:-}"
DOMAINS="${DOMAINS:-}"

out="vless-out"
out_rules="bypass"
if [ -n "${WHITELIST_MODE}" ]; then
	_out=${out}
	out=${out_rules}
	out_rules=${_out}
	unset _out
fi

cat << EOF > /singbox.json
{
  "log": {
    "level": "${LOG_LEVEL}",
    "timestamp": false
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-proxy",
        "address": "${DNS}",
        "address_resolver": "dns-local",
        "detour": "vless-out"
      },
      {
        "tag": "dns-local",
        "address": "local",
        "detour": "bypass"
      }
    ],
    "strategy": "prefer_ipv4",
    "reverse_mapping": true
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": ["198.18.0.1/30"],
      "mtu": 1500,
      "auto_route": true,
      "auto_redirect": false,
      "strict_route": true,
      "stack": "${TUN_STACK}",
      "route_exclude_address": [
        "192.168.0.0/16",
        "172.16.0.0/12",
        "10.0.0.0/8",
        "fc00::/7"
      ]
    },
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "$(ip -o -f inet address show | awk 'END {print $4}' | cut -d/ -f1)",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "${REMOTE_ADDRESS}",
      "server_port": ${REMOTE_PORT},
      "uuid": "${ID}",
      "flow": "${FLOW}",
      "tls": {
        "enabled": true,
        "server_name": "${SERVER_NAME}",
        "utls": {
          "enabled": true,
          "fingerprint": "${FINGER_PRINT}"
        },
        "reality": {
          "enabled": true,
          "public_key": "${PUBLIC_KEY}",
          "short_id": "${SHORT_ID}"
        }
      },
      "packet_encoding": "xudp"
    },
    {
      "type": "direct",
      "tag": "bypass"
    }
  ],
  "route": {
    "default_domain_resolver": "dns-local",
    "auto_detect_interface": true,
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      }
    ],
    "final": "${out}"
  },
  "experimental": {
    "cache_file": {
      "enabled": true
    }
  }
}
EOF

mergeconf() {
	local logfile=$(mktemp)
	sing-box merge singbox.json -D / -c /singbox.json -c "$1" --disable-color > ${logfile} 2>&1
	if [ $? -ne 0 ]; then
		cat ${logfile}
		exit 1
	fi
	rm -f ${logfile} "$1"
}

add_rule() {
	local IFS=,
	local entries=""
	local tmpfile=$(mktemp)
	for e in $2; do entries="${entries}\"${e}\","; done
	cat <<- EOF > ${tmpfile}
		{
		  "route": {
		    "rules": [
		      {
		        "$1": [${entries%?}],
		        "action": "route",
		        "outbound": "${out_rules}"
		      }
		    ]
		  }
		}
	EOF
	mergeconf ${tmpfile}
}

add_rulesets() {
	local IFS=,
	local entries=""
	local tmpfile=$(mktemp)
	local i=1
	for url in $1; do
		local tag="ruleset-${i}"
		entries="${entries}${tag},"
		local format
		case "${url}" in
		*.json) format=source ;;
		*) format=binary ;;
		esac
		cat <<- EOF > ${tmpfile}
			{
			  "route": {
			    "rule_set": [
			      {
			        "tag": "${tag}",
			        "type": "remote",
			        "format": "${format}",
			        "url": "${url}",
			        "download_detour": "vless-out",
			        "update_interval": "2h"
			      }
			    ]
			  }
			}
		EOF
		mergeconf ${tmpfile}
		i=$((i + 1))
	done
	add_rule rule_set "${entries%?}"
}

[ -n "${DOMAINS}" ] && add_rule domain_suffix ${DOMAINS}
[ -n "${RULESETS}" ] && add_rulesets ${RULESETS}
sing-box check -c /singbox.json --disable-color || exit 1
exec runsv /service
