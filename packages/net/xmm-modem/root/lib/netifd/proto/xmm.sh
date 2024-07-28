#!/bin/sh

XMM_LIB_PATH=/etc/xmmlib

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

proto_xmm_init_config() {
    no_device=1
    available=1
    proto_config_add_string "device:device"
    proto_config_add_string "apn"
    proto_config_add_string "pdp"
    proto_config_add_string "delay"
    proto_config_add_string "username"
    proto_config_add_string "password"
    proto_config_add_string "auth"
    proto_config_add_defaults
}

proto_xmm_setup() {
    local interface="$1"
    local OX device ifname auth username password apn pdp delay $PROTO_DEFAULT_OPTIONS
    json_get_vars device ifname auth username password apn pdp delay $PROTO_DEFAULT_OPTIONS
	
    [ "$metric" = "" ] && metric="0"
    [ -z $ifname ] && {
	    local devname devpath hwaddr
        devname=$(basename $device)
        case "$devname" in
        *ttyACM*)
            echo "Setup xmm interface $interface with port ${device}"
            devpath="$(readlink -f /sys/class/tty/$devname/device)"
            echo "Found path $devpath"
            hwaddr="$(ls -1 $devpath/../*/net/*/*address*)"
            for h in $hwaddr; do
                if [ "$(cat ${h})" = "00:00:11:12:13:14" ]; then
                    ifname=$(echo ${h} | awk -F [\/] '{print $(NF-1)}')
                fi
            done
            ;;
        esac
    }

    [ -n "$ifname" ] && {
        echo "Found interface $ifname"
    } || {
        echo "The interface could not be found."
        proto_notify_error "$interface" NO_IFACE
        proto_set_available "$interface" 0
        return 1
    }

    echo "Setting up $ifname"
	sleep 5
    [ -n "$username" ] && [ -n "$password" ] && {
        echo "Using auth type is: $auth"
        case $auth in
        pap) AUTH=1 ;;
        chap) AUTH=2 ;;
        *) AUTH=0 ;;
        esac
        AUTH=$AUTH 
        USER=$username 
        PASS=$password 

        runatcmd "$device" "AT+XGAUTH=1,$AUTH,\"$USER\",\"$PASS\"" >/dev/null 2>&1
    }
	
	OX=$(runatcmd "$device" "AT+CGACT=0,1")
	OX=$(runatcmd "$device" "AT+CGDCONT?;+CFUN?")
	
    pdp=$(echo $pdp | awk '{print toupper($0)}')
    [ "$pdp" = "IP" -o "$pdp" = "IPV6" -o "$pdp" = "IPV4V6" ] || pdp="IP"

	if `echo $OX | grep "+CGDCONT: 1,\"$pdp\",\"$apn\"," 1>/dev/null 2>&1`
	then
		if [ -z "$(echo $OX | grep -o "+CFUN: 1")" ]; then
			OX=$(runatcmd "$device" "AT+CFUN=1")
		fi
	else
		local ATCMDD="AT+CGDCONT=1,\"$pdp\",\"$apn\""
		OX=$(runatcmd "$device" "$ATCMDD")
		
		OX=$(runatcmd "$device" "AT+CFUN=4")
		OX=$(runatcmd "$device" "AT+CFUN=1")
		sleep 5
	fi
	
	OX=$(runatcmd "$device" "AT+CGPIAF=1,0,0,0;+XDNS=1,1;+XDNS=1,2")
	OX=$(runatcmd "$device" "AT+CGACT=1,1")
	
	local ERROR="ERROR"
	OX=$(runatcmd "$device" "AT+CGCONTRDP=1")
	if `echo "$OX" | grep -q "$ERROR"`; then
		echo "Failed to get IP information for context"
		proto_notify_error "$interface" CONFIGURE_FAILED
        return 1
	else
	    local DNS1 DNS2 ip ip6 OX6
	    OX=$(echo "${OX//[\" ]/}")
	    ip=$(echo $OX | cut -d, -f4 | grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}")
		ip=$(echo $ip | cut -d' ' -f1)
	    DNS1=$(echo $OX | cut -d, -f6)
		DNS2=$(echo $OX | cut -d, -f7)
		OX6=$(echo $OX | grep -o "+CGCONTRDP:1,[0-9]\+,[^,]\+,[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}.\+")
		ip6=$(echo $OX6 | grep -o "[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}")
		ip6=$(echo $ip6 | cut -d' ' -f1)
		
        echo "PDP type is: $pdp"
		echo "IP address(es): $ip $ip6"
		echo "DNS servers 1&2: $DNS1 $DNS2"

		if [[ $(echo "$ip6" | grep -o "^[23]") ]]; then
			# Global unicast IP acquired
			v6cap=1
		elif [[ $(echo "$ip6" | grep -o "^[0-9a-fA-F]\{1,4\}:") ]]; then
			# non-routable address
			v6cap=2
		else
			v6cap=0
		fi

		if [ -n "$ip6" -a -z "$ip" ]; then
			echo "Running IPv6-only mode"
			nat46=1
		fi

		OX=$(runatcmd "$device" "AT+XDATACHANNEL=1,1,\"/USBCDC/2\",\"/USBHS/NCM/0\",2,1")
		
        proto_init_update "$ifname" 1
        proto_add_data
        json_add_int reconnect 0
        proto_close_data

		proto_set_keep 1
        ip link set dev $ifname arp off
		proto_add_ipv4_address $ip 32
		proto_add_ipv4_route "0.0.0.0" 0 $ip
		
		if [ "$peerdns" = "0" ]; then
			echo "Using custom dns"
		else
			echo "Using default dns"
			proto_add_dns_server "$DNS1"
			proto_add_dns_server "$DNS2"
		fi

        proto_send_update "$interface"
		
		if [ "$v6cap" -gt 0 ]; then
		   ip -6 address add ${ip6}/64 dev $ifname
		   ip -6 route add default via "$ip6" dev "$ifname"
           json_init
           json_add_string name "${interface}_6"
           json_add_string ifname "@$interface"
           json_add_string proto "dhcpv6"
           json_add_string extendprefix 1
           proto_add_dynamic_defaults
           json_close_object
           ubus call network add_dynamic "$(json_dump)"
		fi
		
		OX=$(runatcmd "$device" "AT+CGDATA=\"M-RAW_IP\",1")
		local RESP=$(echo $OX | sed "s/AT+CGDATA=\"M-RAW_IP\",1 //")
		echo "Final Modem result code is \"$RESP\""

        echo "Starting monitor connection"
        proto_run_command "$interface" sh "$XMM_LIB_PATH/ip-monitor.sh" $interface $ifname
	fi
}

runatcmd(){
    local device opts
    device=$1
	export ATCMD=$2
    opts=$3
	gcom -d $device -s "$XMM_LIB_PATH/run-at.gcom" $opts
}

proto_xmm_teardown() {
    local interface="$1"
    local device
	json_get_vars device
	
    runatcmd "$device" "AT+CGACT=0" >/dev/null 2>&1
    runatcmd "$device" "AT+XDATACHANNEL=0" >/dev/null 2>&1
	
    echo "Modem $device disconnected"
    proto_kill_command "$interface"
}

[ -n "$INCLUDE_ONLY" ] || {
    add_protocol xmm
}
