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
    proto_config_add_string "username"
    proto_config_add_string "password"
    proto_config_add_string "auth"
    proto_config_add_int "delay"
    proto_config_add_int "cid"
    proto_config_add_boolean "autorc"
    proto_config_add_int "mtu"
    proto_config_add_boolean "synctime"
    proto_config_add_defaults
}

proto_xmm_setup() {
    local interface="$1"
    local OX device ifname auth username password apn pdp delay cid autorc mtu synctime $PROTO_DEFAULT_OPTIONS
    json_get_vars device ifname auth username password apn pdp delay cid autorc mtu synctime $PROTO_DEFAULT_OPTIONS

    [ "$metric" = "" ] && metric="0"
    [ "$cid" = "" ] && cid="1"
    [ "$autorc" = "" ] && autorc="1"
    [ "$apn" = "" ] && apn="internet"
    [ "$delay" = "" ] && delay="5"
    [ "$mtu" = "" ] && mtu="1500"
    [ "$synctime" = "" ] && synctime="1"
    [ "$peerdns" = "" ] && peerdns="1"

    [ -z "$ifname" ] && {
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
                    ifname=$(echo ${h} | awk -F '[\/]' '{print $(NF-1)}')
                fi
            done
            ;;
        esac
    }

    if [ -n "$ifname" ]; then
        echo "Found device $ifname"
    else
        echo "Could not get device from port $device"
        proto_notify_error "$interface" DEVICE_NOT_FOUND
        proto_set_available "$interface" 0
        return 1
    fi

    echo "Setting up $ifname"

    [ -n "$delay" ] && [ "$delay" -gt 0 ] && sleep "$delay"

    [ -n "$auth" ] && {
        echo "Using auth type: $auth"
        case $auth in
        pap) AUTH=1 ;;
        chap) AUTH=2 ;;
        *) AUTH=0 ;;
        esac

        USER=$username
        PASS=$password

        OX=$(runatcmd "$device" "AT+XGAUTH=$cid,$AUTH,\"$USER\",\"$PASS\"")
    }

    OX=$(runatcmd "$device" "AT+CGACT=0,$cid")
    OX=$(runatcmd "$device" "AT+CGDCONT?;+CFUN?")

    pdp=$(echo $pdp | awk '{print toupper($0)}')
    [ "$pdp" = "IP" ] || [ "$pdp" = "IPV6" ] || [ "$pdp" = "IPV4V6" ] || pdp="IP"

    if echo $OX | grep "+CGDCONT: $cid,\"$pdp\",\"$apn\"," 1>/dev/null 2>&1; then
        if [ -z "$(echo $OX | grep -o "+CFUN: 1")" ]; then
            OX=$(runatcmd "$device" "AT+CFUN=1")
        fi
    else
        OX=$(runatcmd "$device" "AT+CGDCONT=$cid,\"$pdp\",\"$apn\"")

        OX=$(runatcmd "$device" "AT+CFUN=4")
        OX=$(runatcmd "$device" "AT+CFUN=1")
        sleep 5
    fi

    OX=$(runatcmd "$device" "AT+CGPIAF=1,0,0,0;+XDNS=$cid,1;+XDNS=$cid,2")
    OX=$(runatcmd "$device" "AT+CGACT=1,$cid")

    local ERROR="ERROR"
    OX=$(runatcmd "$device" "AT+CGCONTRDP=$cid")
    if echo "$OX" | grep -q "$ERROR"; then
        echo "Failed to get IP information for context $cid"
        proto_notify_error "$interface" CONFIGURE_FAILED
        return 1
    else
        local DNS1 DNS2 ip ip6 OX6 v6cap RESP
        OX=$(echo "${OX//[\" ]/}")
        ip=$(echo $OX | cut -d, -f4 | grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}")
        ip=$(echo $ip | cut -d' ' -f1)
        DNS1=$(echo $OX | cut -d, -f6)
        DNS2=$(echo $OX | cut -d, -f7)
        OX6=$(echo $OX | grep -o "+CGCONTRDP:$cid,[0-9]\+,[^,]\+,[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}.\+")
        ip6=$(echo $OX6 | grep -o "[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}:[0-9A-F]\{1,4\}")
        ip6=$(echo $ip6 | cut -d' ' -f1)

        echo "PDP type is: $pdp"

        if [[ $(echo "$ip6" | grep -o "^[23]") ]]; then
            # Global unicast IP acquired
            v6cap=1
        elif [[ $(echo "$ip6" | grep -o "^[0-9a-fA-F]\{1,4\}:") ]]; then
            # non-routable address
            v6cap=2
        else
            v6cap=0
        fi

        OX=$(runatcmd "$device" "AT+XDATACHANNEL=1,1,\"/USBCDC/2\",\"/USBHS/NCM/0\",2,$cid")

        [ -n "$mtu" ] && ip link set dev "$ifname" mtu "$mtu"
        ip link set dev $ifname arp off

        [ "$pdp" = "IP" ] || [ "$pdp" = "IPV4V6" ] &&
            setup_ipv4_static "$interface" "$ifname" "$ip" "$DNS1" "$DNS2" "$defaultroute" "$metric" "$peerdns"

        [ "$pdp" = "IPV6" ] || [ "$pdp" = "IPV4V6" ] && [ "$v6cap" -gt 0 ] &&
            setup_ipv6_dhcp "$interface" "$ifname" "$metric"

        OX=$(runatcmd "$device" "AT+CGDATA=\"M-RAW_IP\",$cid")
        RESP=$(echo $OX | sed "s/AT+CGDATA=\"M-RAW_IP\",$cid //")
        echo "Final Modem result code is \"$RESP\""

        [ "$synctime" = "1" ] && update_system_time_from_modem "$device"

        [ "$autorc" = "1" ] && {
            echo "Starting connection monitor"
            proto_run_command "$interface" sh "$XMM_LIB_PATH/ip-monitor.sh" "$interface" "$ifname"
        }
    fi
}

setup_ipv4_static() {
    local interface="$1"
    local ifname="$2"
    local ip="$3"
    local DNS1="$4"
    local DNS2="$5"
    local defaultroute="$6"
    local metric="$7"
    local peerdns="$8"

    proto_init_update "$ifname" 1

    proto_set_keep 1

    echo "Set IPV4 address to $ip"
    proto_add_ipv4_address "$ip" 32

    [ "$defaultroute" = "" ] || [ "$defaultroute" = "1" ] &&
        proto_add_ipv4_route "0.0.0.0" 0 "$ip"

    if [ "$peerdns" = "1" ]; then
        [ -n "$DNS1" ] && {
            proto_add_dns_server "$DNS1"
            echo "Adding IPV4 dns address $DNS1"
        }

        [ -n "$DNS2" ] && {
            proto_add_dns_server "$DNS2"
            echo "Adding IPV4 dns address $DNS2"
        }
    fi

    [ -n "$metric" ] && json_add_int metric "$metric"

    proto_send_update "$interface"
}

setup_ipv6_dhcp() {
    local interface="$1"
    local ifname="$2"
    local metric="$3"
    local zone

    echo "Configure IPV6 dhcp address"

    zone="$(fw3 -q network "$interface" 2>/dev/null)"
    json_init
    json_add_string name "${interface}_6"
    json_add_string ifname "@$interface"
    json_add_string proto "dhcpv6"
    json_add_string extendprefix 1
    [ -n "$zone" ] && json_add_string zone "$zone"
    [ -n "$metric" ] && json_add_int metric "$metric"
    # json_add_string iface_464xlat 0
    proto_add_dynamic_defaults
    json_close_object
    ubus call network add_dynamic "$(json_dump)"
}

runatcmd() {
    local device="$1"
    export ATCMD="$2"
    gcom -d $device -s "$XMM_LIB_PATH/run-at.gcom"
}

update_system_time_from_modem() {
    local OX network_time device
    device=$1

    runatcmd "$device" "AT+CTZU=1" >/dev/null 2>&1
    OX=$(runatcmd "$device" "AT+CCLK?")
    if echo "$OX" | grep -q "ERROR"; then
        echo "Unable to get network time"
    else
        network_time=$(echo "$OX" | sed -n 's/.*"\(.*\)".*/\1/p')
        echo "Updating system time with value: $network_time"
        OX=$(date -D '%y/%m/%d,%H:%M:%S' -s "$network_time")
    fi
}

proto_xmm_teardown() {
    local interface="$1"
    local device OX
    json_get_vars device

    runatcmd "$device" "AT+CGACT=0" >/dev/null 2>&1
    runatcmd "$device" "AT+XDATACHANNEL=0" >/dev/null 2>&1
    echo "Modem $device disconnected"
    proto_kill_command "$interface"
}

[ -n "$INCLUDE_ONLY" ] || {
    add_protocol xmm
}
