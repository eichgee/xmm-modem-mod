#!/bin/sh

. /lib/functions.sh
. ../netifd-proto.sh

interface=$1
ifname=$2
 
if_state=
dev_state=
con_state=

stopMonitor() {
    local pid=$((LAST_PID - 1))
    kill $LAST_PID > /dev/null 2>&1
    kill $pid > /dev/null 2>&1
}

while IFS= read -r line; do
    ubus_status=$(ubus call network.interface.$interface status)
    if_state=$(echo $ubus_status | jsonfilter -q -e '@.up')
    dev_state=$(echo $line | grep -oE 'state [A-Z]+ ' | grep -oE '[A-Z]+')

    if [ "$if_state" = "true" ] && [ "$dev_state" = "DOWN" ]; then
        con_state=$(echo $ubus_status | jsonfilter -e '@.data.reconnect')
        # handling ip lost
        if [ "$con_state" -eq "0" ]; then
            proto_init_update "$ifname" 1
            proto_add_data
            json_add_int reconnect 1
            proto_close_data
            proto_send_update "$interface"

            echo "$ifname ip link is down, restarting interface"

            ifdown $interface
            ifup $interface

            break
        fi
    fi
done < <(ip monitor dev $ifname link) &
LAST_PID=$!

trap stopMonitor SIGHUP SIGTERM SIGKILL SIGINT EXIT INT
wait $LAST_PID
