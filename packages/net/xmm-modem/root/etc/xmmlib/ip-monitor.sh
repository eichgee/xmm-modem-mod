#!/bin/sh

. ../netifd-proto.sh

interface=$1
ifname=$2

if_state=
dev_state=

monitor_pid=
loop_pid=

stopMonitor() {
    kill $monitor_pid >/dev/null 2>&1
    kill $loop_pid >/dev/null 2>&1
    rm -f $monitor_pipe
}

monitor_pipe="/tmp/xmm_monitor_$interface.$ifname.$$"
mkfifo $monitor_pipe
ip monitor dev $ifname link >$monitor_pipe &
monitor_pid=$!

while IFS= read -r line <$monitor_pipe; do
    dev_state=$(echo $line | grep -oE 'state [A-Z]+ ' | grep -oE '[A-Z]+')

    ubus_status=$(ubus call network.interface.$interface status)
    json_load "$ubus_status"
    json_get_var if_state up

    if [ "$if_state" = "1" ] && [ "$dev_state" = "DOWN" ]; then
        echo "$ifname ip link is down, restarting interface"

        proto_init_update "$ifname" 0
        proto_send_update "$interface"
        proto_kill_command "$interface"
        sleep 1
        ifup $interface

        break
    fi
done &
loop_pid=$!

trap stopMonitor SIGHUP SIGTERM SIGKILL SIGINT EXIT INT
wait $loop_pid
