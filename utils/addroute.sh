#!/bin/sh -x

# A simple script handling default routing for GoVPN,
# inspired by vpnc-script, but much simpler.

# List of parameters passed through environment
# - reason               -- why this script is called:
#                           pre-init, connect, disconnect
# - VPNGATEWAY           -- public address of vpn gateway
# - TAPDEV               -- tap device
# - INTERNAL_IP4_ADDRESS -- e.g. 172.0.0.2/24
# - INTERNAL_IP4_GATEWAY -- e.g. 172.0.0.1


set_up_dev() {
  ip tuntap add dev $TAPDEV mode tap
}


tear_down_dev() {
  ip tuntap del dev $TAPDEV mode tap
}


do_connect() {
  local OLDGW=$(ip route show 0/0 | sed 's/^default//')
  ip link set dev $TAPDEV up
  ip addr add $INTERNAL_IP4_ADDRESS dev $TAPDEV
  ip route add $VPNGATEWAY $OLDGW
  ip route add 0/1 via $INTERNAL_IP4_GATEWAY dev $TAPDEV
  ip route add 128/1 via $INTERNAL_IP4_GATEWAY dev $TAPDEV
}


do_disconnect() {
  ip route del $VPNGATEWAY
}


case $reason in
  pre-init)
    set_up_dev
    ;;
  connect)
    do_connect
    ;;
  disconnect)
    do_disconnect
    ;;
esac
