#!/bin/bash

IFACE="wifi_monitor"
OUT_HOST="10.42.0.1"
OUT_PORT="3456"

CHANNELS=(36 40 44 48 149 153 157 161)
#CHANNELS=(1 6 11)

# manual channel hopping
(
  while true; do
    for ch in "${CHANNELS[@]}"; do
      iw dev $IFACE set channel $ch
      sleep 1
    done
  done
) &

# Start capture and stream 
tcpdump -y IEEE802_11_RADIO -i $IFACE not wlan type mgt subtype beacon -U -w - | ./pcap_client $OUT_HOST $OUT_PORT
