#!/bin/sh

tc qdisc del dev eth0 root

tc qdisc  add dev eth0 root handle 1:0 htb default 11
tc class  add dev eth0 parent 1: classid 1:11 htb rate 1mbit ceil 2mbit
#tc class  add dev eth0 parent 1: classid 1:11 htb rate 1mbit ceil 2mbit
#tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dport 2022 0xffff flowid 1:11
#tc filter add dev eth0 protocol ip parent 1:0 prio 2 u32 match ip dport 8081 0xffff flowid 1:11

tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dport 9999 0xffff flowid 1:11
tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dport 9998 0xffff flowid 1:11
