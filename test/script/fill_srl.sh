#!/usr/bin/env bash
set -e

. ./lib/utils.sh

PEER_NODE="192.168.122.230"
disk_name="/dev/sdb"
peer_srl_info=`ssh $PEER_NODE hadmctl dump hadm0 | awk -F[=,] '/local_primary/{print $2,$4,$6}'`
peer_disk_name=`echo $(exe_on_remote "get_status node_peer") | sed 's/^.*Srl device : //; s/ Srl disk.*$//'`

/opt/bin/fill $disk_name $peer_srl_info
