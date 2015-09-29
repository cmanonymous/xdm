#!/usr/bin/env bash
#
# test case 1: regular test for srl synchronize
#

set -e

# load utils lib
LIB_PATH="/hadm_test/case1/hadm_test/lib/utils.sh"

test -r "$LIB_PATH" && source "$LIB_PATH"

# up local_node & peer_node
echo " up local_node & peer_node"
do_hatest up node_local || log_error "up local hadm failed." $?
do_hatest up node_peer  || log_error "up peer hadm failed." $?

# change local node role to primary
echo " change local node role to primary"
do_role primary || log_error "change local node role to primary failed." $?

# wait for peer node connect. default timeout 45s
echo " wait for peer node connect. default timeout 45s"
wait_peer_connect || log_error "wait for peer node connect timeout."

# write some content to local disk
echo " write some content to local disk"
$(dd if=/dev/urandom of=/dev/hadm0 bs=1M count=8 >&/dev/null)

# wait for srl translate finish
echo " wait for srl translate finish"
wait_srl_finish

# check result
echo "test case1 finish, check result for yourslef."
