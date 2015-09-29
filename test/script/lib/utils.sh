#!/usr/bin/env bash
set -e

BASE_DIR="/opt/hadm"

HADMCMD="${BASE_DIR}/bin/hadmctl"
test -x "$HADMCMD" || exit 1

USER="root"
LIB_PATH="${PWD}/utils.sh"
KMOD="${BASE_DIR}/kmod/hadm_kmod.ko"
SERVER="${BASE_DIR}/bin/hadm_main"
SERVER_PORT="9998"

NODE_LOCAL_IP=""
NODE_PEER_IP="192.168.122.230"
NODE_STATE_LINES="15"

check_server() {
    test -n "$(netstat -tunlp | grep $SERVER_PORT)"
}

do_server() {
    local server_pid="$(ps aux | grep [h]adm_main | awk '{print $2}')"

    case "${1:-''}" in
        "up" )
        if [ -n "$server_pid" ]; then
            do_server down
        fi
        $SERVER &
        ;;
        "down" )
        if [ -n "$server_pid" ]; then
            kill -SIGKILL $server_pid
        fi
        ;;
        *)
        echo "usage: do_server up|down" 2>&1
        return 1
        ;;
    esac
}

check_kmod() {
    test -n "$(lsmod | grep hadm_kmod)"
}

do_kmod() {
    case "$1" in
        "up" )
        do_kmod down && { insmod $KMOD || return 1; }
        ;;
        "down" )
        check_kmod && { rmmod $KMOD || return 1; }
        ;;
        *)
        echo "usage: do_kmod up|down" 2>&1
        return 1
        ;;
    esac

    return 0
}

do_init() {
        $HADMCMD init hadm0 >&/dev/null
}

check_status() {
    $HADMCMD status hadm0 >&/dev/null
}

get_status() {
    check_status || { echo "get status error."; return 1; }
    local state_filter
    case "${1:-all}" in
        "node_local" )
        state_filter="\[91m"
        ;;
        "node_peer" )
        state_filter="^[[:space:]]*Node ID"
        ;;
        #"[0-32]")
        # ;;TODO
        "all")
        state_filter=""
        ;;
        * )
        echo "usage: get_status [node_local|node_peer|all(default)] " >&2
        exit 1
        ;;
    esac
    $HADMCMD status hadm0 2>&1 | grep -A $NODE_STATE_LINES "$state_filter"
}

check_config() {
    check_status
}

do_config() {
    check_status >&/dev/null || $HADMCMD config &> /dev/null
}

check_res() {
    case "${1:-}" in
        "node_local" | "" | "node_peer"  )
        local stat="$(get_status $1)"
        test -z "$(get_status $1 | grep down)"
        ;;
        * )
        echo "usage: check_res [ node_local | node_peer]" >&2
        exit 1
        ;;
    esac
}

do_res() {
    case "$1" in
        "up" )
        check_res node_local || $HADMCMD up hadm0
        ;;
        "down" )
        check_res node_local && $HADMCMD down hadm0
        ;;
        *)
        echo "do_res up|down" 2>&1
        exit 1
        ;;
    esac
}

check_hatest() {
    check_server && check_kmod
}

__do_hatest() {
    case "$1" in
        "up" | "down" )
        do_init >& /dev/null || $(true)
        do_server $1
        do_kmod $1
        if [ "$1" = "up" ]; then
            do_config
            do_res $1
        fi
        ;;
        *)
        return 1;
        ;;
    esac
}

do_hatest() {
    case "$1" in
        "up" | "down" )
        case "${2:-}" in
            "node_local" )
            __do_hatest $1
            ;;
            "node_peer" )
<<<<<<< HEAD
            exe_on_remote "__do_hatest $1" >&/dev/null
=======
            exe_on_remote "__do_hatest $1"
>>>>>>> sync_remote_buffer
            ;;
            "")
            __do_hatest $1
            ;;
            * )
            echo "do_hatest [up|down] [node_local|node_peer]" >&2
            exit 1
            ;;
        esac
        ;;
        * )
        echo "do_hatest [up|down] [node_local|node_peer]" >&2
        exit 1;
    esac
}

check_role() {
    case "${1:-}" in
        "node_local" | "" | "node_peer"  )
        test -z "$(get_status $1 | grep secondary)"
        ;;
        * )
        echo "usage: check_role [ node_local | node_peer]" >&2
        exit 2
        ;;
    esac
}

do_role() {
    case "$1" in
        "primary" )
        $HADMCMD primary hadm0
        ;;
        "secondary" )
        $HADMCMD secondary hadm0
        ;;
        * )
        echo "usage: do_role primary|secondary"
        return 1
        ;;
    esac
}

check_connect() {
    case "${1:-}" in
        "node_local" | "" | "node_peer"  )
        test -z "$(get_status $1 | grep disconnect)"
        ;;
        * )
        echo "usage: check_connect [ node_local | node_peer]" >&2
        exit 1
        ;;
    esac
}

wait_peer_connect() {
    for i in $(seq 1 ${1:-15}); do
        if check_connect node_peer; then
            echo "peer node connect!"
            return 0
        fi
        sleep 3
    done
    return 1
}

<<<<<<< HEAD
get_srl_disk() {
	local status
	case "${1:-}" in
		"node_local" | "" | "node_peer"  )
		echo $(get_status $1 | awk -F: '/Srl device/{print $2}')
		;;
		* )
		echo "usage: get_srl_size [ node_local | node_peer]" >&2
		return 1
		;;
	esac
}

=======
>>>>>>> sync_remote_buffer
get_srl_size() {
    local status
    case "${1:-}" in
        "node_local" | "" | "node_peer"  )
        echo $(get_status $1 | awk -F: '/srl_size/{print $2}')
        ;;
        * )
        echo "usage: get_srl_size [ node_local | node_peer]" >&2
        return 1
        ;;
    esac
}

wait_srl_finish() {
    local srl_size i last
    while true
    do
        local srl_size=$(get_srl_size)
        for i in $srl_size
        do
            if [ "$i" != "0" ]; then
                #echo "srl translating... remain $i"
                if [ "$i" = "$last" ]
                then
                    echo "warning srl size remain the same."
                    check_up node_peer || { echo "secondary device down" && exit -1; }
                    check_connect node_peer || { echo "secondary disconnect" && exit -1; }
                fi
                last=$i
                sleep 5
                break
            fi
            echo "srl translate finish."
            return 0
        done
    done
}

exe_on_remote() {
        ssh -T -l $USER $NODE_PEER_IP << EOF
        test -f "$LIB_PATH" && source "$LIB_PATH" || echo "exe lib not find in peer node"
<<<<<<< HEAD
        $*
=======
        $* >&/dev/null
>>>>>>> sync_remote_buffer
EOF
}

log_error() {
        echo "error: $1"
        return ${2:-1}
}
