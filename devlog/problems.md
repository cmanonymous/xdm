
# rhel-6.3 中，server 之间不能握手成功

可能是因为开启了防火墙，关闭之：

    # iptables -F
