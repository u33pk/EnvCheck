#!/bin/sh
# 允许本机发起 DNS 查询（出站）
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# 允许 DNS 响应返回（入站）
iptables -A INPUT -p udp --sport 53 -j ACCEPT
# 禁止所有其他 UDP 流量
iptables -A INPUT -p udp -j DROP
iptables -A OUTPUT -p udp -j DROP
iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.1 -m owner --uid-owner 1000:10999 -j DNAT --to-destination 127.0.0.1:16666
echo "UDP disable, but DNS enable, and TCP enable"
cat > /data/app/red.conf << 'EOF'
base {
    log_debug = off;
    log_info = off;
    log = stderr;
    daemon = on;
    redirector = iptables;
}
redsocks {
    bind = "127.0.0.1:16666";
    relay = "192.168.31.68:10808";
    type = socks5;
    autoproxy = 0;
    timeout = 13;
}
EOF
/data/local/tmp/redsocks2 -c /data/app/red.conf