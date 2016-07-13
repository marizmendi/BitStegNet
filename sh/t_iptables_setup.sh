#! /bin/sh
sudo iptables -F
sudo iptables -A OUTPUT -p udp --dport 9898 -j NFQUEUE --queue-num 0;
# sudo iptables -A OUTPUT -p tcp --dport 9898 -j DROP;