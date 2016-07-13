#! /bin/sh
sudo iptables -F
sudo iptables -A INPUT -p udp --dport 9898 -j NFQUEUE --queue-num 1;
# sudo iptables -A INPUT -p tcp --dport 9898 -j DROP;
