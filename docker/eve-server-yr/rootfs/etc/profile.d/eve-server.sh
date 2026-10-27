# shellcheck shell=sh
# Login banner for interactive shells.
export ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections
case $- in *i*)
  printf '\n eve-server-yr  %s  %s\n' "$(hostname)" "$(ip -4 -br addr show scope global 2>/dev/null | awk '{print $1"="$3}' | xargs)"
  printf ' services: svc list    tools: nmap ncat nc socat hping3 iperf3 tcpdump tshark tcpreplay\n'
  printf '           mtr fping arping dig curl ab ansible scapy netmiko    http: /health /whoami /files/\n\n'
;; esac
