#!/bin/bash
# Copyright (c) 2025 TriplePlay Network
# Contact: contato@tripleplay.network

if [ -z ${1} ] || [ -z ${2} ] ; then
	echo "You need to specify the IP address of zabbix server and hostname of your DNS Unbound on zabbix"
	exit 1
fi

# ZABBIX_SERVER IP
IP_ZABBIX=$1
# NAME Unbound on Zabbix
NAME_HOST=$2

# Get Server Stats
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
MEMORY_TOTAL=$(free -b | grep Mem | awk '{print $2}')
MEMORY_USED=$(free -b | grep Mem | awk '{print $3}')
MEMORY_FREE=$(free -b | grep Mem | awk '{print $4}')
DISK_USAGE=$(df -B1 / | grep / | awk '{print $3}')
DISK_FREE=$(df -B1 / | grep / | awk '{print $4}')
SYSTEM_UPTIME=$(awk '{print $1}' /proc/uptime)
LOAD_AVERAGE=$(cat /proc/loadavg | awk '{print $1}')
PROCESS_COUNT=$(ps aux | wc -l)
TCP_CONNECTIONS=$(netstat -ant | grep ESTABLISHED | wc -l)

# Send System Stats to Zabbix
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k cpu.usage -o ${CPU_USAGE}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k mem.total -o ${MEMORY_TOTAL}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k mem.usage -o ${MEMORY_USED}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k mem.free -o ${MEMORY_FREE}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k disk.usage -o ${DISK_USAGE}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k disk.free -o ${DISK_FREE}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k system.uptime -o ${SYSTEM_UPTIME}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k system.load -o ${LOAD_AVERAGE}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k system.processes -o ${PROCESS_COUNT}
zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k net.tcp.connections -o ${TCP_CONNECTIONS}

# Calculate memory usage percentage
if [ ! -z ${MEMORY_TOTAL} ] && [ ${MEMORY_TOTAL} -gt 0 ]; then
    MEMORY_USAGE_PCT=$(echo "scale=2; (${MEMORY_USED} * 100) / ${MEMORY_TOTAL}" | bc)
    zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k mem.usage.percent -o ${MEMORY_USAGE_PCT}
fi

# Check for network interfaces and collect statistics
for INTERFACE in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"); do
    # Get received and transmitted bytes
    RX_BYTES=$(cat /sys/class/net/${INTERFACE}/statistics/rx_bytes 2>/dev/null || echo 0)
    TX_BYTES=$(cat /sys/class/net/${INTERFACE}/statistics/tx_bytes 2>/dev/null || echo 0)
    
    # Send to Zabbix
    zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k net.if.in[${INTERFACE}] -o ${RX_BYTES}
    zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k net.if.out[${INTERFACE}] -o ${TX_BYTES}
done

# Check DNS protection status
if systemctl is-active --quiet dns-protection; then
    zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k dns.protection.active -o 1
else
    zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k dns.protection.active -o 0
fi

# Get Fail2ban statistics for DNS abuse
if command -v fail2ban-client &> /dev/null; then
    DNS_BANNED_IPS=$(fail2ban-client status dns-abuse 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo 0)
    zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k dns.banned.count -o ${DNS_BANNED_IPS}
fi