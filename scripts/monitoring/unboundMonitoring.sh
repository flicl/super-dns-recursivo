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

# Get Unbound Statistics
UNBOUND_STATS=$(unbound-control stats)
TOTAL_QUERIES=$(echo "$UNBOUND_STATS" | grep "total.num.queries=" | cut -d= -f2)
CACHE_HITS=$(echo "$UNBOUND_STATS" | grep "total.num.cachehits=" | cut -d= -f2)
CACHE_MISSES=$(echo "$UNBOUND_STATS" | grep "total.num.cachemiss=" | cut -d= -f2)
QUERIES_TCP=$(echo "$UNBOUND_STATS" | grep "total.num.queries.tcp=" | cut -d= -f2)
QUERIES_UDP=$(echo "$UNBOUND_STATS" | grep "total.num.queries.udp=" | cut -d= -f2)
MEM_CACHE_SIZE=$(echo "$UNBOUND_STATS" | grep "mem.cache.rrset=" | cut -d= -f2)
MEM_TOTAL=$(echo "$UNBOUND_STATS" | grep "mem.total.sbrk=" | cut -d= -f2)
UPTIME=$(echo "$UNBOUND_STATS" | grep "time.up=" | cut -d= -f2)
RECURSION_TIME_AVG=$(echo "$UNBOUND_STATS" | grep "total.recursion.time.avg=" | cut -d= -f2)
QPS_CURRENT=$(echo "$UNBOUND_STATS" | grep "total.requestlist.current.all=" | cut -d= -f2)
QPS_AVG=$(echo "$UNBOUND_STATS" | grep "total.requestlist.avg=" | cut -d= -f2)

# Send to Zabbix
[ -z ${TOTAL_QUERIES} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.queries.total -o ${TOTAL_QUERIES}
[ -z ${CACHE_HITS} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.cache.hits -o ${CACHE_HITS}
[ -z ${CACHE_MISSES} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.cache.misses -o ${CACHE_MISSES}
[ -z ${QUERIES_TCP} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.queries.tcp -o ${QUERIES_TCP}
[ -z ${QUERIES_UDP} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.queries.udp -o ${QUERIES_UDP}
[ -z ${MEM_CACHE_SIZE} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.mem.cache -o ${MEM_CACHE_SIZE}
[ -z ${MEM_TOTAL} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.mem.total -o ${MEM_TOTAL}
[ -z ${UPTIME} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.uptime -o ${UPTIME}
[ -z ${RECURSION_TIME_AVG} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.recursion.time.avg -o ${RECURSION_TIME_AVG}
[ -z ${QPS_CURRENT} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.qps.current -o ${QPS_CURRENT}
[ -z ${QPS_AVG} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.qps.avg -o ${QPS_AVG}

# Calculate cache hit ratio
if [ ! -z ${TOTAL_QUERIES} ] && [ ! -z ${CACHE_HITS} ] && [ ${TOTAL_QUERIES} -gt 0 ]; then
    CACHE_HIT_RATIO=$(echo "scale=2; (${CACHE_HITS} * 100) / ${TOTAL_QUERIES}" | bc)
    zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k unbound.cache.hit.ratio -o ${CACHE_HIT_RATIO}
fi