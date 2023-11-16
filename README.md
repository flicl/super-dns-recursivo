# DNS Recursivo Unbound + Monitoramento

Neste repositório, você encontrará o passo a passo para a criação de um DNS Recursivo utilizando o Unbound e a realização do monitoramento utilizando o Zabbix com um painel detalhado no Grafana.

As versões utilizadas foram:

- Ubuntu 20.04 LTS
- Ubuntu 22.04 LTS
- Debian 10, 11 e 12

> Todas as versões foram testadas usando uma instalação limpa e o modo “container” do Proxmox.

## Instalação
O processo abaixo visa instalar o DNS, bem como ajustar o servidor para o envio de métricas de monitoramento para o Zabbix. Será utilizado o zabbix-sender no lugar do zabbix-agent, pois, caso seja utilizado o container de Proxmox, as coletas serão feitas do CT e não do PVE como um todo.

### Instalação - Unbound

```bash
#Atualizando as dependencias
sudo apt update && sudo apt upgrade -y

#Instalação das dependencias necessárias
sudo apt install unbound net-tools unbound-anchor wget dnsutils dnstop -y

#Parametrizando o Unbound
cd /etc/unbound
mv unbound.conf unbound.conf.bkp
nano unbound.conf

```
Cole o arquivo abaixo, editando de acordo com os comentários e sua realidade em relação aos prefixos.

```bash
# TriplePlay Network
#
# Unbound DNS Server V1.0
#


include: "/etc/unbound/unbound.conf.d/*.conf"

#Habilitar uso do unbound-control
remote-control:
  control-enable: yes

#Configuração do servidor
server:

#LOGS DE USO - Descomente apenas para debug

#  chroot: ""
#  logfile: /var/log/syslog.log
#  verbosity: 1
#  log-queries: yes

#Estatiticas de Uso para Monitoramento

  statistics-interval: 0
  extended-statistics: yes
  statistics-cumulative: no
  port: 53
  
#Lista de Interface - descomente caso queira usar Anycast
# ou adicione novas interfaces caso necessário

  interface: 0.0.0.0
  interface: ::0
#  interface: 8.8.8.8
#  interface: 8.8.4.4
  interface: 127.0.0.1
  interface: ::1

#Lista de IPs com acesso permitido nas consultas
# Adicone os IPs de seu provedor

  access-control: 127.0.0.1 allow
  access-control: ::1 allow

  access-control: 10.0.0.0/8 allow
  access-control: 100.64.0.0/10 allow
  access-control: 127.0.0.0/8 allow
  access-control: 172.16.0.0/12 allow
  access-control: 192.168.0.0/16 allow



# ==> Tunning
  #CPUs
  num-threads: 4

  #*-slabs = num-treads * 2

  msg-cache-slabs: 8
  rrset-cache-slabs: 8
  infra-cache-slabs: 8
  key-cache-slabs: 8

  #Aprimora pacotes udp com multithreading
  so-reuseport: yes

  #Conexoes por thread ~ 1024/cores - 50
  outgoing-range: 200
  
  #Aumenta cache rrset (resource records)
  #uso total ~ 384m * msg-cache = 1512m ou 1.5g

  rrset-cache-size: 256m
  msg-cache-size: 128m


  #Tempo (em segundos) para manter em cache
  cache-min-ttl: 3600
  cache-max-ttl: 10800

  #Aceitar requicao ipv4, ipv6, udp ou tcp
  #Se nao aceitar ipv6, entao a resolucao vai para ipv4

  do-ip4: yes
  do-ip6: yes
  do-tcp: yes
  do-udp: yes
  
  #Arquivo onde tem a lista de root servers
  root-hints: "/etc/unbound/named.cache"
  
  #Seguranca
  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-dnssec-stripped: yes

```

Ainda na pasta do Unbound, faça o download do arquivo de zonas raiz (root-zones).

``` bash
wget https://www.internic.net/domain/named.cache
```

> Caso esteja usando Ubuntu, desative o resolverdor nativo (systemd-resolved).
```bash
service systemd-resolved stop
systemctl disable systemd-resolved.service
```
Finalize as configurações do Unbound.
```bash
# Verifica se há algum erro no arquivo de configuração do unbound
unbound-checkconf

# Habilita o Unbound para inicar junto com o sistema
systemctl enable unbound
systemctl restart unbound

# Habilta o Unbound Control
unbound-control-setup

#Reinicia o Unbound e o unbound control
systemctl restart unbound
unbound-control reload
systemctl restart unbound
```

Após esse processo, faça o servidor consultar a si mesmo, alterando o ```/etc/resolv.conf``` e colocando ```nameserver 127.0.0.1``` e ```nameserver ::1```.

### Instalação - Monitoramento 
Neste processo, vamos instalar o zabbix-sender, configurar o cron para o envio de dados e adicionar os scripts de monitoramento.

> Caso esteja usando Ubuntu como container no proxmox faça o link do unbound-control.
```bash
ln -s /usr/sbin/unbound-control /usr/bin/unbound-control
```


```bash
#Atualizando as dependencias
sudo apt update && sudo apt upgrade -y

#Instalação das dependencias do Zabbix
## Ubuntu 20.04
wget https://repo.zabbix.com/zabbix/6.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.0-4+ubuntu20.04_all.deb
dpkg -i zabbix-release_6.0-4+ubuntu20.04_all.deb
apt update
apt install zabbix-sender

## Ubuntu 22.04
wget https://repo.zabbix.com/zabbix/6.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.0-4+ubuntu22.04_all.deb
dpkg -i zabbix-release_6.0-4+ubuntu22.04_all.deb
apt update
apt install zabbix-sender

## Debian 10
wget https://repo.zabbix.com/zabbix/6.0/debian/pool/main/z/zabbix-release/zabbix-release_6.0-4+debian10_all.deb
dpkg -i zabbix-release_6.0-4+debian10_all.deb
apt update
apt install zabbix-sender

## Debian 11
wget https://repo.zabbix.com/zabbix/6.0/debian/pool/main/z/zabbix-release/zabbix-release_6.0-4+debian11_all.deb
dpkg -i zabbix-release_6.0-4+debian11_all.deb
apt update
apt install zabbix-sender

## Debian 12
wget https://repo.zabbix.com/zabbix/6.0/debian/pool/main/z/zabbix-release/zabbix-release_6.0-5+debian12_all.deb
dpkg -i zabbix-release_6.0-5+debian12_all.deb
apt update
apt install zabbix-sender

```
Adicione os scripts de monitoramento.

> serverMonitoring.sh
```nano /etc/unbound/serverMonitoring.sh```
```bash
#!/bin/bash
#	Douglas Rodrigues
#	douglas.rodrigues@tripleplay.network

if [ -z ${1} ] || [ -z ${2} ] ; then
	echo "You need to specify the IP address of zabbix server and hostname of your DNS Unbound on zabbix"
	exit 1
fi

# ZABBIX_SERVER IP
IP_ZABBIX=$1
# NAME Unbound on Zabbix
NAME_HOST=$2

cpuUsage=$(top -bn1 | awk '/Cpu/ { print $2}')

memTotal=$(free -b | awk '/Mem/{print $2}')
memUsage=$(free -b | awk '/Mem/{print $3}')
memFree=$(free -b | awk '/Mem/{print $4}')


#	Sending info to zabbix_server, if variables is not empty!
[ -z ${cpuUsage} ] ||  zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k cpu.usage -o ${cpuUsage}

[ -z ${memTotal} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k mem.total -o ${memTotal}
[ -z ${memUsage} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k mem.usage -o ${memUsage}
[ -z ${memFree} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k mem.free -o ${memFree}

```
> unboundMonitoring.sh
```nano /etc/unbound/unboundMonitoring.sh```
```bash
#!/bin/bash
#	Douglas Rodrigues
#	douglas.rodrigues@tripleplay.network


if [ -z ${1} ] || [ -z ${2} ] ; then
	echo "You need to specify the IP address of zabbix server and hostname of your DNS Unbound on zabbix"
	exit 1
fi

# ZABBIX_SERVER IP
IP_ZABBIX=$1
# NAME Unbound on Zabbix
NAME_HOST=$2
DIR_TEMP=/var/tmp/
FILE="${DIR_TEMP}dump_unbound_control_stats.txt"
unbound-control stats > ${FILE}

TOTAL_NUM_QUERIES=$(cat ${FILE} | grep -w 'total.num.queries' | cut -d '=' -f2)
TOTAL_NUM_CACHEHITS=$(cat ${FILE} | grep -w 'total.num.cachehits' | cut -d '=' -f2)
TOTAL_NUM_CACHEMISS=$(cat ${FILE} | grep -w 'total.num.cachemiss' | cut -d '=' -f2)
TOTAL_NUM_PREFETCH=$(cat ${FILE} | grep -w 'total.num.prefetch' | cut -d '=' -f2)
TOTAL_NUM_RECURSIVEREPLIES=$(cat ${FILE} | grep -w 'total.num.recursivereplies' | cut -d '=' -f2)

TOTAL_REQ_MAX=$(cat ${FILE} | grep -w 'total.requestlist.max' | cut -d '=' -f2)
TOTAL_REQ_AVG=$(cat ${FILE} | grep -w 'total.requestlist.avg' | cut -d '=' -f2)
TOTAL_REQ_OVERWRITTEN=$(cat ${FILE} | grep -w 'total.requestlist.overwritten' | cut -d '=' -f2)
TOTAL_REQ_EXCEEDED=$(cat ${FILE} | grep -w 'total.requestlist.exceeded' | cut -d '=' -f2)
TOTAL_REQ_CURRENT_ALL=$(cat ${FILE} | grep -w 'total.requestlist.current.all' | cut -d '=' -f2)
TOTAL_REQ_CURRENT_USER=$(cat ${FILE} | grep -w 'total.requestlist.current.user' | cut -d '=' -f2)

MED_RECURSION_TIME=$(cat ${FILE} | grep -w 'total.recursion.time.avg' | cut -d '=' -f2)

TOTAL_TCPUSAGE=$(cat ${FILE} | grep -w 'total.tcpusage' | cut -d '=' -f2)

NUM_QUERY_TYPE_A=$(cat ${FILE} | grep -w 'num.query.type.A' | cut -d '=' -f2)
NUM_QUERY_TYPE_NS=$(cat ${FILE} | grep -w 'num.query.type.NS' | cut -d '=' -f2)
NUM_QUERY_TYPE_MX=$(cat ${FILE} | grep -w 'num.query.type.MX' | cut -d '=' -f2)
NUM_QUERY_TYPE_TXT=$(cat ${FILE} | grep -w 'num.query.type.TXT' | cut -d '=' -f2)
NUM_QUERY_TYPE_PTR=$(cat ${FILE} | grep -w 'num.query.type.PTR' | cut -d '=' -f2)
NUM_QUERY_TYPE_AAAA=$(cat ${FILE} | grep -w 'num.query.type.AAAA' | cut -d '=' -f2)
NUM_QUERY_TYPE_SRV=$(cat ${FILE} | grep -w 'num.query.type.SRV' | cut -d '=' -f2)
NUM_QUERY_TYPE_SOA=$(cat ${FILE} | grep -w 'num.query.type.SOA' | cut -d '=' -f2)

NUM_ANSWER_RCODE_NOERROR=$(cat ${FILE} | grep -w 'num.answer.rcode.NOERROR' | cut -d '=' -f2)
NUM_ANSWER_RCODE_NXDOMAIN=$(cat ${FILE} | grep -w 'num.answer.rcode.NXDOMAIN' | cut -d '=' -f2)
NUM_ANSWER_RCODE_SERVFAIL=$(cat ${FILE} | grep -w 'num.answer.rcode.SERVFAIL' | cut -d '=' -f2)
NUM_ANSWER_RCODE_REFUSED=$(cat ${FILE} | grep -w 'num.answer.rcode.REFUSED' | cut -d '=' -f2)
NUM_ANSWER_RCODE_nodata=$(cat ${FILE} | grep -w 'num.answer.rcode.nodata' | cut -d '=' -f2)
NUM_ANSWER_secure=$(cat ${FILE} | grep -w 'num.answer.secure' | cut -d '=' -f2)

#	Sending info to zabbix_server, if variables is not empty!
[ -z ${TOTAL_NUM_QUERIES} ] ||  zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.num.queries -o ${TOTAL_NUM_QUERIES}
[ -z ${TOTAL_NUM_CACHEHITS} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.num.cachehits -o ${TOTAL_NUM_CACHEHITS}
[ -z ${TOTAL_NUM_CACHEMISS} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.num.cachemiss -o ${TOTAL_NUM_CACHEMISS}
[ -z ${TOTAL_NUM_PREFETCH} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.num.prefetch -o ${TOTAL_NUM_PREFETCH}
[ -z ${TOTAL_NUM_RECURSIVEREPLIES} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.num.recursivereplies -o ${TOTAL_NUM_RECURSIVEREPLIES}

[ -z ${TOTAL_REQ_MAX} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.requestlist.max -o ${TOTAL_REQ_MAX}
[ -z ${TOTAL_REQ_AVG} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.requestlist.avg -o ${TOTAL_REQ_AVG}
[ -z ${TOTAL_REQ_OVERWRITTEN} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.requestlist.overwritten -o ${TOTAL_REQ_OVERWRITTEN}
[ -z ${TOTAL_REQ_EXCEEDED} ] ||  zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.requestlist.exceeded -o ${TOTAL_REQ_EXCEEDED}
[ -z ${TOTAL_REQ_CURRENT_ALL} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.requestlist.current.all -o ${TOTAL_REQ_CURRENT_ALL}
[ -z ${TOTAL_REQ_CURRENT_USER} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.requestlist.current.user -o ${TOTAL_REQ_CURRENT_USER}

[ -z ${MED_RECURSION_TIME} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k avg.recursion.time -o ${MED_RECURSION_TIME}

[ -z ${TOTAL_TCPUSAGE} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k total.tcpusage -o ${TOTAL_TCPUSAGE}

[ -z ${NUM_QUERY_TYPE_A} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.a -o ${NUM_QUERY_TYPE_A}
[ -z ${NUM_QUERY_TYPE_NS} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.ns -o ${NUM_QUERY_TYPE_NS}
[ -z ${NUM_QUERY_TYPE_MX} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.mx -o ${NUM_QUERY_TYPE_MX}
[ -z ${NUM_QUERY_TYPE_TXT} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.txt -o ${NUM_QUERY_TYPE_TXT}
[ -z ${NUM_QUERY_TYPE_PTR} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.ptr -o ${NUM_QUERY_TYPE_PTR}
[ -z ${NUM_QUERY_TYPE_AAAA} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.aaaa -o ${NUM_QUERY_TYPE_AAAA}
[ -z ${NUM_QUERY_TYPE_SRV} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.srv -o ${NUM_QUERY_TYPE_SRV}
[ -z ${NUM_QUERY_TYPE_SOA} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.query.soa -o ${NUM_QUERY_TYPE_SOA}

[ -z ${NUM_ANSWER_RCODE_NOERROR} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.answer.rcode.NOERROR -o ${NUM_ANSWER_RCODE_NOERROR}
[ -z ${NUM_ANSWER_RCODE_NXDOMAIN} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.answer.rcode.NXDOMAIN -o ${NUM_ANSWER_RCODE_NXDOMAIN}
[ -z ${NUM_ANSWER_RCODE_SERVFAIL} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.answer.rcode.SERVFAIL -o ${NUM_ANSWER_RCODE_SERVFAIL}
[ -z ${NUM_ANSWER_RCODE_REFUSED} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.answer.rcode.REFUSED -o ${NUM_ANSWER_RCODE_REFUSED}
[ -z ${NUM_ANSWER_RCODE_nodata} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.answer.rcode.nodata -o ${NUM_ANSWER_RCODE_nodata}
[ -z ${NUM_ANSWER_secure} ] || zabbix_sender -z ${IP_ZABBIX} -s ${NAME_HOST} -k num.answer.secure -o ${NUM_ANSWER_secure}

```



