#!/bin/bash
#
# advanced-monitoring-setup.sh - Configuração de monitoramento avançado para redes ISP com PPPoE
#
# Este script implementa análise gradativa com iptables e configura ferramentas 
# de monitoramento adicional para ISPs com muitos clientes PPPoE
#

# Verificar se está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script precisa ser executado como root"
    exit 1
fi

# Configuração da interface de rede
NETWORK_INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
MONITORING_DIR="/opt/dns-protection/monitoring"
DATA_DIR="$MONITORING_DIR/data"

# Criar diretórios
mkdir -p $MONITORING_DIR
mkdir -p $DATA_DIR

echo "=== Configurando monitoramento avançado para ISP com clientes PPPoE ==="

# 1. Configurar Análise Gradativa com iptables
echo "Configurando regras de análise gradativa com iptables..."

# Limpar regras anteriores relacionadas
iptables -F INPUT 2>/dev/null
iptables -F DNS_MONITORING 2>/dev/null
iptables -X DNS_MONITORING 2>/dev/null

# Criar nova chain para monitoramento
iptables -N DNS_MONITORING

# Adicionar regras de análise gradativa
echo "Adicionando regra de alerta para tráfego DNS acima de 1000 req/s..."
iptables -A DNS_MONITORING -p udp --dport 53 -m hashlimit \
    --hashlimit-name DNS_ALERT \
    --hashlimit-above 1000/sec \
    --hashlimit-burst 500 \
    --hashlimit-mode srcip \
    --hashlimit-htable-max 10000 \
    -j LOG --log-prefix "DNS_ALERT: " --log-level 4

# Adicionar regra para logging de ataques severos (acima de 2500 req/s)
echo "Adicionando regra de alerta para ataques severos acima de 2500 req/s..."
iptables -A DNS_MONITORING -p udp --dport 53 -m hashlimit \
    --hashlimit-name DNS_CRITICAL \
    --hashlimit-above 2500/sec \
    --hashlimit-burst 1000 \
    --hashlimit-mode srcip \
    --hashlimit-htable-max 10000 \
    -j LOG --log-prefix "DNS_CRITICAL: " --log-level 3

# Adicionar chain ao fluxo de INPUT
iptables -A INPUT -p udp --dport 53 -j DNS_MONITORING
iptables -A INPUT -p tcp --dport 53 -j DNS_MONITORING

# 2. Configurar coleta de dados para análise posterior
echo "Configurando ferramentas de monitoramento para coleta de dados inicial (48h)..."

# Configurar vnstat para monitoramento de tráfego (se instalado)
if command -v vnstat &> /dev/null; then
    vnstat -u -i $NETWORK_INTERFACE
    echo "* * * * * root vnstat -tr 30 --oneline | grep -v \"rx:0 tx:0\" >> $DATA_DIR/vnstat_peaks.log" > /etc/cron.d/dns_traffic_monitoring
    echo "Monitoramento vnstat configurado para registrar picos de tráfego"
else
    echo "AVISO: vnstat não encontrado. Considere instalar com 'apt install vnstat'"
fi

# Configurar atop para monitoramento de recursos (se instalado)
if command -v atop &> /dev/null; then
    echo "0 * * * * root atop -w $DATA_DIR/atop_hourly_\$(date +\%Y\%m\%d\%H).log 3600 1" > /etc/cron.d/dns_resource_monitoring
    echo "Monitoramento atop configurado para capturar dados a cada hora"
else
    echo "AVISO: atop não encontrado. Considere instalar com 'apt install atop'"
fi

# 3. Configurar captura de pacotes DNS para análise posterior
echo "Configurando captura periódica de tráfego DNS para análise..."

cat > /usr/local/bin/dns_capture.sh << 'EOF'
#!/bin/bash
CAPTURE_DIR="/opt/dns-protection/monitoring/data/captures"
NETWORK_INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
TIMESTAMP=$(date +%Y%m%d_%H%M)
mkdir -p $CAPTURE_DIR

# Captura 5 minutos de tráfego DNS (300 segundos)
tcpdump -i $NETWORK_INTERFACE port 53 -w $CAPTURE_DIR/dns_capture_$TIMESTAMP.pcap -G 300 -W 1
# Analisar com dnstop e salvar resultados
if command -v dnstop &> /dev/null; then
    dnstop -r $CAPTURE_DIR/dns_capture_$TIMESTAMP.pcap -w $CAPTURE_DIR/dns_analysis_$TIMESTAMP.txt
fi
EOF

chmod +x /usr/local/bin/dns_capture.sh

# Agendar captura diária nos horários de pico
echo "0 8,12,18,21 * * * root /usr/local/bin/dns_capture.sh" > /etc/cron.d/dns_capture

# 4. Configurar whitelist automática para redes internas
echo "Configurando whitelist automática para redes internas..."

if command -v fail2ban-client &> /dev/null; then
    # Adicionar redes privadas à whitelist do Fail2ban
    fail2ban-client set dns-abuse unbanip 127.0.0.1/8 2>/dev/null
    fail2ban-client set dns-abuse unbanip 10.0.0.0/8 2>/dev/null
    fail2ban-client set dns-abuse unbanip 172.16.0.0/12 2>/dev/null
    fail2ban-client set dns-abuse unbanip 192.168.0.0/16 2>/dev/null
    
    echo "Redes internas adicionadas à whitelist do Fail2ban"
else
    echo "AVISO: fail2ban-client não encontrado. Verifique a instalação do Fail2ban."
fi

# 5. Adicionar recomendação para CoA no RADIUS
echo -e "\nRECOMENDAÇÃO IMPORTANTE PARA PPOE:"
echo "Para implementar CoA (Change of Authorization) no RADIUS para desconectar"
echo "clientes maliciosos ao invés de apenas bloquear DNS, consulte a documentação"
echo "do seu servidor RADIUS (como FreeRADIUS) para integração com o Fail2ban."
echo "Exemplo para FreeRADIUS: https://wiki.freeradius.org/config/CoA"

# 6. Criar script para teste de carga
cat > /usr/local/bin/dns_load_test.sh << 'EOF'
#!/bin/bash
# Script para teste de carga do DNS
# Requer dnsperf (apt install dnsperf)

if ! command -v dnsperf &> /dev/null; then
    echo "dnsperf não encontrado. Instale com 'apt install dnsperf'"
    exit 1
fi

# Cria arquivo de queries para teste
QUERIES_FILE="/tmp/dns_queries.txt"
echo "Gerando queries para teste..."

for domain in google.com facebook.com amazon.com microsoft.com apple.com netflix.com twitter.com; do
    for i in {1..100}; do
        echo "test$i.$domain A" >> $QUERIES_FILE
    done
done

echo "Executando teste de carga..."
dnsperf -s 127.0.0.1 -d $QUERIES_FILE -c 100 -Q 1000 -l 30

echo "Para um teste mais intenso use:"
echo "dnsperf -s 127.0.0.1 -d $QUERIES_FILE -c 1000 -Q 5000 -l 60"
EOF

chmod +x /usr/local/bin/dns_load_test.sh

echo -e "\nConfiguração de monitoramento avançado concluída!"
echo -e "Para realizar um teste de carga no servidor DNS: /usr/local/bin/dns_load_test.sh"
echo -e "Whitelist automática configurada para redes internas"
echo -e "Monitoramento de picos de tráfego configurado"
echo -e "Captura periódica de tráfego DNS para análise configurada"

exit 0