#!/bin/bash
#
# dns-metrics-exporter.sh - Exporta métricas do monitoramento DNS para sistemas de monitoramento
#
# Este script coleta métricas do sistema DNS e as formata para integração com 
# Zabbix, Grafana/Prometheus ou outros sistemas de monitoramento
#

# Configurações
METRICS_DIR="/opt/dns-protection/metrics"
CONFIG_DIR="/opt/dns-protection/config"
CONFIG_FILE="$CONFIG_DIR/dns-monitor.conf"
NETWORK_INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
DNS_PORT="port 53"
METRICS_INTERVAL=60  # Coleta de métricas a cada 60 segundos
ZABBIX_SENDER=$(which zabbix_sender 2>/dev/null)
ZABBIX_CONFIG="/etc/zabbix/zabbix_agentd.conf"
PROMETHEUS_DIR="$METRICS_DIR/prometheus"
PROMETHEUS_FILE="$PROMETHEUS_DIR/dns_metrics.prom"

# Criar diretórios necessários
mkdir -p $METRICS_DIR
mkdir -p $PROMETHEUS_DIR

# Verificar se está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script precisa ser executado como root"
    exit 1
fi

# Carregar configurações
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Arquivo de configuração $CONFIG_FILE não encontrado."
    exit 1
fi

# Função para exibir mensagens de ajuda
show_help() {
    echo "Uso: $0 [OPÇÕES]"
    echo
    echo "Opções:"
    echo "  --zabbix       Envia métricas para servidor Zabbix"
    echo "  --prometheus   Gera arquivo de métricas para Prometheus"
    echo "  --grafana      Gera dados para visualização direta no Grafana"
    echo "  --once         Executa uma única vez e sai"
    echo "  --help         Exibe esta mensagem de ajuda"
    echo
    echo "Sem opções, o script executa no modo padrão (Prometheus)."
    exit 0
}

# Variáveis para controle de fluxo
ZABBIX_MODE=false
PROMETHEUS_MODE=true  # Padrão
GRAFANA_MODE=false
RUN_ONCE=false

# Processar argumentos da linha de comando
for arg in "$@"; do
    case $arg in
        --zabbix)
            ZABBIX_MODE=true
            PROMETHEUS_MODE=false
            ;;
        --prometheus)
            PROMETHEUS_MODE=true
            ZABBIX_MODE=false
            GRAFANA_MODE=false
            ;;
        --grafana)
            GRAFANA_MODE=true
            PROMETHEUS_MODE=false
            ZABBIX_MODE=false
            ;;
        --once)
            RUN_ONCE=true
            ;;
        --help)
            show_help
            ;;
    esac
done

# Função para coletar métricas de DNS
collect_dns_metrics() {
    local output_file="/tmp/dns_metrics_raw.txt"
    local temp_dir="/tmp/dns_metrics"
    
    mkdir -p $temp_dir
    
    # Timestamp para as métricas
    local timestamp=$(date +%s)
    
    # Capturar estatísticas gerais do DNS
    (timeout 10s tcpdump -i $NETWORK_INTERFACE -n $DNS_PORT -c 1000 -w - 2>/dev/null | \
     dnstop -l 10 -r - src 2>/dev/null) | \
     grep -v "^#" | grep -v "^$" > $output_file
    
    # Processar estatísticas básicas
    local total_queries=$(cat $output_file | awk '{sum+=$2} END {print sum}')
    local unique_ips=$(cat $output_file | wc -l)
    local max_rps=0
    local avg_rps=0
    
    # Se temos queries, calcular RPS
    if [ "$total_queries" -gt 0 ]; then
        # Calcular RPS máximo
        max_rps=$(cat $output_file | awk '{print $2}' | sort -nr | head -1)
        max_rps=$((max_rps / 10))  # Convertendo para req/s (período de 10s)
        
        # Calcular RPS médio
        if [ "$unique_ips" -gt 0 ]; then
            avg_rps=$((total_queries / 10 / unique_ips))
        fi
    fi
    
    # Coletar também estatísticas por tipo de consulta
    (timeout 10s tcpdump -i $NETWORK_INTERFACE -n $DNS_PORT -c 1000 -w - 2>/dev/null | \
     dnstop -l 10 -r - qtype 2>/dev/null) | \
     grep -v "^#" | grep -v "^$" > $temp_dir/query_types.txt
    
    # Extrair consultas NXDomain
    local nx_queries=$(grep "NXDomain" $temp_dir/query_types.txt | awk '{print $2}')
    if [ -z "$nx_queries" ]; then
        nx_queries=0
    fi
    
    # Calcular percentual de NXDomain
    local nx_percent=0
    if [ "$total_queries" -gt 0 ]; then
        nx_percent=$((nx_queries * 100 / total_queries))
    fi
    
    # Exportar as métricas conforme o modo selecionado
    if $PROMETHEUS_MODE; then
        # Formato para Prometheus
        cat > $PROMETHEUS_FILE << EOF
# HELP dns_total_queries Total de consultas DNS nos últimos 10 segundos
# TYPE dns_total_queries gauge
dns_total_queries $total_queries $timestamp
# HELP dns_unique_ips Número de IPs únicos fazendo consultas DNS
# TYPE dns_unique_ips gauge
dns_unique_ips $unique_ips $timestamp
# HELP dns_max_rps Taxa máxima de requisições por segundo
# TYPE dns_max_rps gauge
dns_max_rps $max_rps $timestamp
# HELP dns_avg_rps Taxa média de requisições por segundo por IP
# TYPE dns_avg_rps gauge
dns_avg_rps $avg_rps $timestamp
# HELP dns_nx_percent Percentual de consultas NXDomain
# TYPE dns_nx_percent gauge
dns_nx_percent $nx_percent $timestamp
# HELP dns_max_rps_limit Limite configurado de requisições por segundo
# TYPE dns_max_rps_limit gauge
dns_max_rps_limit $MAX_RPS $timestamp
# HELP dns_ban_count Total de IPs banidos nas últimas 24 horas
# TYPE dns_ban_count gauge
dns_ban_count $(grep -c "Abuso de DNS detectado" /var/log/dns-abuse.log | tail -n 1000) $timestamp
EOF
        echo "Métricas exportadas para Prometheus em $PROMETHEUS_FILE"
    fi
    
    if $ZABBIX_MODE && [ -n "$ZABBIX_SENDER" ] && [ -f "$ZABBIX_CONFIG" ]; then
        # Formato para Zabbix
        local hostname=$(hostname)
        
        $ZABBIX_SENDER -c $ZABBIX_CONFIG -s "$hostname" -k dns.total_queries -o "$total_queries"
        $ZABBIX_SENDER -c $ZABBIX_CONFIG -s "$hostname" -k dns.unique_ips -o "$unique_ips"
        $ZABBIX_SENDER -c $ZABBIX_CONFIG -s "$hostname" -k dns.max_rps -o "$max_rps"
        $ZABBIX_SENDER -c $ZABBIX_CONFIG -s "$hostname" -k dns.avg_rps -o "$avg_rps"
        $ZABBIX_SENDER -c $ZABBIX_CONFIG -s "$hostname" -k dns.nx_percent -o "$nx_percent"
        $ZABBIX_SENDER -c $ZABBIX_CONFIG -s "$hostname" -k dns.max_rps_limit -o "$MAX_RPS"
        $ZABBIX_SENDER -c $ZABBIX_CONFIG -s "$hostname" -k dns.ban_count -o "$(grep -c "Abuso de DNS detectado" /var/log/dns-abuse.log | tail -n 1000)"
        
        echo "Métricas enviadas para o servidor Zabbix"
    fi
    
    if $GRAFANA_MODE; then
        # Formato para Grafana (JSON)
        cat > $METRICS_DIR/grafana_metrics.json << EOF
{
  "timestamp": $timestamp,
  "dns_metrics": {
    "total_queries": $total_queries,
    "unique_ips": $unique_ips,
    "max_rps": $max_rps,
    "avg_rps": $avg_rps,
    "nx_percent": $nx_percent,
    "max_rps_limit": $MAX_RPS,
    "ban_count": $(grep -c "Abuso de DNS detectado" /var/log/dns-abuse.log | tail -n 1000)
  }
}
EOF
        echo "Métricas exportadas para Grafana em $METRICS_DIR/grafana_metrics.json"
    fi
    
    # Limpar arquivos temporários
    rm -f $output_file
    rm -rf $temp_dir
}

# Função principal
main() {
    if $RUN_ONCE; then
        collect_dns_metrics
    else
        # Loop infinito para coleta contínua
        while true; do
            collect_dns_metrics
            sleep $METRICS_INTERVAL
        done
    fi
}

# Iniciar a coleta de métricas
main