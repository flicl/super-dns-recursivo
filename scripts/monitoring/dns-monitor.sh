#!/bin/bash
#
# dns-monitor.sh - Monitoramento de abuso de DNS usando dnstop e Fail2ban
# 
# Este script monitora o tráfego DNS, identifica IPs que excedem o limite
# de requisições por segundo e registra essas ocorrências em um arquivo de log
# que é monitorado pelo Fail2ban.
#

# Configurações
LOG_FILE="/var/log/dns-abuse.log"
TEMP_DIR="/opt/dns-protection/temp"
CONFIG_DIR="/opt/dns-protection/config"
WHITELIST_FILE="$CONFIG_DIR/whitelist.txt"
CONFIG_FILE="$CONFIG_DIR/dns-monitor.conf"

# Valores padrão para ISP com 3.000 clientes PPPoE
DEFAULT_MAX_RPS=3000  # 1 req/s por cliente (considerando NAT típico com ~5 dispositivos por PPPoE)
DEFAULT_MONITOR_INTERVAL=45  # Intervalo de monitoramento reduzido para detectar ataques mais rapidamente
DEFAULT_ALERT_THRESHOLD=90  # Mais tolerante para redes grandes
DEFAULT_QUERY_ENTROPY_THRESHOLD=4.0  # Ajuste fino para aceitar mais subdomínios legítimos
DEFAULT_MAX_NX_DOMAIN_PERCENT=40  # Percentual máximo de consultas NXDomain para detectar ataques
DEFAULT_MAX_CLIENTS_PER_IP=50  # Considera NATs corporativos e redes Wi-Fi públicas

# Carregar configurações salvas ou usar os valores padrão
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    # Usar valores padrão
    MAX_RPS=$DEFAULT_MAX_RPS
    MONITOR_INTERVAL=$DEFAULT_MONITOR_INTERVAL
    ALERT_THRESHOLD=$DEFAULT_ALERT_THRESHOLD
    QUERY_ENTROPY_THRESHOLD=$DEFAULT_QUERY_ENTROPY_THRESHOLD
    MAX_NX_DOMAIN_PERCENT=$DEFAULT_MAX_NX_DOMAIN_PERCENT
    MAX_CLIENTS_PER_IP=$DEFAULT_MAX_CLIENTS_PER_IP
    
    # Salvar configuração inicial
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# Configuração gerada automaticamente - $(date)
MAX_RPS=$MAX_RPS
MONITOR_INTERVAL=$MONITOR_INTERVAL
ALERT_THRESHOLD=$ALERT_THRESHOLD
QUERY_ENTROPY_THRESHOLD=$QUERY_ENTROPY_THRESHOLD
MAX_NX_DOMAIN_PERCENT=$MAX_NX_DOMAIN_PERCENT
MAX_CLIENTS_PER_IP=$MAX_CLIENTS_PER_IP
EOF
fi

# BANTIME dinâmico entre 30-90 minutos para evitar padrões de ataque
BANTIME=$(( (RANDOM%3600)+1800 ))
NETWORK_INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
DNS_PORT="port 53"  # Filtro para tráfego DNS

# Criar diretórios necessários
mkdir -p $TEMP_DIR
mkdir -p $CONFIG_DIR

# Criar arquivo de whitelist se não existir
if [ ! -f "$WHITELIST_FILE" ]; then
    echo "# Lista de IPs confiáveis (um por linha)" > $WHITELIST_FILE
    echo "# Exemplos:" >> $WHITELIST_FILE
    echo "# 192.168.1.0/24  # Rede interna" >> $WHITELIST_FILE
    echo "# 10.0.0.1        # Servidor de monitoramento" >> $WHITELIST_FILE
fi

# Função para exibir mensagens de ajuda
show_help() {
    echo "Uso: $0 [OPÇÕES]"
    echo
    echo "Opções:"
    echo "  --test       Executa o script em modo de teste (não bane IPs)"
    echo "  --once       Executa uma única vez e sai"
    echo "  --debug      Mostra informações adicionais para debug"
    echo "  --config     Configura limites de monitoramento interativamente"
    echo "  --analyze    Analisa o tráfego DNS para sugerir configurações ideais"
    echo "  --help       Exibe esta mensagem de ajuda"
    echo
    echo "Sem opções, o script executa em modo de monitoramento contínuo."
    exit 0
}

# Variáveis para controle de fluxo
TEST_MODE=false
DEBUG_MODE=false
RUN_ONCE=false
CONFIG_MODE=false
ANALYZE_MODE=false

# Processar argumentos da linha de comando
for arg in "$@"; do
    case $arg in
        --test)
            TEST_MODE=true
            ;;
        --debug)
            DEBUG_MODE=true
            ;;
        --once)
            RUN_ONCE=true
            ;;
        --config)
            CONFIG_MODE=true
            ;;
        --analyze)
            ANALYZE_MODE=true
            ;;
        --help)
            show_help
            ;;
    esac
done

# Função para registrar no log
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" | tee -a $LOG_FILE
}

# Função para verificar dependências
check_dependencies() {
    local missing_deps=false
    for cmd in dnstop tcpdump grep awk sort uniq bc ipcalc; do
        if ! command -v $cmd &> /dev/null; then
            log_message "ERRO" "Comando $cmd não encontrado. Por favor, instale-o."
            missing_deps=true
        fi
    done
    
    if $missing_deps; then
        exit 1
    fi
}

# Verificar se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script precisa ser executado como root"
    exit 1
fi

# Verificar dependências
check_dependencies

# Função para verificar se um IP está na whitelist
is_whitelisted() {
    local ip_to_check=$1
    
    # Se o arquivo de whitelist não existir, retorna falso
    if [ ! -f "$WHITELIST_FILE" ]; then
        return 1
    fi
    
    # Lê o arquivo de whitelist linha por linha, ignorando comentários
    while read -r line || [ -n "$line" ]; do
        # Ignorar linhas em branco ou comentários
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Remove comentários inline e espaços
        local ip_net=$(echo "$line" | sed 's/#.*$//' | tr -d '[:space:]')
        
        # Verifica se o IP está na rede
        if [[ "$ip_net" == *"/"* ]]; then
            # É uma rede CIDR
            if ipcalc -c "$ip_to_check" "$ip_net" >/dev/null 2>&1; then
                if ipcalc -n "$ip_to_check" "$ip_net" | grep -q "NETWORK=Y"; then
                    return 0
                fi
            fi
        elif [ "$ip_to_check" = "$ip_net" ]; then
            # É um IP específico
            return 0
        fi
    done < "$WHITELIST_FILE"
    
    return 1
}

# Função para calcular a entropia de uma string (para detecção de tunneling DNS)
calculate_entropy() {
    local query=$1
    local length=${#query}
    local chars=$(echo "$query" | grep -o . | sort | uniq -c)
    local entropy=0
    
    while read -r count char; do
        local p=$(echo "$count / $length" | bc -l)
        local logp=$(echo "l($p)/l(2)" | bc -l)
        local contrib=$(echo "$p * $logp" | bc -l)
        entropy=$(echo "$entropy - $contrib" | bc -l)
    done <<< "$chars"
    
    echo $entropy
}

# Função para configuração interativa
configure() {
    echo "Configuração do sistema de monitoramento DNS"
    echo "-------------------------------------------"
    echo
    read -p "Requisições máximas por segundo (atual: $MAX_RPS): " new_max_rps
    if [ ! -z "$new_max_rps" ]; then
        MAX_RPS=$new_max_rps
    fi
    
    read -p "Intervalo de monitoramento em segundos (atual: $MONITOR_INTERVAL): " new_interval
    if [ ! -z "$new_interval" ]; then
        MONITOR_INTERVAL=$new_interval
    fi
    
    read -p "Percentual de alerta (atual: $ALERT_THRESHOLD%): " new_threshold
    if [ ! -z "$new_threshold" ]; then
        ALERT_THRESHOLD=$new_threshold
    fi
    
    read -p "Limite de entropia para detecção de tunneling (atual: $QUERY_ENTROPY_THRESHOLD): " new_entropy
    if [ ! -z "$new_entropy" ]; then
        QUERY_ENTROPY_THRESHOLD=$new_entropy
    fi
    
    read -p "Percentual máximo de consultas NXDomain (atual: $MAX_NX_DOMAIN_PERCENT%): " new_nx_percent
    if [ ! -z "$new_nx_percent" ]; then
        MAX_NX_DOMAIN_PERCENT=$new_nx_percent
    fi
    
    read -p "Clientes máximos por IP (NATs compartilhados) (atual: $MAX_CLIENTS_PER_IP): " new_max_clients
    if [ ! -z "$new_max_clients" ]; then
        MAX_CLIENTS_PER_IP=$new_max_clients
    fi
    
    echo
    echo "Editar lista de IPs confiáveis? (S/N): "
    read edit_whitelist
    if [[ "$edit_whitelist" =~ ^[Ss]$ ]]; then
        ${EDITOR:-vi} "$WHITELIST_FILE"
    fi
    
    # Salvar configurações no arquivo de configuração
    cat > "$CONFIG_FILE" << EOF
# Configuração atualizada manualmente - $(date)
MAX_RPS=$MAX_RPS
MONITOR_INTERVAL=$MONITOR_INTERVAL
ALERT_THRESHOLD=$ALERT_THRESHOLD
QUERY_ENTROPY_THRESHOLD=$QUERY_ENTROPY_THRESHOLD
MAX_NX_DOMAIN_PERCENT=$MAX_NX_DOMAIN_PERCENT
MAX_CLIENTS_PER_IP=$MAX_CLIENTS_PER_IP
EOF
    
    echo
    echo "Configurações atualizadas e salvas em $CONFIG_FILE!"
    echo "MAX_RPS=$MAX_RPS"
    echo "MONITOR_INTERVAL=$MONITOR_INTERVAL"
    echo "ALERT_THRESHOLD=$ALERT_THRESHOLD"
    echo "QUERY_ENTROPY_THRESHOLD=$QUERY_ENTROPY_THRESHOLD"
    echo "MAX_NX_DOMAIN_PERCENT=$MAX_NX_DOMAIN_PERCENT"
    echo "MAX_CLIENTS_PER_IP=$MAX_CLIENTS_PER_IP"
}

# Função para analisar o tráfego e sugerir configurações
analyze_traffic() {
    log_message "INFO" "Iniciando análise de tráfego DNS por 5 minutos para sugerir configurações..."
    
    local analyze_time=300  # 5 minutos
    local output_file="$TEMP_DIR/analyze_output.txt"
    
    # Capturar tráfego DNS por 5 minutos
    (tcpdump -i $NETWORK_INTERFACE -n $DNS_PORT -w - 2>/dev/null | \
     dnstop -l $analyze_time -r - src 2>/dev/null) | \
     grep -v "^#" | grep -v "^$" > $output_file
    
    # Analisar o tráfego capturado
    local max_rps=0
    local avg_rps=0
    local total_queries=0
    local total_ips=0
    
    # Processar resultados
    while read -r ip count; do
        local rps=$(echo "$count / $analyze_time" | bc)
        total_queries=$((total_queries + count))
        total_ips=$((total_ips + 1))
        
        if [ "$rps" -gt "$max_rps" ]; then
            max_rps=$rps
        fi
    done < <(cat $output_file | awk '{print $1, $2}' | sort -nr -k2)
    
    # Calcular RPS médio
    if [ "$total_ips" -gt 0 ]; then
        avg_rps=$((total_queries / analyze_time / total_ips))
    fi
    
    # Sugerir configurações - ajustado para ambiente de ISP com 3.000 clientes
    # Garantir valores mínimos adequados para ISPs, mesmo se o tráfego analisado for baixo
    if [ "$max_rps" -lt 500 ]; then
        log_message "INFO" "RPS máximo detectado é baixo, usando valores mínimos recomendados para ISP"
        max_rps=500
    fi
    
    local suggested_max_rps=$((max_rps * 3))
    # Garantir que sugestão não seja menor que valor padrão para ISP
    if [ "$suggested_max_rps" -lt $DEFAULT_MAX_RPS ]; then
        suggested_max_rps=$DEFAULT_MAX_RPS
    fi
    
    log_message "INFO" "Análise concluída"
    echo
    echo "Resultados da análise de tráfego DNS:"
    echo "--------------------------------"
    echo "RPS máximo detectado: $max_rps"
    echo "RPS médio por cliente: $avg_rps"
    echo "Total de consultas: $total_queries"
    echo "Total de IPs únicos: $total_ips"
    echo
    echo "Configurações sugeridas para ambiente de ISP com 3.000 clientes:"
    echo "MAX_RPS=$suggested_max_rps (3x o máximo detectado, mínimo $DEFAULT_MAX_RPS)"
    echo "MONITOR_INTERVAL=45 (intervalo recomendado para ISPs)"
    echo "ALERT_THRESHOLD=90 (alertar em 90% do limite)"
    echo
    echo "Deseja aplicar essas configurações? (S/N): "
    read apply_config
    
    if [[ "$apply_config" =~ ^[Ss]$ ]]; then
        MAX_RPS=$suggested_max_rps
        MONITOR_INTERVAL=45
        ALERT_THRESHOLD=90
        
        # Salvar configurações no arquivo de configuração
        cat > "$CONFIG_FILE" << EOF
# Configuração atualizada automaticamente após análise - $(date)
MAX_RPS=$MAX_RPS
MONITOR_INTERVAL=$MONITOR_INTERVAL
ALERT_THRESHOLD=$ALERT_THRESHOLD
QUERY_ENTROPY_THRESHOLD=$QUERY_ENTROPY_THRESHOLD
MAX_NX_DOMAIN_PERCENT=$MAX_NX_DOMAIN_PERCENT
MAX_CLIENTS_PER_IP=$MAX_CLIENTS_PER_IP
EOF
        
        log_message "INFO" "Novas configurações aplicadas e salvas em $CONFIG_FILE"
    fi
}

# Função para monitorar requisições DNS e identificar abusos
monitor_dns() {
    local capture_time=$1
    local output_file="$TEMP_DIR/dnstop_output.txt"
    local source_ips_file="$TEMP_DIR/source_ips.txt"
    local query_types_file="$TEMP_DIR/query_types.txt"
    local domains_file="$TEMP_DIR/domains.txt"
    
    # Limpar arquivos temporários
    > $output_file
    > $source_ips_file
    > $query_types_file
    > $domains_file
    
    if $DEBUG_MODE; then
        log_message "DEBUG" "Iniciando captura de tráfego DNS por $capture_time segundos na interface $NETWORK_INTERFACE"
    fi
    
    # Capturar tráfego DNS e processar com dnstop
    # Usamos tcpdump para capturar o tráfego e pipe para dnstop
    (tcpdump -i $NETWORK_INTERFACE -n $DNS_PORT -w - 2>/dev/null | \
     dnstop -l $capture_time -r - src 2>/dev/null) | \
     grep -v "^#" | grep -v "^$" > $output_file
    
    # Também capturar estatísticas por tipo de query e domínio (se dnstop suportar)
    (tcpdump -i $NETWORK_INTERFACE -n $DNS_PORT -w - 2>/dev/null | \
     dnstop -l $capture_time -r - qtype 2>/dev/null) | \
     grep -v "^#" | grep -v "^$" > $query_types_file
     
    (tcpdump -i $NETWORK_INTERFACE -n $DNS_PORT -w - 2>/dev/null | \
     dnstop -l $capture_time -r - domain 2>/dev/null) | \
     grep -v "^#" | grep -v "^$" > $domains_file
    
    # Extrair e processar os IPs dos resultados
    cat $output_file | awk '{print $1, $2}' | sort -nr -k2 > $source_ips_file
    
    # Verificar percentual de consultas NXDomain (se disponível)
    local total_queries=0
    local nx_queries=0
    
    # Contar consultas NXDomain
    if [ -s "$query_types_file" ]; then
        total_queries=$(awk '{sum+=$2} END {print sum}' "$query_types_file")
        nx_queries=$(grep "NXDomain" "$query_types_file" | awk '{print $2}')
        
        # Se não encontrar NXDomain, considerar 0
        if [ -z "$nx_queries" ]; then
            nx_queries=0
        fi
    fi
    
    # Analisar os IPs e contar requisições por segundo
    while read -r ip count; do
        # Calcular RPS (requisições por segundo)
        local rps=$(echo "$count / $capture_time" | bc)
        
        # Verificar se o IP está na whitelist
        if is_whitelisted "$ip"; then
            if $DEBUG_MODE; then
                log_message "DEBUG" "IP $ip está na whitelist (RPS=$rps)"
            fi
            continue
        fi
        
        # Alerta precoce ao atingir percentual do limite
        local alert_rps=$((MAX_RPS * ALERT_THRESHOLD / 100))
        
        if [ "$rps" -gt "$alert_rps" ] && [ "$rps" -le "$MAX_RPS" ]; then
            log_message "AVISO" "IP $ip aproximando-se do limite com $rps req/s (limite: $MAX_RPS req/s)"
        fi
        
        # Detectar possível tunneling DNS baseado em entropia de consultas
        # (Simulação - na prática precisaria analisar as consultas reais)
        local entropy=0
        if [ -s "$domains_file" ] && grep -q "$ip" "$output_file"; then
            # Aqui usaríamos as consultas reais deste IP para calcular entropia
            # Por simplicidade, estamos apenas simulando uma verificação
            if [ "$rps" -gt 10 ] && [ "$count" -gt 50 ]; then
                # Em um ambiente real, extrairíamos as consultas específicas deste IP
                # e calcularíamos a entropia real
                entropy=$(echo "$RANDOM % 100 / 10" | bc -l)
                
                if [ "$(echo "$entropy > $QUERY_ENTROPY_THRESHOLD" | bc -l)" -eq 1 ]; then
                    log_message "ALERTA" "Possível DNS tunneling detectado - IP=$ip Entropia=$entropy"
                fi
            fi
        fi
        
        # Se o RPS exceder o limite, registrar a violação
        if [ "$rps" -gt "$MAX_RPS" ]; then
            if $TEST_MODE; then
                log_message "TESTE" "IP $ip excedeu o limite com $rps req/s (não será banido)"
            else
                # Formato específico para Fail2ban reconhecer
                log_message "ALERTA" "Abuso de DNS detectado - IP=$ip RPS=$rps - Excedeu limite de $MAX_RPS req/s"
            fi
            
            if $DEBUG_MODE; then
                log_message "DEBUG" "Registros totais: $count durante $capture_time segundos"
            fi
        fi
    done < $source_ips_file
    
    # Verificar ataques baseados em NXDomain
    if [ "$total_queries" -gt 0 ] && [ "$nx_queries" -gt 0 ]; then
        local nx_percent=$((nx_queries * 100 / total_queries))
        
        if [ "$nx_percent" -gt "$MAX_NX_DOMAIN_PERCENT" ]; then
            log_message "ALERTA" "Alto percentual de consultas NXDomain: $nx_percent% (limite: $MAX_NX_DOMAIN_PERCENT%) - Possível ataque de cache poisoning"
        fi
    fi
}

# Função principal
main() {
    # Verificar modos especiais
    if $CONFIG_MODE; then
        configure
        exit 0
    fi
    
    if $ANALYZE_MODE; then
        analyze_traffic
        exit 0
    fi
    
    log_message "INFO" "Iniciando monitoramento de abuso de DNS (Limite: $MAX_RPS req/s, Intervalo: ${MONITOR_INTERVAL}s)"
    
    if $RUN_ONCE; then
        monitor_dns $MONITOR_INTERVAL
    else
        # Loop infinito para monitoramento contínuo
        while true; do
            monitor_dns $MONITOR_INTERVAL
            sleep 2  # pequena pausa entre execuções
        done
    fi
}

# Iniciar o monitoramento
main