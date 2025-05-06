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
MAX_RPS=100  # Requisições máximas por segundo
MONITOR_INTERVAL=60  # Intervalo de monitoramento em segundos
NETWORK_INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
DNS_PORT="port 53"  # Filtro para tráfego DNS

# Criar diretório temporário se não existir
mkdir -p $TEMP_DIR

# Função para exibir mensagens de ajuda
show_help() {
    echo "Uso: $0 [OPÇÕES]"
    echo
    echo "Opções:"
    echo "  --test       Executa o script em modo de teste (não bane IPs)"
    echo "  --once       Executa uma única vez e sai"
    echo "  --debug      Mostra informações adicionais para debug"
    echo "  --help       Exibe esta mensagem de ajuda"
    echo
    echo "Sem opções, o script executa em modo de monitoramento contínuo."
    exit 0
}

# Variáveis para controle de fluxo
TEST_MODE=false
DEBUG_MODE=false
RUN_ONCE=false

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
        --help)
            show_help
            ;;
    esac
done

# Função para registrar no log
log_message() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a $LOG_FILE
}

# Função para verificar dependências
check_dependencies() {
    for cmd in dnstop tcpdump grep awk sort uniq bc; do
        if ! command -v $cmd &> /dev/null; then
            log_message "ERRO: Comando $cmd não encontrado. Por favor, instale-o."
            exit 1
        fi
    done
}

# Verificar se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script precisa ser executado como root"
    exit 1
fi

# Verificar dependências
check_dependencies

# Função para monitorar requisições DNS e identificar abusos
monitor_dns() {
    local capture_time=$1
    local output_file="$TEMP_DIR/dnstop_output.txt"
    local source_ips_file="$TEMP_DIR/source_ips.txt"
    
    # Limpar arquivos temporários
    > $output_file
    > $source_ips_file
    
    if $DEBUG_MODE; then
        log_message "Iniciando captura de tráfego DNS por $capture_time segundos na interface $NETWORK_INTERFACE"
    fi
    
    # Capturar tráfego DNS e processar com dnstop
    # Usamos tcpdump para capturar o tráfego e pipe para dnstop
    (tcpdump -i $NETWORK_INTERFACE -n $DNS_PORT -w - 2>/dev/null | \
     dnstop -l $capture_time -r - src 2>/dev/null) | \
     grep -v "^#" | grep -v "^$" > $output_file
    
    # Extrair e processar os IPs dos resultados
    cat $output_file | awk '{print $1, $2}' | sort -nr -k2 > $source_ips_file
    
    # Analisar os IPs e contar requisições por segundo
    while read -r ip count; do
        # Calcular RPS (requisições por segundo)
        local rps=$(echo "$count / $capture_time" | bc)
        
        # Se o RPS exceder o limite, registrar a violação
        if [ "$rps" -gt "$MAX_RPS" ]; then
            if $TEST_MODE; then
                log_message "TESTE: IP $ip excedeu o limite com $rps req/s (não será banido)"
            else
                # Formato específico para Fail2ban reconhecer
                log_message "ALERTA: Abuso de DNS detectado - IP=$ip RPS=$rps - Excedeu limite de $MAX_RPS req/s"
            fi
            
            if $DEBUG_MODE; then
                log_message "DEBUG: Registros totais: $count durante $capture_time segundos"
            fi
        fi
    done < $source_ips_file
}

# Função principal
main() {
    log_message "Iniciando monitoramento de abuso de DNS (Limite: $MAX_RPS req/s)"
    
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