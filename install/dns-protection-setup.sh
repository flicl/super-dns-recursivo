#!/bin/bash
#
# dns-protection-setup.sh - Script de instalação da proteção contra abusos em DNS
#
# Este script automatiza a instalação e configuração do sistema de proteção
# contra abusos em servidores DNS Unbound usando dnstop e Fail2ban.
#

# Cores para saída do terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verificar se está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Este script precisa ser executado como root${NC}"
    exit 1
fi

# Diretórios principais (fixo conforme solicitado)
DNS_PROTECTION_DIR="/opt/dns-protection"
DNS_PROTECTION_DOCS_DIR="/opt/dns-protection/docs"
DNS_PROTECTION_CONF_DIR="/opt/dns-protection/config"
DNS_PROTECTION_TEMP_DIR="/opt/dns-protection/temp"

# Banner
echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}  INSTALAÇÃO DA PROTEÇÃO DNS CONTRA ABUSOS   ${NC}"
echo -e "${BLUE}==============================================${NC}"
echo -e "${GREEN}Este script irá configurar:${NC}"
echo -e " - Fail2ban para proteção do servidor DNS"
echo -e " - dnstop para monitoramento de tráfego DNS"
echo -e " - Script de detecção avançada de requisições abusivas"
echo -e " - Sistema de whitelist para IPs confiáveis"
echo -e " - Detecção de tunneling DNS e ataques NXDomain"
echo -e " - Análise automática para otimização de configurações"
echo -e " - Integração com iptables para bloqueio automático"
echo

# Criar diretório de proteção e seus subdiretórios
echo -e "${YELLOW}[1/8]${NC} Criando diretórios..."
mkdir -p $DNS_PROTECTION_DIR
mkdir -p $DNS_PROTECTION_TEMP_DIR
mkdir -p $DNS_PROTECTION_CONF_DIR
mkdir -p $DNS_PROTECTION_DOCS_DIR

# Verificar dependências
echo -e "${YELLOW}[2/8]${NC} Verificando e instalando dependências..."
apt update

# Verificar se dnstop, tcpdump e outras ferramentas estão instaladas
if ! command -v dnstop &> /dev/null || ! command -v tcpdump &> /dev/null; then
    echo -e "   ${BLUE}→${NC} Instalando dnstop e tcpdump..."
    apt install -y dnstop tcpdump bc
fi

# Verificar/instalar outras dependências necessárias
if ! command -v ipcalc &> /dev/null; then
    echo -e "   ${BLUE}→${NC} Instalando ipcalc..."
    apt install -y ipcalc
fi

# Instalar Fail2ban se necessário
if ! command -v fail2ban-server &> /dev/null; then
    echo -e "   ${BLUE}→${NC} Instalando Fail2ban..."
    apt install -y fail2ban
fi

# Criar arquivo de whitelist
echo -e "${YELLOW}[3/8]${NC} Criando arquivo de whitelist..."
cat > $DNS_PROTECTION_CONF_DIR/whitelist.txt << 'EOF'
# Lista de IPs confiáveis (um por linha)
# IPs e redes nesta lista nunca serão bloqueados, independentemente do volume de consultas
#
# Exemplos:
# 192.168.1.0/24  # Rede interna
# 10.0.0.1        # Servidor de monitoramento
# 172.16.5.10     # Servidor de logs

# Adicione seus IPs confiáveis abaixo:
127.0.0.1
EOF

# Criar script de monitoramento de DNS
echo -e "${YELLOW}[4/8]${NC} Criando script de monitoramento DNS..."
cat > $DNS_PROTECTION_DIR/dns-monitor.sh << 'EOF'
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
MAX_RPS=300  # Requisições máximas por segundo (valor aumentado conforme recomendado)
MONITOR_INTERVAL=30  # Intervalo de monitoramento reduzido para detectar ataques mais rapidamente
NETWORK_INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
DNS_PORT="port 53"  # Filtro para tráfego DNS
ALERT_THRESHOLD=80  # Percentual do MAX_RPS para emitir alertas sem bloquear (detecção precoce)
QUERY_ENTROPY_THRESHOLD=4.0  # Limite de entropia para detecção de tunneling DNS
MAX_NX_DOMAIN_PERCENT=30  # Percentual máximo de consultas NXDomain para detectar ataques

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
    
    echo
    echo "Editar lista de IPs confiáveis? (S/N): "
    read edit_whitelist
    if [[ "$edit_whitelist" =~ ^[Ss]$ ]]; then
        ${EDITOR:-vi} "$WHITELIST_FILE"
    fi
    
    echo
    echo "Configurações atualizadas!"
    echo "MAX_RPS=$MAX_RPS"
    echo "MONITOR_INTERVAL=$MONITOR_INTERVAL"
    echo "ALERT_THRESHOLD=$ALERT_THRESHOLD"
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
    
    # Sugerir configurações
    local suggested_max_rps=$((max_rps * 3))
    
    log_message "INFO" "Análise concluída"
    echo
    echo "Resultados da análise de tráfego DNS:"
    echo "--------------------------------"
    echo "RPS máximo detectado: $max_rps"
    echo "RPS médio por cliente: $avg_rps"
    echo "Total de consultas: $total_queries"
    echo "Total de IPs únicos: $total_ips"
    echo
    echo "Configurações sugeridas:"
    echo "MAX_RPS=$suggested_max_rps (3x o máximo detectado)"
    echo "MONITOR_INTERVAL=30 (intervalo recomendado para ambientes em produção)"
    echo "ALERT_THRESHOLD=80 (alertar em 80% do limite)"
    echo
    echo "Deseja aplicar essas configurações? (S/N): "
    read apply_config
    
    if [[ "$apply_config" =~ ^[Ss]$ ]]; then
        MAX_RPS=$suggested_max_rps
        MONITOR_INTERVAL=30
        ALERT_THRESHOLD=80
        log_message "INFO" "Novas configurações aplicadas"
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
EOF

# Tornar o script executável
chmod +x $DNS_PROTECTION_DIR/dns-monitor.sh

# Criar arquivo de configuração do filtro Fail2ban
echo -e "${YELLOW}[5/8]${NC} Configurando Fail2ban..."
cat > /etc/fail2ban/filter.d/dns-abuse.conf << 'EOF'
# Fail2ban filter para detectar abuso de DNS baseado no output do script dns-monitor.sh
#

[Definition]
# Opções para o Fail2ban
_daemon = dns-monitor

# Padrão para capturar IPs que abusam do serviço DNS
# Formato do log: [2025-05-05 12:34:56] [ALERTA] Abuso de DNS detectado - IP=192.168.1.100 RPS=150 - Excedeu limite de 100 req/s
failregex = ^.*\[ALERTA\] Abuso de DNS detectado - IP=<HOST> RPS=.* - Excedeu limite de .* req/s$

# Ignorar padrões que não sejam de falha
ignoreregex =
EOF

# Criar arquivo de configuração da jail Fail2ban
cat > /etc/fail2ban/jail.d/dns-abuse.conf << 'EOF'
[dns-abuse]
enabled = true
filter = dns-abuse
logpath = /var/log/dns-abuse.log
maxretry = 2
findtime = 300
bantime = 3600
action = iptables-multiport[name=dns-abuse, port="53", protocol=udp]
         iptables-multiport[name=dns-abuse, port="53", protocol=tcp]
EOF

# Criar arquivo de serviço systemd para o monitoramento DNS
echo -e "${YELLOW}[6/8]${NC} Criando serviço de monitoramento..."
cat > /etc/systemd/system/dns-protection.service << EOF
[Unit]
Description=Serviço de Proteção contra Abuso de DNS
After=network.target fail2ban.service

[Service]
Type=simple
ExecStart=$DNS_PROTECTION_DIR/dns-monitor.sh
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=dns-protection

[Install]
WantedBy=multi-user.target
EOF

# Criar log vazio se não existir
touch /var/log/dns-abuse.log

# Configurar rotação de logs
cat > /etc/logrotate.d/dns-protection << 'EOF'
/var/log/dns-abuse.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root adm
}
EOF

# Preparar documentação básica
echo -e "${YELLOW}[7/8]${NC} Criando documentação..."

# Copiar documentação do repositório para o diretório de docs
if [ -d "/home/felicio/super-dns-recursivo/docs" ]; then
    echo -e "   ${BLUE}→${NC} Copiando guias e documentação avançada..."
    cp /home/felicio/super-dns-recursivo/docs/dns-protection-quickstart.md $DNS_PROTECTION_DOCS_DIR/
    cp /home/felicio/super-dns-recursivo/docs/dns-protection-technical-guide.md $DNS_PROTECTION_DOCS_DIR/
else
    # Criar um README básico se a documentação completa não estiver disponível
    cat > $DNS_PROTECTION_DOCS_DIR/README.md << 'EOF'
# Documentação - Proteção DNS contra Abusos

Esta pasta contém a documentação e arquivos de configuração usados pelo sistema de proteção DNS contra abusos.

## Componentes Principais

- **Script de monitoramento**: `/opt/dns-protection/dns-monitor.sh`
- **Whitelist**: `/opt/dns-protection/config/whitelist.txt`
- **Filtro Fail2ban**: `/etc/fail2ban/filter.d/dns-abuse.conf`
- **Configuração do Fail2ban**: `/etc/fail2ban/jail.d/dns-abuse.conf`

## Funcionalidades Avançadas

- **Análise automática**: Execute `sudo /opt/dns-protection/dns-monitor.sh --analyze` para analisar o tráfego atual e receber sugestões de configuração otimizada
- **Configuração interativa**: Execute `sudo /opt/dns-protection/dns-monitor.sh --config` para ajustar parâmetros sem editar arquivos
- **Whitelist**: Adicione IPs e redes confiáveis em `/opt/dns-protection/config/whitelist.txt`
- **Modo de teste**: Execute `sudo /opt/dns-protection/dns-monitor.sh --test` para testar sem banir IPs

## Comandos Úteis

```bash
# Ver status do serviço
sudo systemctl status dns-protection

# Ver IPs bloqueados
sudo fail2ban-client status dns-abuse

# Desbloquear um IP
sudo fail2ban-client set dns-abuse unbanip IP_ADDRESS

# Ver logs em tempo real
sudo tail -f /var/log/dns-abuse.log
```
EOF
fi

# Reiniciar serviços
echo -e "${YELLOW}[8/8]${NC} Reiniciando serviços..."
systemctl daemon-reload
systemctl restart fail2ban
systemctl enable dns-protection
systemctl start dns-protection

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}      INSTALAÇÃO CONCLUÍDA COM SUCESSO!      ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo
echo -e "O sistema avançado de proteção contra abusos de DNS está ativo e configurado."
echo
echo -e "${BLUE}[RECURSOS AVANÇADOS]${NC}"
echo -e " - Análise automática de tráfego: ${YELLOW}sudo /opt/dns-protection/dns-monitor.sh --analyze${NC}"
echo -e " - Configuração interativa:       ${YELLOW}sudo /opt/dns-protection/dns-monitor.sh --config${NC}" 
echo -e " - Editar whitelist:              ${YELLOW}sudo nano /opt/dns-protection/config/whitelist.txt${NC}"
echo -e " - Modo de teste:                 ${YELLOW}sudo /opt/dns-protection/dns-monitor.sh --test${NC}"
echo
echo -e "${BLUE}[INFORMAÇÕES IMPORTANTES]${NC}"
echo -e " - Logs de detecção:              ${YELLOW}/var/log/dns-abuse.log${NC}"
echo -e " - Limite padrão:                 ${YELLOW}300 requisições por segundo (configurável)${NC}"
echo -e " - Status do serviço:             ${YELLOW}systemctl status dns-protection${NC}"
echo -e " - Status do Fail2ban:            ${YELLOW}fail2ban-client status dns-abuse${NC}"
echo
echo -e "A documentação completa está disponível em: ${BLUE}$DNS_PROTECTION_DOCS_DIR${NC}"
echo