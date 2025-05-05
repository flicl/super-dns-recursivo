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

# Banner
echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}  INSTALAÇÃO DA PROTEÇÃO DNS CONTRA ABUSOS   ${NC}"
echo -e "${BLUE}==============================================${NC}"
echo -e "${GREEN}Este script irá configurar:${NC}"
echo -e " - Fail2ban para proteção do servidor DNS"
echo -e " - dnstop para monitoramento de tráfego DNS"
echo -e " - Script de detecção de requisições abusivas"
echo -e " - Integração com iptables para bloqueio automático"
echo

# Criar diretório de proteção e seus subdiretórios
echo -e "${YELLOW}[1/7]${NC} Criando diretórios..."
mkdir -p $DNS_PROTECTION_DIR
mkdir -p $DNS_PROTECTION_DIR/temp
mkdir -p $DNS_PROTECTION_DIR/logs
mkdir -p $DNS_PROTECTION_DOCS_DIR

# Verificar dependências
echo -e "${YELLOW}[2/7]${NC} Verificando e instalando dependências..."
apt update

# Verificar se dnstop e tcpdump estão instalados
if ! command -v dnstop &> /dev/null || ! command -v tcpdump &> /dev/null; then
    echo -e "   ${BLUE}→${NC} Instalando dnstop e tcpdump..."
    apt install -y dnstop tcpdump bc
fi

# Instalar Fail2ban se necessário
if ! command -v fail2ban-server &> /dev/null; then
    echo -e "   ${BLUE}→${NC} Instalando Fail2ban..."
    apt install -y fail2ban
fi

# Criar script de monitoramento de DNS
echo -e "${YELLOW}[3/7]${NC} Criando script de monitoramento DNS..."
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
EOF

# Tornar o script executável
chmod +x $DNS_PROTECTION_DIR/dns-monitor.sh

# Criar arquivo de configuração do filtro Fail2ban
echo -e "${YELLOW}[4/7]${NC} Configurando Fail2ban..."
cat > /etc/fail2ban/filter.d/dns-abuse.conf << 'EOF'
# Fail2ban filter para detectar abuso de DNS baseado no output do script dns-monitor.sh
#

[Definition]
# Opções para o Fail2ban
_daemon = dns-monitor

# Padrão para capturar IPs que abusam do serviço DNS
# Formato do log: [2025-05-05 12:34:56] ALERTA: Abuso de DNS detectado - IP=192.168.1.100 RPS=150 - Excedeu limite de 100 req/s
failregex = ^.*ALERTA: Abuso de DNS detectado - IP=<HOST> RPS=.* - Excedeu limite de .* req/s$

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
echo -e "${YELLOW}[5/7]${NC} Criando serviço de monitoramento..."
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

# Copiar os arquivos necessários para a documentação
echo -e "${YELLOW}[6/7]${NC} Criando documentação..."
cp $DNS_PROTECTION_DIR/dns-monitor.sh $DNS_PROTECTION_DOCS_DIR/
cp /etc/fail2ban/filter.d/dns-abuse.conf $DNS_PROTECTION_DOCS_DIR/
cp /etc/fail2ban/jail.d/dns-abuse.conf $DNS_PROTECTION_DOCS_DIR/

# Criar arquivo README na documentação
cat > $DNS_PROTECTION_DOCS_DIR/README.md << 'EOF'
# Documentação - Proteção DNS contra Abusos

Esta pasta contém a documentação e arquivos de configuração usados pelo sistema de proteção DNS contra abusos.

## Arquivos

- `dns-monitor.sh`: Script principal de monitoramento
- `dns-abuse.conf`: Filtro do Fail2ban para detecção de padrões de abuso
- `dns-abuse-jail.conf`: Configuração da jail do Fail2ban

Toda a documentação completa do sistema está disponível em `/opt/dns-protection/docs/`.
EOF

# Reiniciar serviços
echo -e "${YELLOW}[7/7]${NC} Reiniciando serviços..."
systemctl daemon-reload
systemctl restart fail2ban
systemctl enable dns-protection
systemctl start dns-protection

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}      INSTALAÇÃO CONCLUÍDA COM SUCESSO!      ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo
echo -e "O sistema de proteção contra abusos de DNS está ativo e configurado."
echo -e "Logs de detecção: ${BLUE}/var/log/dns-abuse.log${NC}"
echo -e "Status do serviço: ${BLUE}systemctl status dns-protection${NC}"
echo -e "Status do Fail2ban: ${BLUE}fail2ban-client status dns-abuse${NC}"
echo
echo -e "A documentação está disponível em: ${BLUE}$DNS_PROTECTION_DOCS_DIR${NC}"
echo -e "${YELLOW}Lembre-se de ajustar o limite de requisições por segundo (MAX_RPS=100) no script se necessário.${NC}"
echo