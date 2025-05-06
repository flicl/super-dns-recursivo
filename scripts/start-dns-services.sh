#!/bin/bash
#
# start-dns-services.sh - Inicia todos os serviços do Super DNS Recursivo
#
# Este script inicia o servidor Unbound, o sistema de proteção contra abusos,
# o exportador de métricas e o servidor de API REST.
#

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções de log
function log_info() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${BLUE}[INFO]${NC} $1"
}

function log_success() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[SUCESSO]${NC} $1"
}

function log_warning() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[AVISO]${NC} $1"
}

function log_error() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[ERRO]${NC} $1"
}

# Diretório base para os scripts
BASE_DIR="/home/felicio/super-dns-recursivo"
SCRIPT_DIR="$BASE_DIR/scripts"
CONFIG_DIR="/opt/dns-protection/config"
MONITOR_DIR="$SCRIPT_DIR/monitoring"
API_DIR="$SCRIPT_DIR/api"
LOG_DIR="/var/log"

# Verifica se está sendo executado como root
if [ "$EUID" -ne 0 ]; then
    log_error "Este script precisa ser executado como root"
    exit 1
fi

# Cria diretórios necessários se não existirem
mkdir -p /opt/dns-protection/{config,ml,metrics/prometheus} 2>/dev/null
mkdir -p /var/log/dns-protection 2>/dev/null

# Função para verificar se um serviço está rodando
check_service() {
    if systemctl is-active --quiet $1; then
        return 0
    else
        return 1
    fi
}

# Função para iniciar ou reiniciar um serviço
start_service() {
    local service_name=$1
    local display_name=$2
    
    log_info "Verificando serviço $display_name..."
    
    if check_service $service_name; then
        log_info "$display_name já está em execução, reiniciando..."
        systemctl restart $service_name
        if [ $? -eq 0 ]; then
            log_success "$display_name reiniciado com sucesso"
        else
            log_error "Falha ao reiniciar $display_name"
            return 1
        fi
    else
        log_info "Iniciando $display_name..."
        systemctl start $service_name
        if [ $? -eq 0 ]; then
            log_success "$display_name iniciado com sucesso"
        else
            log_error "Falha ao iniciar $display_name"
            return 1
        fi
    fi
    
    return 0
}

# Inicia o serviço Unbound
log_info "Iniciando serviços do Super DNS Recursivo..."
start_service unbound "Servidor DNS Unbound"

# Verifica se o Fail2ban está rodando e a jail do DNS está habilitada
if check_service fail2ban; then
    log_info "Fail2ban está rodando, verificando jails..."
    if fail2ban-client status | grep -q "dns-abuse"; then
        log_success "Jail dns-abuse está configurada"
    else
        log_warning "Jail dns-abuse não encontrada, tentando habilitá-la..."
        fail2ban-client reload
        sleep 2
        if fail2ban-client status | grep -q "dns-abuse"; then
            log_success "Jail dns-abuse habilitada com sucesso"
        else
            log_error "Não foi possível habilitar a jail dns-abuse"
        fi
    fi
else
    log_warning "Fail2ban não está rodando, iniciando..."
    start_service fail2ban "Fail2ban"
    sleep 2
    if fail2ban-client status | grep -q "dns-abuse"; then
        log_success "Jail dns-abuse está habilitada"
    else
        log_warning "Habilitando jail dns-abuse manualmente..."
        fail2ban-client reload
        sleep 2
    fi
fi

# Verifica e inicia os serviços de monitoramento, se configurados
if [ -f /etc/systemd/system/dns-monitor.service ]; then
    start_service dns-monitor "Monitoramento DNS"
else
    log_warning "Serviço dns-monitor não encontrado no systemd, verificando se o script existe..."
    if [ -f "$MONITOR_DIR/dns-monitor.sh" ]; then
        log_info "Iniciando o monitoramento manualmente..."
        nohup "$MONITOR_DIR/dns-monitor.sh" --start > /dev/null 2>&1 &
        if [ $? -eq 0 ]; then
            log_success "Monitoramento DNS iniciado manualmente"
        else
            log_error "Falha ao iniciar monitoramento manualmente"
        fi
    else
        log_error "Script de monitoramento não encontrado em $MONITOR_DIR/dns-monitor.sh"
    fi
fi

# Verifica e inicia o exportador de métricas, se configurado
if [ -f /etc/systemd/system/dns-metrics-exporter.service ]; then
    start_service dns-metrics-exporter "Exportador de métricas DNS"
else
    log_warning "Serviço dns-metrics-exporter não encontrado no systemd, verificando se o script existe..."
    if [ -f "$MONITOR_DIR/dns-metrics-exporter.sh" ]; then
        log_info "Iniciando o exportador de métricas manualmente..."
        nohup "$MONITOR_DIR/dns-metrics-exporter.sh" > /dev/null 2>&1 &
        if [ $? -eq 0 ]; then
            log_success "Exportador de métricas DNS iniciado manualmente"
        else
            log_error "Falha ao iniciar exportador de métricas manualmente"
        fi
    else
        log_error "Script de exportação de métricas não encontrado em $MONITOR_DIR/dns-metrics-exporter.sh"
    fi
fi

# Inicia o servidor da API REST
log_info "Iniciando o servidor da API REST..."
if [ -f "$API_DIR/dns-api-server.py" ]; then
    # Verifica se a API já está rodando
    pgrep -f "python.*dns-api-server.py" > /dev/null
    if [ $? -eq 0 ]; then
        log_warning "Servidor API já está rodando, reiniciando..."
        pkill -f "python.*dns-api-server.py"
        sleep 2
    fi
    
    # Inicia o servidor da API com nohup para continuar rodando após o script terminar
    cd "$API_DIR"
    nohup python3 dns-api-server.py > "$LOG_DIR/dns-api.log" 2>&1 &
    
    # Verifica se iniciou com sucesso
    sleep 2
    pgrep -f "python.*dns-api-server.py" > /dev/null
    if [ $? -eq 0 ]; then
        log_success "Servidor da API REST iniciado com sucesso"
    else
        log_error "Falha ao iniciar o servidor da API REST"
    fi
else
    log_error "Script do servidor API não encontrado em $API_DIR/dns-api-server.py"
fi

# Verifica o detector de anomalias
log_info "Verificando detector de anomalias..."
if [ -f "$MONITOR_DIR/dns-anomaly-detector.py" ]; then
    # Executa a coleta de métricas para o treinamento
    log_info "Coletando métricas para o detector de anomalias..."
    python3 "$MONITOR_DIR/dns-anomaly-detector.py" --collect
    
    # Verifica se o modelo existe, se não, tenta treiná-lo
    if [ ! -f "/opt/dns-protection/ml/anomaly_model.pkl" ]; then
        log_warning "Modelo de detecção de anomalias não encontrado, tentando treinar..."
        python3 "$MONITOR_DIR/dns-anomaly-detector.py" --train
        if [ $? -eq 0 ]; then
            log_success "Modelo de detecção de anomalias treinado com sucesso"
        else
            log_warning "Não foi possível treinar o modelo. Colecione mais dados primeiro."
        fi
    else
        log_success "Modelo de detecção de anomalias encontrado"
    fi
else
    log_warning "Detector de anomalias não encontrado em $MONITOR_DIR/dns-anomaly-detector.py"
fi

# Executa verificações finais
log_info "Verificando status dos serviços..."

# Verificar unbound
if check_service unbound; then
    log_success "Servidor DNS Unbound: ATIVO"
else
    log_error "Servidor DNS Unbound: INATIVO"
fi

# Verificar fail2ban
if check_service fail2ban; then
    log_success "Fail2ban: ATIVO"
else
    log_error "Fail2ban: INATIVO"
fi

# Verificar API
pgrep -f "python.*dns-api-server.py" > /dev/null
if [ $? -eq 0 ]; then
    log_success "Servidor API REST: ATIVO (URL: http://localhost:5000)"
else
    log_error "Servidor API REST: INATIVO"
fi

log_info "Todos os serviços do Super DNS Recursivo foram iniciados ou verificados"
log_info "Para acessar o dashboard web, navegue para http://localhost:5000"
echo ""