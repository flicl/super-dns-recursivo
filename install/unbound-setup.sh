#!/bin/bash
#
# unbound-setup.sh - Script de instalação e configuração do servidor DNS Unbound
#
# Este script automatiza a instalação e configuração inicial do Unbound DNS Server,
# otimizado para desempenho e segurança.
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

# Banner
echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}     INSTALAÇÃO DO SERVIDOR DNS UNBOUND      ${NC}"
echo -e "${BLUE}==============================================${NC}"
echo -e "${GREEN}Este script irá configurar:${NC}"
echo -e " - Unbound DNS Server otimizado"
echo -e " - Configuração de DNSSEC"
echo -e " - Ferramentas de estatísticas e controle"
echo

# Atualizar repositórios
echo -e "${YELLOW}[1/6]${NC} Atualizando repositórios..."
apt update

# Instalar Unbound e ferramentas relacionadas
echo -e "${YELLOW}[2/6]${NC} Instalando Unbound e ferramentas relacionadas..."
apt install -y unbound unbound-anchor unbound-host dnsutils

# Verificar se a instalação foi bem-sucedida
if ! command -v unbound -V &> /dev/null; then
    echo -e "${RED}Falha na instalação do Unbound. Verifique os logs para mais detalhes.${NC}"
    exit 1
fi

# Parar o serviço para configuração
echo -e "${YELLOW}[3/6]${NC} Parando o serviço Unbound para configuração..."
systemctl stop unbound

# Fazer backup da configuração original
echo -e "${YELLOW}[4/6]${NC} Fazendo backup da configuração original..."
if [ -f /etc/unbound/unbound.conf ]; then
    mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.original.$(date +%Y%m%d)
fi

# Copiar nova configuração
echo -e "${YELLOW}[5/6]${NC} Aplicando nova configuração..."
cp $(dirname $0)/../conf/unbound.conf /etc/unbound/unbound.conf

# Ajustar configuração para este servidor
echo -e "${YELLOW}[5.1/6]${NC} Ajustando configuração para este servidor..."
# Detectar número de CPUs disponíveis e ajustar threads
NUM_CPUS=$(nproc)
sed -i "s/num-threads: 4/num-threads: $NUM_CPUS/" /etc/unbound/unbound.conf

# Configurar o DNSSEC
echo -e "${YELLOW}[5.2/6]${NC} Configurando DNSSEC..."
unbound-anchor -a /var/lib/unbound/root.key

# Configurar controle remoto
echo -e "${YELLOW}[5.3/6]${NC} Configurando unbound-control..."
unbound-control-setup

# Ajustar permissões
chown -R unbound:unbound /etc/unbound
chown -R unbound:unbound /var/lib/unbound

# Iniciar e habilitar o serviço
echo -e "${YELLOW}[6/6]${NC} Iniciando e habilitando o serviço Unbound..."
systemctl enable unbound
systemctl restart unbound

# Verificar se o serviço está rodando
if systemctl is-active --quiet unbound; then
    echo -e "${GREEN}O serviço Unbound está rodando.${NC}"
else
    echo -e "${RED}Falha ao iniciar o serviço Unbound. Verifique os logs para mais detalhes.${NC}"
    exit 1
fi

# Testar resolução de DNS
echo -e "${YELLOW}Testando resolução de DNS...${NC}"
if dig @127.0.0.1 google.com +short &> /dev/null; then
    echo -e "${GREEN}Teste de resolução de DNS bem-sucedido!${NC}"
else
    echo -e "${RED}Falha no teste de resolução de DNS. Verifique a configuração.${NC}"
fi

# Testar validação DNSSEC
echo -e "${YELLOW}Testando validação DNSSEC...${NC}"
if unbound-host -C /etc/unbound/unbound.conf -v isc.org | grep -q "DNSSEC signature verified"; then
    echo -e "${GREEN}Validação DNSSEC está funcionando corretamente!${NC}"
else
    echo -e "${YELLOW}Alerta: Validação DNSSEC pode não estar funcionando corretamente.${NC}"
fi

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}      INSTALAÇÃO CONCLUÍDA COM SUCESSO!      ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo
echo -e "O servidor DNS Unbound está instalado e configurado."
echo -e "Para verificar o status: ${BLUE}systemctl status unbound${NC}"
echo -e "Para verificar estatísticas: ${BLUE}unbound-control stats${NC}"
echo
echo -e "${YELLOW}Para maior proteção, considere instalar o sistema de proteção contra abusos:${NC}"
echo -e "${BLUE}sudo ./dns-protection-setup.sh${NC}"
echo