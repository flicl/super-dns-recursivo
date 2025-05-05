# Guia Técnico: Proteção de Servidores DNS Unbound contra Abusos

## 1. Visão Geral e Arquitetura da Solução

Este documento apresenta uma solução completa para proteção de servidores DNS Unbound contra ataques de negação de serviço (DoS) e uso abusivo do serviço. A solução implementa um sistema de monitoramento em tempo real usando **dnstop** para análise do tráfego DNS, com integração ao **Fail2ban** para banimento automático de IPs que excedam limites pré-definidos de requisições por segundo.

### 1.1. Componentes da Arquitetura

1. **dnstop + tcpdump**: Ferramentas para captura e análise de pacotes DNS em tempo real
2. **Script de processamento personalizado**: Interpreta os dados do dnstop e detecta padrões de abuso
3. **Sistema de logs**: Registra detalhes de abusos para análise posterior
4. **Fail2ban**: Serviço de mitigação que efetua o bloqueio dos IPs abusivos
5. **Serviço systemd**: Gerencia o ciclo de vida do processo de monitoramento

### 1.2. Fluxo de Operação

```
[Tráfego DNS] → [tcpdump] → [dnstop] → [Script de Análise] → [Logs de Abuso] → [Fail2ban] → [Regras iptables]
```

O fluxo completo de operação ocorre da seguinte forma:

1. O tráfego DNS na porta 53 (UDP/TCP) é capturado pelo tcpdump
2. Os pacotes capturados são analisados em tempo real pelo dnstop
3. O script de análise processa a saída do dnstop e identifica IPs que excedem o limite de requisições
4. Os eventos de abuso são registrados em um arquivo de log específico
5. O Fail2ban monitora esse arquivo de log e aciona ações quando detecta padrões de abuso
6. O Fail2ban cria regras no iptables para bloquear o acesso dos IPs abusivos

## 2. Instalação e Configuração Detalhada

### 2.1. Pré-requisitos

- Sistema operacional Linux (Debian/Ubuntu recomendado)
- Unbound DNS Server já instalado e operacional
- Privilégios de administrador (root)
- Portas UDP/TCP 53 em uso pelo serviço DNS

### 2.2. Instalação Automatizada

Para uma instalação completa e automatizada, utilize o script de instalação fornecido:

```bash
# Tornar o script executável
chmod +x dns-protection-setup.sh

# Executar o script como root
sudo ./dns-protection-setup.sh
```

### 2.3. Instalação Manual (Passo a Passo)

Se preferir realizar a instalação manualmente, siga esses passos:

#### 2.3.1. Instalação de Dependências

```bash
# Atualizar os repositórios
sudo apt update

# Instalar dependências
sudo apt install -y dnstop tcpdump fail2ban bc
```

#### 2.3.2. Criação da Estrutura de Diretórios

```bash
# Diretório principal da solução (fixo)
DNS_PROTECTION_DIR="/opt/dns-protection"

# Criar diretórios para a solução
sudo mkdir -p $DNS_PROTECTION_DIR
sudo mkdir -p $DNS_PROTECTION_DIR/temp
sudo mkdir -p $DNS_PROTECTION_DIR/logs
sudo mkdir -p $DNS_PROTECTION_DIR/docs
```

#### 2.3.3. Instalação do Script de Monitoramento

Crie o script de monitoramento:

```bash
# Criar script de monitoramento
sudo nano /opt/dns-protection/dns-monitor.sh

# Copie o conteúdo do script fornecido na pasta docs/dns-protection
# [conteúdo do script aqui]

# Definir permissões de execução
sudo chmod +x /opt/dns-protection/dns-monitor.sh
```

#### 2.3.4. Configuração do Fail2ban

1. Criar o filtro Fail2ban para detecção de abusos:

```bash
# Criar filtro Fail2ban
sudo nano /etc/fail2ban/filter.d/dns-abuse.conf

# Insira o conteúdo:
[Definition]
_daemon = dns-monitor
failregex = ^.*ALERTA: Abuso de DNS detectado - IP=<HOST> RPS=.* - Excedeu limite de .* req/s$
ignoreregex =
```

2. Configurar a jail específica para proteção DNS:

```bash
# Criar configuração da jail
sudo nano /etc/fail2ban/jail.d/dns-abuse.conf

# Insira o conteúdo:
[dns-abuse]
enabled = true
filter = dns-abuse
logpath = /var/log/dns-abuse.log
maxretry = 2
findtime = 300
bantime = 3600
action = iptables-multiport[name=dns-abuse, port="53", protocol=udp]
         iptables-multiport[name=dns-abuse, port="53", protocol=tcp]
```

#### 2.3.5. Configuração do Serviço Systemd

Crie o arquivo de serviço para garantir que o monitoramento seja executado como um serviço gerenciado pelo systemd:

```bash
# Criar arquivo de serviço
sudo nano /etc/systemd/system/dns-protection.service

# Insira o conteúdo:
[Unit]
Description=Serviço de Proteção contra Abuso de DNS
After=network.target fail2ban.service

[Service]
Type=simple
ExecStart=/opt/dns-protection/dns-monitor.sh
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=dns-protection

[Install]
WantedBy=multi-user.target
```

#### 2.3.6. Inicialização e Habilitação dos Serviços

```bash
# Criar arquivo de log vazio
sudo touch /var/log/dns-abuse.log

# Recarregar unidades systemd
sudo systemctl daemon-reload

# Reiniciar o Fail2ban para reconhecer as novas configurações
sudo systemctl restart fail2ban

# Habilitar e iniciar o serviço de proteção DNS
sudo systemctl enable dns-protection
sudo systemctl start dns-protection
```

## 3. Customização e Otimização

### 3.1. Ajuste de Limites de Requisições

O limite padrão é de 100 requisições por segundo. Para sistemas com diferentes perfis de carga, esse valor pode ser ajustado:

```bash
# Editar o script de monitoramento
sudo nano /opt/dns-protection/dns-monitor.sh

# Alterar o valor da variável MAX_RPS
# Por exemplo, para 150 requisições por segundo:
MAX_RPS=150
```

### 3.2. Configuração de Tempo de Banimento

O tempo padrão de banimento é de 1 hora (3600 segundos). Para ajustar:

```bash
# Editar a configuração da jail
sudo nano /etc/fail2ban/jail.d/dns-abuse.conf

# Modificar o parâmetro bantime
# Por exemplo, para banir por 2 horas:
bantime = 7200
```

### 3.3. Configuração de IPs Confiáveis

Para evitar o banimento de IPs legítimos (como servidores internos, proxies, ou outras infraestruturas confiáveis):

```bash
# Editar a configuração da jail
sudo nano /etc/fail2ban/jail.d/dns-abuse.conf

# Adicionar a linha ignoreip com os IPs/redes a serem ignorados
ignoreip = 127.0.0.1/8 10.0.0.0/8 192.168.1.0/24
```

### 3.4. Otimização para Servidores com Alto Tráfego

Para servidores que processam grandes volumes de tráfego DNS, recomenda-se:

1. Aumentar o intervalo de captura para reduzir o impacto no processador:

```bash
# Editar o script de monitoramento
sudo nano /opt/dns-protection/dns-monitor.sh

# Aumentar o intervalo de monitoramento, por exemplo, para 120 segundos:
MONITOR_INTERVAL=120
```

2. Ajustar o filtro para focar apenas nos tipos de tráfego mais relevantes:

```bash
# Modificar o filtro tcpdump no script para capturar apenas UDP (que geralmente representa a maior parte do tráfego DNS)
DNS_PORT="port 53 and udp"
```

## 4. Monitoramento e Verificação

### 4.1. Verificação do Status do Serviço

```bash
# Verificar status do serviço de proteção
sudo systemctl status dns-protection

# Verificar status do Fail2ban
sudo fail2ban-client status dns-abuse
```

### 4.2. Monitoramento de Logs

```bash
# Visualizar logs de abuso em tempo real
sudo tail -f /var/log/dns-abuse.log

# Verificar ações do Fail2ban
sudo tail -f /var/log/fail2ban.log
```

### 4.3. Teste do Sistema de Proteção

Para testar o sistema sem efetivamente banir IPs:

```bash
# Executar o script em modo de teste
sudo /opt/dns-protection/dns-monitor.sh --test --once
```

### 4.4. Verificação de IPs Banidos

```bash
# Listar IPs atualmente banidos pelo Fail2ban
sudo fail2ban-client status dns-abuse

# Verificar regras iptables criadas
sudo iptables -L -n | grep -i dns-abuse
```

## 5. Solução de Problemas

### 5.1. O Serviço de Monitoramento Falha ao Iniciar

**Possíveis causas e soluções:**

1. **Permissões**: Verifique se o script tem permissões de execução:
   ```bash
   sudo chmod +x /opt/dns-protection/dns-monitor.sh
   ```

2. **Dependências**: Certifique-se de que todas as dependências estão instaladas:
   ```bash
   sudo apt install -y dnstop tcpdump bc grep awk
   ```

3. **Interface de rede incorreta**: O script tenta detectar automaticamente a interface de rede. Se estiver incorreta:
   ```bash
   # Editar o script para definir manualmente a interface
   sudo nano /opt/dns-protection/dns-monitor.sh
   
   # Substituir a linha de detecção automática por:
   NETWORK_INTERFACE="eth0"  # Use o nome correto da sua interface
   ```

### 5.2. O Fail2ban Não Está Banindo IPs

**Possíveis causas e soluções:**

1. **Filtro incorreto**: Verifique se o filtro está reconhecendo corretamente as entradas no log:
   ```bash
   sudo fail2ban-regex /var/log/dns-abuse.log /etc/fail2ban/filter.d/dns-abuse.conf
   ```

2. **Problema com as ações**: Verifique os logs do Fail2ban:
   ```bash
   sudo tail -f /var/log/fail2ban.log
   ```

3. **Reinício necessário**: Reinicie o Fail2ban após modificações:
   ```bash
   sudo systemctl restart fail2ban
   ```

### 5.3. Alto Consumo de CPU pelo dnstop

**Possíveis soluções:**

1. **Aumentar intervalo de monitoramento**:
   ```bash
   # Editar o script
   sudo nano /opt/dns-protection/dns-monitor.sh
   
   # Aumentar o valor de MONITOR_INTERVAL para 120 ou mais
   ```

2. **Limitar a captura a tipos específicos de pacotes**:
   ```bash
   # Modificar o filtro tcpdump para capturar menos pacotes
   DNS_PORT="port 53 and udp and not (src net 127.0.0.0/8)"
   ```

### 5.4. Falsos Positivos (IPs Legítimos Sendo Banidos)

**Possíveis soluções:**

1. **Aumentar o limite de requisições por segundo**:
   ```bash
   # Editar o script
   sudo nano /opt/dns-protection/dns-monitor.sh
   
   # Aumentar MAX_RPS para um valor mais apropriado
   ```

2. **Adicionar IPs à lista de ignorados**:
   ```bash
   sudo nano /etc/fail2ban/jail.d/dns-abuse.conf
   
   # Adicionar ou modificar a linha ignoreip
   ignoreip = 127.0.0.1/8 10.0.0.0/8 192.168.0.0/16 IP_A_IGNORAR
   ```

3. **Aumentar o número de retentativas antes do banimento**:
   ```bash
   sudo nano /etc/fail2ban/jail.d/dns-abuse.conf
   
   # Aumentar maxretry
   maxretry = 5
   ```

## 6. Manutenção e Boas Práticas

### 6.1. Atualização Periódica

```bash
# Atualizar pacotes regularmente
sudo apt update && sudo apt upgrade -y
```

### 6.2. Verificação Regular dos Logs

Implemente um processo regular de análise de logs para identificar padrões e ajustar configurações:

```bash
# Resumo diário de IPs banidos
grep "Ban " /var/log/fail2ban.log | grep "dns-abuse" | awk '{print $NF}' | sort | uniq -c | sort -nr
```

### 6.3. Backup das Configurações

```bash
# Definir diretório de backup
BACKUP_DIR="/root/backups/dns-protection-$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup periódico das configurações
sudo cp -r /opt/dns-protection $BACKUP_DIR/
sudo cp /etc/fail2ban/filter.d/dns-abuse.conf $BACKUP_DIR/
sudo cp /etc/fail2ban/jail.d/dns-abuse.conf $BACKUP_DIR/
```

### 6.4. Monitoramento Integrado

Considere integrar o monitoramento de IPs banidos com sistemas existentes como Zabbix:

```bash
# Script para enviar contagem de IPs banidos para o Zabbix
# Salve como /opt/dns-protection/zabbix-integration.sh
#!/bin/bash
IP_ZABBIX="seu_ip_zabbix"
HOST_NAME="seu_host_dns"
BANNED_COUNT=$(fail2ban-client status dns-abuse | grep "Currently banned" | awk '{print $4}')
zabbix_sender -z $IP_ZABBIX -s $HOST_NAME -k dns.banned.count -o $BANNED_COUNT
```

## 7. Informações Adicionais

### 7.1. Arquivos Principais

- **Script principal**: `/opt/dns-protection/dns-monitor.sh`
- **Filtro Fail2ban**: `/etc/fail2ban/filter.d/dns-abuse.conf`
- **Configuração da jail**: `/etc/fail2ban/jail.d/dns-abuse.conf`
- **Arquivo de log**: `/var/log/dns-abuse.log`
- **Serviço systemd**: `/etc/systemd/system/dns-protection.service`
- **Documentação**: `/opt/dns-protection/docs/`

### 7.2. Comandos Úteis

```bash
# Ver estatísticas de tráfego DNS em tempo real
sudo dnstop -l 10 $(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")

# Liberar um IP banido pelo Fail2ban
sudo fail2ban-client set dns-abuse unbanip IP_ADDRESS

# Recarregar configuração do Fail2ban sem reiniciar
sudo fail2ban-client reload dns-abuse
```

### 7.3. Recursos e Referências

- [Documentação oficial do dnstop](https://github.com/measurement-factory/dnstop)
- [Documentação oficial do Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Documentação oficial do Unbound](https://nlnetlabs.nl/documentation/unbound/)