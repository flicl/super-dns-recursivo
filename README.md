# Super DNS Recursivo - Servidor DNS + Monitoramento + Proteção

![Versão](https://img.shields.io/badge/Versão-1.1-blue.svg)
![Licença](https://img.shields.io/badge/Licença-MIT-green.svg)

Um servidor DNS recursivo completo baseado no Unbound com monitoramento integrado e proteção contra abusos.

## Visão Geral

O Super DNS Recursivo oferece uma solução completa para serviços DNS em provedores de Internet e empresas, com foco em:

- **Alto Desempenho**: Configuração otimizada do Unbound para ambientes corporativos e de ISP
- **Monitoramento Detalhado**: Integração com Zabbix e Grafana para métricas em tempo real
- **Proteção Avançada**: Sistema de detecção e mitigação de ataques e abusos DNS
- **Fácil Implantação**: Scripts de instalação automatizados

## Plataformas Suportadas

- Ubuntu 20.04 LTS / 22.04 LTS
- Debian 10 / 11 / 12

> Todas as versões foram testadas em instalações limpas e em modo "container" do Proxmox.

## Componentes do Sistema

O sistema é composto por três componentes principais:

1. **Servidor DNS Unbound**: Resolvedor DNS recursivo altamente otimizado
2. **Sistema de Monitoramento**: Coleta de métricas com Zabbix e visualização com Grafana
3. **Sistema de Proteção**: Detecção e bloqueio automático de abusos com análise avançada e Fail2ban

## Guia de Instalação

### 1. Servidor DNS Unbound

```bash
# Atualizar dependências
sudo apt update && sudo apt upgrade -y

# Instalar componentes necessários
sudo apt install unbound net-tools unbound-anchor wget dnsutils dnstop -y

# Configurar Unbound
cd /etc/unbound
sudo mv unbound.conf unbound.conf.bkp
sudo nano unbound.conf
```

Cole o seguinte conteúdo no arquivo de configuração, ajustando conforme necessário:

```properties
# TriplePlay Network
# Unbound DNS Server V1.0

include: "/etc/unbound/unbound.conf.d/*.conf"

# Habilitar uso do unbound-control
remote-control:
  control-enable: yes

# Configuração do servidor
server:
  # LOGS DE USO - Descomente apenas para debug
  # chroot: ""
  # logfile: /var/log/syslog.log
  # verbosity: 1
  # log-queries: yes

  # Estatísticas de Uso para Monitoramento
  statistics-interval: 0
  extended-statistics: yes
  statistics-cumulative: no
  port: 53
  
  # Lista de Interfaces
  interface: 0.0.0.0
  interface: ::0
  interface: 127.0.0.1
  interface: ::1

  # Lista de IPs com acesso permitido
  access-control: 127.0.0.1 allow
  access-control: ::1 allow
  access-control: 10.0.0.0/8 allow
  access-control: 100.64.0.0/10 allow
  access-control: 127.0.0.0/8 allow
  access-control: 172.16.0.0/12 allow
  access-control: 192.168.0.0/16 allow

  # Tunning de Desempenho
  num-threads: 4
  msg-cache-slabs: 8
  rrset-cache-slabs: 8
  infra-cache-slabs: 8
  key-cache-slabs: 8
  so-reuseport: yes
  outgoing-range: 200
  rrset-cache-size: 256m
  msg-cache-size: 128m
  cache-min-ttl: 3600
  cache-max-ttl: 10800

  # Protocolos Suportados
  do-ip4: yes
  do-ip6: yes
  do-tcp: yes
  do-udp: yes
  
  # Arquivo de Hints
  root-hints: "/etc/unbound/named.cache"
  
  # Configurações de Segurança
  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
```

Finalize a configuração:

```bash
# Baixar lista de servidores raiz
wget https://www.internic.net/domain/named.cache -O /etc/unbound/named.cache

# Caso esteja usando Ubuntu, desativar o resolver nativo
sudo service systemd-resolved stop
sudo systemctl disable systemd-resolved.service

# Validar, habilitar e iniciar o serviço
sudo unbound-checkconf
sudo systemctl enable unbound
sudo systemctl restart unbound
sudo unbound-control-setup
sudo systemctl restart unbound
sudo unbound-control reload

# Configurar o servidor para usar o DNS local
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
echo "nameserver ::1" | sudo tee -a /etc/resolv.conf
```

### 2. Sistema de Proteção Contra Abusos

O sistema de proteção monitora o tráfego DNS para identificar e bloquear automaticamente tentativas de abuso, com recursos avançados de detecção e análise.

```bash
# Instalar o sistema de proteção
sudo chmod +x ./install/dns-protection-setup.sh
sudo ./install/dns-protection-setup.sh
```

Este script configura:
- Monitoramento de tráfego DNS com dnstop
- Detecção de requisições abusivas com análise inteligente
- Sistema de whitelist para IPs confiáveis
- Detecção de tunneling DNS através de análise de entropia
- Detecção de ataques baseados em consultas NXDomain
- Alertas precoces antes de atingir limites críticos
- Integração com Fail2ban para bloqueio automático
- Serviço systemd para execução contínua

#### Recursos Avançados de Proteção

##### Análise Automática de Tráfego
```bash
# Analisa o tráfego atual por 5 minutos e sugere configurações ideais
sudo /opt/dns-protection/dns-monitor.sh --analyze
```

##### Configuração Interativa
```bash
# Interface interativa para ajuste de parâmetros
sudo /opt/dns-protection/dns-monitor.sh --config
```

##### Whitelist de IPs Confiáveis
```bash
# Editar a lista de IPs e redes confiáveis que nunca serão bloqueados
sudo nano /opt/dns-protection/config/whitelist.txt
```

##### Modo de Teste
```bash
# Executa o monitoramento sem banir IPs (útil para ajustar configurações)
sudo /opt/dns-protection/dns-monitor.sh --test
```

Para verificar o status da proteção:
```bash
sudo systemctl status dns-protection
sudo fail2ban-client status dns-abuse
```

### 3. Sistema de Monitoramento

```bash
# Instalar o zabbix-sender para o seu sistema operacional
## Para Debian 10/11/12
sudo wget https://repo.zabbix.com/zabbix/6.4/debian/pool/main/z/zabbix-release/zabbix-release_6.4-1+debian$(lsb_release -rs)_all.deb
sudo dpkg -i zabbix-release_6.4-1+debian$(lsb_release -rs)_all.deb
sudo apt update
sudo apt install zabbix-sender

## Para Ubuntu 20.04/22.04/24.04
sudo wget https://repo.zabbix.com/zabbix/6.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.4-1+ubuntu$(lsb_release -rs)_all.deb
sudo dpkg -i zabbix-release_6.4-1+ubuntu$(lsb_release -rs)_all.deb
sudo apt update
sudo apt install zabbix-sender
```

Configurar os scripts de monitoramento:

```bash
# Copiar e configurar os scripts
sudo cp ./scripts/monitoring/*.sh /etc/unbound/
sudo chmod +x /etc/unbound/*.sh

# Configurar o agendamento com cron
sudo crontab -e

# Adicionar as linhas:
*/1 * * * * /etc/unbound/serverMonitoring.sh IP-DO-ZABBIX NOME-DO-HOST-DNS >/dev/null 2>&1
*/3 * * * * /etc/unbound/unboundMonitoring.sh IP-DO-ZABBIX NOME-DO-HOST-DNS >/dev/null 2>&1
```

#### Importação dos Templates

##### Zabbix
1. Acesse seu servidor Zabbix (5.4+)
2. Navegue até **Configuração** > **Templates**
3. Clique em **Importar**
4. Selecione o arquivo `templates/zabbix/dns-server-template.yaml`
5. Confirme a importação

##### Grafana
1. Acesse seu servidor Grafana (10.2.1+)
2. Navegue até **Dashboards** > **Import**
3. Clique em **Upload JSON file**
4. Selecione o arquivo `templates/grafana/dns-monitoring-dashboard.json`
5. Selecione o datasource do Zabbix que contém os dados do servidor DNS
6. Clique em **Import**

## Verificação e Solução de Problemas

### Verificar Status dos Serviços
```bash
# Status do servidor DNS
systemctl status unbound

# Status da proteção contra abusos
systemctl status dns-protection

# Listar IPs bloqueados
fail2ban-client status dns-abuse

# Visualizar logs do sistema de proteção
tail -f /var/log/dns-abuse.log
```

### Verificar Funcionamento do DNS
```bash
# Testar resolução de nomes
dig @127.0.0.1 google.com

# Verificar estatísticas do servidor
unbound-control stats
```

### Problemas Comuns

| Problema | Solução |
|----------|---------|
| Falha na inicialização do Unbound | Verifique erros em `/var/log/syslog` ou execute `unbound-checkconf` |
| Alto uso de CPU | Ajuste o valor de `num-threads` de acordo com o número de CPUs |
| Baixo desempenho de cache | Aumente os valores de `rrset-cache-size` e `msg-cache-size` |
| Falsos positivos no sistema de proteção | Use `/opt/dns-protection/dns-monitor.sh --analyze` para encontrar configurações ideais ou adicione IPs à whitelist |
| Bloqueio de clientes legítimos | Adicione seus IPs confiáveis em `/opt/dns-protection/config/whitelist.txt` |

## Documentação Adicional

Para informações mais detalhadas sobre o sistema de proteção DNS, consulte:

- **Guia Rápido**: `docs/dns-protection-quickstart.md`
- **Guia Técnico**: `docs/dns-protection-technical-guide.md`

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE.md para detalhes.

## Créditos

Desenvolvido pela TriplePlay Network - [www.tripleplay.network](https://www.tripleplay.network)