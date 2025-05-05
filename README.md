# Super DNS Recursivo

Servidor DNS Recursivo com proteção contra abusos, monitoramento via Zabbix e visualização pelo Grafana.

## Estrutura do Projeto

```
/
├── docs/                     # Documentação completa
│   ├── dns-protection/       # Documentação da proteção contra abusos
│   └── README.md             # Documentação principal
├── install/                  # Scripts de instalação
│   ├── dns-protection-setup.sh    # Instalador da proteção contra abusos
│   └── unbound-setup.sh      # Instalador do servidor DNS Unbound
├── conf/                     # Arquivos de configuração
│   ├── unbound.conf          # Configuração principal do Unbound
│   └── fail2ban/             # Configurações do Fail2ban
├── scripts/                  # Scripts de monitoramento e utilitários
│   ├── monitoring/           # Scripts de monitoramento para Zabbix
│   └── dns-monitor.sh        # Script de monitoramento de abusos DNS
└── templates/                # Templates de monitoramento
    ├── GRAFANA-TEMPLATE.json # Template para o Grafana
    └── ZABBIX-TEMPLATE.yaml  # Template para o Zabbix
```

## Proteção contra Abusos DNS

Este repositório inclui um sistema completo de proteção contra ataques de negação de serviço e uso abusivo em servidores DNS Unbound, utilizando:

- **dnstop** para monitoramento de tráfego DNS em tempo real
- **Fail2ban** para banimento automático de IPs abusivos
- Scripts personalizados para detecção de padrões de abuso

Para mais detalhes, consulte a [documentação completa da proteção DNS](/docs/dns-protection-technical-guide.md).

## Instalação

### 1. Servidor DNS Unbound

Para instalar o servidor DNS Unbound com as configurações recomendadas:

```bash
chmod +x install/unbound-setup.sh
sudo ./install/unbound-setup.sh
```

### 2. Sistema de Proteção contra Abusos

Para instalar o sistema de proteção contra abusos:

```bash
chmod +x install/dns-protection-setup.sh
sudo ./install/dns-protection-setup.sh
```

### 3. Monitoramento (Opcional)

Para configurar o monitoramento via Zabbix:

```bash
# Configure os scripts de monitoramento
sudo cp scripts/monitoring/*.sh /etc/unbound/
sudo chmod +x /etc/unbound/*.sh

# Configure o cron para executar os scripts
sudo crontab -e

# Adicione as linhas:
*/1 * * * * /etc/unbound/serverMonitoring.sh IP-DO-ZABBIX NOME-DO-HOST-DNS >/dev/null 2>&1
*/3 * * * * /etc/unbound/unboundMonitoring.sh IP-DO-ZABBIX NOME-DO-HOST-DNS >/dev/null 2>&1
```

## Monitoramento

Importe os templates de monitoramento:

- **Zabbix**: Importe o arquivo `templates/ZABBIX-TEMPLATE.yaml`
- **Grafana**: Importe o arquivo `templates/GRAFANA-TEMPLATE.json`

## Documentação

Consulte a pasta `docs/` para documentação completa:

- [Guia de início rápido](/docs/dns-protection-quickstart.md)
- [Guia técnico completo](/docs/dns-protection-technical-guide.md)
- [Configuração do Unbound](/docs/README.md)

## Licença

Copyright (c) 2025 TriplePlay Network