# Documentação do Super DNS Recursivo

Este diretório contém a documentação completa para instalação, configuração e manutenção do servidor Super DNS Recursivo, incluindo o sistema de proteção contra abusos.

## Índice

1. [Instalação do Servidor Unbound](#instalação-do-servidor-unbound)
2. [Sistema de Proteção contra Abusos](#sistema-de-proteção-contra-abusos)
3. [Configuração de Monitoramento](#configuração-de-monitoramento)
4. [Solução de Problemas](#solução-de-problemas)

## Instalação do Servidor Unbound

O Super DNS Recursivo é baseado no servidor Unbound, um resolvedor DNS validador, recursivo e com cache de alto desempenho. Para instalar o servidor:

```bash
chmod +x ../install/unbound-setup.sh
sudo ../install/unbound-setup.sh
```

O script de instalação configura automaticamente:
- Otimizações de desempenho com base no número de CPUs
- Configuração de DNSSEC
- Ferramentas de estatísticas e controle

## Sistema de Proteção contra Abusos

O sistema de proteção contra abusos monitora o tráfego DNS e identifica automaticamente IPs que excedem limites de requisições, aplicando bloqueios através do Fail2ban.

### Instalação

```bash
chmod +x ../install/dns-protection-setup.sh
sudo ../install/dns-protection-setup.sh
```

### Documentação Detalhada

- [Guia de Início Rápido](dns-protection-quickstart.md)
- [Guia Técnico Completo](dns-protection-technical-guide.md)

## Configuração de Monitoramento

O Super DNS Recursivo inclui integração com Zabbix para monitoramento completo do servidor e do serviço DNS.

### Configuração do Monitoramento

1. Configure os scripts de monitoramento:
```bash
sudo cp ../scripts/monitoring/*.sh /etc/unbound/
sudo chmod +x /etc/unbound/*.sh
```

2. Configure o cron para executar os scripts:
```bash
sudo crontab -e

# Adicione as linhas:
*/1 * * * * /etc/unbound/serverMonitoring.sh IP-DO-ZABBIX NOME-DO-HOST-DNS >/dev/null 2>&1
*/3 * * * * /etc/unbound/unboundMonitoring.sh IP-DO-ZABBIX NOME-DO-HOST-DNS >/dev/null 2>&1
```

3. Importe os templates de monitoramento:
   - **Zabbix**: Importe o arquivo `../templates/ZABBIX-TEMPLATE.yaml`
   - **Grafana**: Importe o arquivo `../templates/GRAFANA-TEMPLATE.json`

## Solução de Problemas

### Verificação de Status

```bash
# Verificar status do servidor DNS
systemctl status unbound

# Verificar estatísticas do Unbound
unbound-control stats

# Verificar status da proteção contra abusos
systemctl status dns-protection

# Verificar IPs banidos
fail2ban-client status dns-abuse
```

### Problemas Comuns

1. **Falha na resolução DNS**:
   - Verifique se o servidor Unbound está em execução
   - Verifique as permissões dos arquivos de configuração
   - Verifique os logs: `journalctl -u unbound`

2. **Alto uso de CPU**:
   - Ajuste o parâmetro `num-threads` na configuração
   - Verifique se o servidor está sofrendo ataque de DoS
   - Verifique se o sistema de proteção está funcionando corretamente

3. **Falsos positivos no sistema de proteção**:
   - Aumente o valor de `MAX_RPS` em `/opt/dns-protection/dns-monitor.sh`
   - Adicione IPs confiáveis à lista `ignoreip` em `/etc/fail2ban/jail.d/dns-abuse.conf`