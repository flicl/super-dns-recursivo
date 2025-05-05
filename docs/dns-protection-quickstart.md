# Guia Rápido de Implementação: Proteção DNS com dnstop e Fail2ban

Este guia apresenta o procedimento simplificado para implementar a proteção do servidor DNS Unbound contra abusos, utilizando dnstop para monitoramento e Fail2ban para bloqueio automático.

## Instalação em 4 Passos

### 1. Verificar Pré-requisitos

Certifique-se de que o Unbound está corretamente instalado e funcionando:

```bash
systemctl status unbound
```

### 2. Instalar Script de Proteção

```bash
# Baixar o script (se necessário) para o diretório atual
# git clone https://seu-repositorio.git
# cd seu-repositorio

# Tornar executável
chmod +x dns-protection-setup.sh

# Executar instalação (necessário privilégios de root)
sudo ./dns-protection-setup.sh
```

### 3. Verificar Instalação

```bash
# Verificar o status do serviço de proteção
sudo systemctl status dns-protection

# Verificar configuração do Fail2ban
sudo fail2ban-client status dns-abuse
```

### 4. Personalizar (Opcional)

Ajuste os parâmetros principais conforme necessário:

- **Limite de requisições**: Altere o valor de `MAX_RPS` em `/opt/dns-protection/dns-monitor.sh`
- **Tempo de banimento**: Altere o valor de `bantime` em `/etc/fail2ban/jail.d/dns-abuse.conf`
- **IPs a serem ignorados**: Adicione IPs confiáveis em `/etc/fail2ban/jail.d/dns-abuse.conf`

## Comandos Úteis

```bash
# Verificar logs de detecção
sudo tail -f /var/log/dns-abuse.log

# Ver IPs banidos
sudo fail2ban-client status dns-abuse

# Desbanir um IP manualmente
sudo fail2ban-client set dns-abuse unbanip IP_ADDRESS

# Reiniciar proteção após modificações
sudo systemctl restart dns-protection
sudo systemctl restart fail2ban
```

## Estrutura da Solução

- **Script de monitoramento**: `/opt/dns-protection/dns-monitor.sh`
- **Logs de abuso**: `/var/log/dns-abuse.log`
- **Configuração Fail2ban**: `/etc/fail2ban/jail.d/dns-abuse.conf`
- **Filtro Fail2ban**: `/etc/fail2ban/filter.d/dns-abuse.conf`

## Solução de Problemas Comuns

- **Alto uso de CPU**: Aumente `MONITOR_INTERVAL` no script principal
- **Falsos positivos**: Aumente o valor de `MAX_RPS` ou adicione IPs à lista `ignoreip`
- **Fail2ban não está banindo**: Verifique os logs em `/var/log/fail2ban.log`

## Documentação Detalhada

Consulte o guia técnico completo para informações detalhadas sobre instalação manual, personalização avançada e solução de problemas:

`/opt/dns-protection/docs/dns-protection-technical-guide.md`