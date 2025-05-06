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
# git clone https://github.com/flicl/super-dns-recursivo.git
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

- **Análise e configuração automática**: Execute `sudo /opt/dns-protection/dns-monitor.sh --analyze` para avaliar o tráfego e receber recomendações de configuração
- **Configuração interativa**: Execute `sudo /opt/dns-protection/dns-monitor.sh --config` para ajustar parâmetros interativamente
- **Lista de IPs confiáveis**: Edite o arquivo `/opt/dns-protection/config/whitelist.txt` para adicionar IPs e redes que nunca devem ser bloqueados

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

# Executar em modo de teste (sem banir IPs)
sudo /opt/dns-protection/dns-monitor.sh --test
```

## Estrutura da Solução

- **Script de monitoramento**: `/opt/dns-protection/dns-monitor.sh`
- **Logs de abuso**: `/var/log/dns-abuse.log`
- **Configuração Fail2ban**: `/etc/fail2ban/jail.d/dns-abuse.conf`
- **Filtro Fail2ban**: `/etc/fail2ban/filter.d/dns-abuse.conf`
- **Lista de IPs confiáveis**: `/opt/dns-protection/config/whitelist.txt`

## Solução de Problemas Comuns

- **Alto uso de CPU**: Aumente `MONITOR_INTERVAL` via modo de configuração interativa
- **Falsos positivos**: Execute a análise de tráfego para ajustar parâmetros automaticamente ou adicione IPs à lista de confiáveis
- **Fail2ban não está banindo**: Verifique os logs em `/var/log/fail2ban.log`

## Documentação Detalhada

Consulte o guia técnico completo para informações detalhadas sobre instalação manual, personalização avançada e solução de problemas:

`/opt/dns-protection/docs/dns-protection-technical-guide.md`