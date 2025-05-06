# Super DNS Recursivo - Project Structure

This document provides an overview of the project's directory structure and file organization.

## Directory Structure

```
super-dns-recursivo/
├── README.md              # Main project documentation
├── conf/                  # Configuration files
│   ├── unbound.conf       # Main Unbound DNS server configuration
│   └── fail2ban/          # Fail2ban configurations for DNS abuse protection
│       ├── dns-abuse-jail.conf
│       └── dns-abuse.conf
├── docs/                  # Documentation files
│   ├── README.md          # Documentation index
│   ├── dns-protection-quickstart.md
│   ├── dns-protection-technical-guide.md
│   ├── dns-auto-adjusting-system.md  # Auto-adjusting system documentation
│   └── project-structure.md         # This file
├── install/               # Installation scripts
│   ├── dns-protection-setup.sh
│   ├── unbound-setup.sh
│   └── systemd/           # Systemd service files
│       ├── dns-metrics-exporter.service
│       └── dns-monitor.service
├── scripts/               # Operational scripts
│   └── monitoring/        # Monitoring scripts
│       ├── advanced-monitoring-setup.sh
│       ├── dns-anomaly-detector.py
│       ├── dns-metrics-exporter.sh
│       ├── dns-monitor.sh
│       ├── serverMonitoring.sh
│       └── unboundMonitoring.sh
└── templates/             # Templates for monitoring systems
    ├── grafana/
    │   └── dns-monitoring-dashboard.json
    └── zabbix/
        └── dns-server-template.yaml
```

## Key Components

### Configuration Files

- `conf/unbound.conf`: Main configuration for the Unbound DNS server
- `conf/fail2ban/`: Configuration files for the Fail2ban integration that handles blocking abusive IP addresses

### Installation Scripts

- `install/dns-protection-setup.sh`: Main installation script for the DNS protection system
- `install/unbound-setup.sh`: Setup script specifically for Unbound DNS server

### Monitoring Scripts

- `scripts/monitoring/dns-monitor.sh`: Core monitoring script that detects and responds to DNS abuse
- `scripts/monitoring/advanced-monitoring-setup.sh`: Setup for advanced monitoring features
- `scripts/monitoring/serverMonitoring.sh` & `unboundMonitoring.sh`: Collect server and Unbound statistics

### Templates

- `templates/grafana/dns-monitoring-dashboard.json`: Grafana dashboard for visualizing DNS metrics
- `templates/zabbix/dns-server-template.yaml`: Zabbix template for monitoring the DNS server

## Best Practices

1. **Relative Paths**: All scripts should use relative paths instead of absolute paths for better portability across different installations

2. **Configuration Location**: User-specific configurations should be stored in `/opt/dns-protection/config/` to allow for persistence across updates

3. **Logs**: All system logs are written to standard locations:
   - DNS abuse detection logs: `/var/log/dns-abuse.log`
   - Monitoring logs: `/var/log/dns-monitoring.log`

4. **Auto-Adjusting System**: The system is designed to automatically adjust to any environment size, not just specific client counts. Use the `--analyze` option with monitoring scripts to optimize for your specific deployment.