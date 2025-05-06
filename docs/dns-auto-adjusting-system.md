# DNS Auto-Adjusting System

This document explains the auto-adjusting capabilities of the Super DNS Recursivo system, which automatically adapts to any network size.

## Auto-Adjusting System Overview

The system monitoring includes advanced self-tuning features that allow it to automatically adapt to the specific characteristics of your network. The configurations are:

1. **Persistent** - Saved in `/opt/dns-protection/config/dns-monitor.conf`
2. **Adaptive** - Automatically adjusted based on traffic analysis
3. **Configurable** - Can be manually adjusted when needed

### Default Initial Values

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| MAX_RPS | Auto-detected | Requests per second threshold (auto-calculated based on network size) |
| MONITOR_INTERVAL | 45 | Monitoring interval in seconds |
| ALERT_THRESHOLD | 90 | Alert percentage threshold before taking action |
| QUERY_ENTROPY_THRESHOLD | 4.0 | Fine-tuned to accept more legitimate subdomains |
| MAX_NX_DOMAIN_PERCENT | 40 | Maximum percentage of NXDomain queries |
| MAX_CLIENTS_PER_IP | 50 | Considers corporate NATs and public Wi-Fi networks |
| BANTIME | Dynamic | Between 30-90 minutes (1800-5400 seconds) randomly to prevent attack patterns |

### How Auto-Adjustment Works

The system can be run in `--analyze` mode, which:

1. Monitors DNS traffic for 5 minutes
2. Calculates maximum and average RPS detected
3. Suggests optimized settings based on collected data
4. Ensures suggested values are not below recommended minimums
5. Allows you to accept the suggested settings
6. Saves the configuration to the configuration file for future use

This process should be run:
- During initial installation
- After significant client base growth
- When traffic patterns change (e.g., after implementing new services)

## Using the Auto-Adjusting System

### 1. Traffic Analysis and Automatic Adjustment

To analyze traffic and receive configuration suggestions:

```bash
sudo scripts/monitoring/dns-monitor.sh --analyze
```

The script monitors your DNS traffic for 5 minutes and suggests optimized configurations based on your actual network traffic, while ensuring appropriate minimum values.

### 2. Interactive Manual Configuration

To manually adjust parameters:

```bash
sudo scripts/monitoring/dns-monitor.sh --config
```

This option allows you to interactively adjust all parameters and save the configurations.

### 3. Monitoring with Current Settings

To start monitoring using current settings (normal mode):

```bash
sudo scripts/monitoring/dns-monitor.sh
```

### 4. Testing Without Banning

To test detection without actually banning IPs:

```bash
sudo scripts/monitoring/dns-monitor.sh --test
```

## Advanced Monitoring

The `advanced-monitoring-setup.sh` script configures complementary tools for:

1. **Gradual Analysis with iptables** - Multi-level monitoring (1000 req/s and 2500 req/s)
2. **Data Collection** - Setting up vnstat and atop for performance analysis
3. **Periodic Capture** - Automatic DNS traffic sampling during peak hours

To configure these additional tools:

```bash
sudo scripts/monitoring/advanced-monitoring-setup.sh
```

## Recommendations for ISPs

1. **Periodic Analysis** - Run `--analyze` monthly to adjust settings as your client base evolves

2. **Connection Monitoring** - Regularly check the actual number of simultaneous connections:
   ```bash
   conntrack -L | awk '{print $4}' | sort | uniq -c
   ```

3. **Whitelist for Shared NATs** - Add large corporate or institutional NATs to the whitelist