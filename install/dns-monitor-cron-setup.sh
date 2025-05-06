#!/bin/bash
#
# Setup script for DNS monitoring system
#

# Create cron job file
echo "*/5 * * * * root $(dirname $(dirname $(realpath $0)))/scripts/monitoring/dns-monitor.sh >> /var/log/dns-monitoring.log 2>&1" > /etc/cron.d/dns-monitoring

# Set appropriate permissions
chmod 644 /etc/cron.d/dns-monitoring

echo "Installation complete: DNS monitoring script will run every 5 minutes."
echo "To configure the monitoring parameters, run:"
echo "  sudo $(dirname $(dirname $(realpath $0)))/scripts/monitoring/dns-monitor.sh --config"
echo
echo "To test the monitoring system, run:"
echo "  sudo $(dirname $(dirname $(realpath $0)))/scripts/monitoring/dns-monitor.sh --test"