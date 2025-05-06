#!/bin/bash
#
# dns-security-integration.sh - DNS Security Integration for Monitoring
#
# This script monitors the logs of Fail2ban and provides advanced security integration
# for DNS protection systems
#

# Configuration
LOG_FILE="/var/log/dns-abuse.log"
JAIL_LOG="/var/log/fail2ban.log"
CONFIG_DIR="$(dirname "$(readlink -f "$0")")/../../config"
SECURITY_CONFIG="$CONFIG_DIR/dns-security.conf"
LAST_BAN_FILE="/tmp/last_ban_processed"
MAX_ACTIONS_PER_RUN=5  # Limit of actions per execution to avoid overload

# Load configuration if exists
if [ -f "$SECURITY_CONFIG" ]; then
    source "$SECURITY_CONFIG"
fi

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs to be run as root"
    exit 1
fi

# Function to display help messages
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --config      Configure security parameters"
    echo "  --test        Test the security integration"
    echo "  --debug       Display debug messages"
    echo "  --dryrun      Run without sending actual commands"
    echo "  --help        Display this help message"
    echo
    exit 0
}

# Flow control variables
CONFIG_MODE=false
TEST_MODE=false
DEBUG_MODE=false
DRYRUN_MODE=false

# Process command line arguments
for arg in "$@"; do
    case $arg in
        --config)
            CONFIG_MODE=true
            ;;
        --test)
            TEST_MODE=true
            ;;
        --debug)
            DEBUG_MODE=true
            ;;
        --dryrun)
            DRYRUN_MODE=true
            ;;
        --help)
            show_help
            ;;
    esac
done

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" | tee -a /var/log/dns-security.log
}

# Function for interactive configuration
configure() {
    echo "DNS Security Integration Configuration"
    echo "-------------------------------------------------------------------"
    echo
    
    # Configuration for advanced security options
    read -p "Maximum actions per run (current: $MAX_ACTIONS_PER_RUN): " new_max
    if [ ! -z "$new_max" ]; then
        MAX_ACTIONS_PER_RUN=$new_max
    fi
    
    # Save configuration
    mkdir -p $CONFIG_DIR
    cat > $SECURITY_CONFIG << EOF
# DNS Security Integration Configuration - $(date)
MAX_ACTIONS_PER_RUN=$MAX_ACTIONS_PER_RUN
EOF
    
    chmod 600 $SECURITY_CONFIG  # Protect the config file
    
    echo
    echo "Configuration saved in $SECURITY_CONFIG"
}

# Function to test security integration
test_security() {
    log_message "INFO" "Testing DNS security integration"
    
    # Check if Fail2ban is running and properly configured
    if systemctl is-active --quiet fail2ban; then
        log_message "INFO" "Fail2ban is running correctly"
        
        # Test if DNS abuse jail exists
        if fail2ban-client status | grep -q "dns-abuse"; then
            log_message "INFO" "DNS abuse jail is properly configured"
            echo "DNS security integration test: SUCCESS"
        else
            log_message "ERROR" "DNS abuse jail not found in Fail2ban"
            echo "DNS security integration test: FAIL - dns-abuse jail not found"
            echo "Please check your Fail2ban configuration."
        fi
    else
        log_message "ERROR" "Fail2ban is not running"
        echo "DNS security integration test: FAIL - Fail2ban not running"
    fi
}

# Function to process bans and take action
process_bans() {
    local last_processed=0
    local action_count=0
    
    # Get the last processed timestamp
    if [ -f "$LAST_BAN_FILE" ]; then
        last_processed=$(cat "$LAST_BAN_FILE")
    fi
    
    current_time=$(date +%s)
    
    log_message "INFO" "Looking for recent bans (since $last_processed)"
    
    # Process logs to find recently banned IPs
    while read line; do
        if [[ "$line" =~ \[([0-9\-]+\ [0-9\:]+)\].*\[ALERTA\].*IP=([0-9\.]+).* ]]; then
            timestamp=$(date -d "${BASH_REMATCH[1]}" +%s)
            ip="${BASH_REMATCH[2]}"
            
            # Check if this ban is more recent than the last processed
            if [ "$timestamp" -gt "$last_processed" ] && [ "$action_count" -lt "$MAX_ACTIONS_PER_RUN" ]; then
                log_message "INFO" "Processing ban for IP $ip (timestamp: $timestamp)"
                
                # Check if the IP is still banned by Fail2ban
                if fail2ban-client status dns-abuse | grep -q "$ip"; then
                    # Add additional security actions here
                    log_message "ACTION" "Security action taken for IP $ip"
                    
                    # Example: Log to syslog for SIEM integration
                    logger -t dns-security "Security action: IP $ip banned for DNS abuse"
                    
                    action_count=$((action_count + 1))
                else
                    log_message "INFO" "IP $ip not banned anymore, ignoring"
                fi
            fi
        fi
    done < <(grep -E "\[ALERTA\] Abuso de DNS detectado - IP=[0-9\.]+" "$LOG_FILE")
    
    # Update the last processed timestamp
    echo "$current_time" > "$LAST_BAN_FILE"
    
    log_message "INFO" "Processing complete. $action_count security actions taken."
}

# Main function
main() {
    # Check special modes
    if $CONFIG_MODE; then
        configure
        exit 0
    fi
    
    if $TEST_MODE; then
        test_security
        exit 0
    fi
    
    # Normal operation: process bans and take actions
    process_bans
}

# Start processing
main