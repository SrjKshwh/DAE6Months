#!/bin/bash

# Wazuh Custom Alert Rules Setup Script for Parrot OS
# This script creates and deploys 3 custom alert rules for security events

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to create custom alert rules
create_custom_rules() {
    log "Creating custom Wazuh alert rules..."

    # Create local rules directory if it doesn't exist
    sudo mkdir -p /var/ossec/etc/rules

    # Create custom rules file
    sudo tee /var/ossec/etc/rules/local_rules.xml << 'EOF'
<!-- Custom Security Alert Rules for Incident Response -->
<group name="custom_security_rules">

  <!-- Rule 1: Failed SSH Authentication Attempts -->
  <rule id="100001" level="10" frequency="5" timeframe="600">
    <if_sid>5710</if_sid>
    <match>Failed password</match>
    <description>Multiple failed SSH authentication attempts detected</description>
    <group>authentication_failures,brute_force</group>
  </rule>

  <!-- Rule 2: Suspicious File Access Patterns -->
  <rule id="100002" level="12">
    <if_sid>550</if_sid>
    <match>access|read|write|modify</match>
    <description>Suspicious file access detected on sensitive system files</description>
    <group>file_access,policy_violation</group>
  </rule>

  <!-- Rule 3: Network Anomaly Detection -->
  <rule id="100003" level="8">
    <if_sid>530</if_sid>
    <match>connection refused|timeout|unreachable</match>
    <description>Network connection anomalies detected</description>
    <group>network,anomaly</group>
  </rule>

  <!-- Advanced Rule: Brute Force Attack Pattern -->
  <rule id="100004" level="15">
    <if_sid>100001</if_sid>
    <match>invalid user</match>
    <timeframe>300</timeframe>
    <frequency>3</frequency>
    <description>Brute force attack with invalid usernames detected</description>
    <group>brute_force,authentication_failures,critical</group>
  </rule>

  <!-- Advanced Rule: Privilege Escalation Attempt -->
  <rule id="100005" level="13">
    <if_sid>100002</if_sid>
    <match>/etc/sudoers|/etc/passwd|/etc/shadow</match>
    <description>Attempted access to privilege escalation files</description>
    <group>privilege_escalation,file_access,critical</group>
  </rule>

  <!-- Advanced Rule: Suspicious External Connections -->
  <rule id="100006" level="11">
    <if_sid>100003</if_sid>
    <srcip>!192.168.0.0/16</srcip>
    <description>Suspicious external network connections</description>
    <group>network,external_threat</group>
  </rule>

</group>
EOF

    success "Custom alert rules created"
}

# Function to test alert rules
test_alert_rules() {
    log "Testing custom alert rules..."

    # Test Rule 1: Failed SSH Authentication
    echo "Testing Rule 100001 - Failed SSH Authentication..."
    logger -p auth.warning "Failed password for invalid user test from 192.168.1.100 port 22 ssh2"

    # Test Rule 2: Suspicious File Access
    echo "Testing Rule 100002 - Suspicious File Access..."
    logger -p auth.info "Access to sensitive file /etc/passwd detected"

    # Test Rule 3: Network Anomaly
    echo "Testing Rule 100003 - Network Anomaly..."
    logger -p daemon.warning "iptables blocked suspicious connection from 10.0.0.1"

    success "Alert rule tests completed"
}

# Function to verify rules deployment
verify_rules() {
    log "Verifying alert rules deployment..."

    # Check if rules file exists
    if [ -f "/var/ossec/etc/rules/local_rules.xml" ]; then
        success "Custom rules file exists"
    else
        error "Custom rules file not found"
        return 1
    fi

    # Validate XML syntax
    if command -v xmllint >/dev/null 2>&1; then
        if xmllint --noout /var/ossec/etc/rules/local_rules.xml 2>/dev/null; then
            success "XML syntax is valid"
        else
            error "XML syntax validation failed"
            return 1
        fi
    else
        warning "xmllint not available for XML validation"
    fi

    # Test rules loading
    if sudo /var/ossec/bin/ossec-logtest -f /var/ossec/etc/rules/local_rules.xml >/dev/null 2>&1; then
        success "Rules load successfully"
    else
        error "Rules failed to load"
        return 1
    fi

    success "Alert rules verification completed"
}

# Function to restart Wazuh services
restart_services() {
    log "Restarting Wazuh services..."

    sudo systemctl restart wazuh-manager
    sudo systemctl restart wazuh-agent

    # Wait for services to start
    sleep 5

    # Verify services are running
    if sudo systemctl is-active --quiet wazuh-manager; then
        success "Wazuh manager restarted successfully"
    else
        error "Wazuh manager failed to restart"
        return 1
    fi

    if sudo systemctl is-active --quiet wazuh-agent; then
        success "Wazuh agent restarted successfully"
    else
        error "Wazuh agent failed to restart"
        return 1
    fi
}

# Function to monitor alerts
monitor_alerts() {
    log "Monitoring alerts (checking last 10 entries)..."

    if [ -f "/var/ossec/logs/alerts/alerts.log" ]; then
        echo "Recent alerts:"
        tail -10 /var/ossec/logs/alerts/alerts.log | grep -E "(100001|100002|100003|100004|100005|100006)" || echo "No custom rule alerts found yet"
    else
        warning "Alerts log not found"
    fi
}

# Function to create documentation
create_documentation() {
    log "Creating alert rules documentation..."

    cat > ~/wazuh_custom_rules_README.md << 'EOF'
# Wazuh Custom Alert Rules Documentation

## Overview
This document describes the 3 custom alert rules implemented for enhanced security monitoring in the Incident Response environment.

## Custom Alert Rules

### Rule 100001: Failed SSH Authentication Attempts (Level 10)
**Purpose**: Detect multiple failed SSH login attempts that may indicate brute force attacks.

**Trigger Conditions**:
- Base rule: 5710 (SSH authentication failure)
- Match: "Failed password"
- Frequency: 5 attempts within 600 seconds (10 minutes)

**Alert Level**: 10 (Medium severity)
**Groups**: authentication_failures, brute_force

**Example Log**:
```
Failed password for invalid user test from 192.168.1.100 port 22 ssh2
```

### Rule 100002: Suspicious File Access Patterns (Level 12)
**Purpose**: Detect unauthorized access to sensitive system files.

**Trigger Conditions**:
- Base rule: 550 (File access)
- Match: "access|read|write|modify"
- Applied to sensitive system files

**Alert Level**: 12 (High severity)
**Groups**: file_access, policy_violation

**Example Log**:
```
Access to sensitive file /etc/passwd detected
```

### Rule 100003: Network Anomaly Detection (Level 8)
**Purpose**: Identify unusual network connection patterns and failures.

**Trigger Conditions**:
- Base rule: 530 (Network event)
- Match: "connection refused|timeout|unreachable"

**Alert Level**: 8 (Low severity)
**Groups**: network, anomaly

**Example Log**:
```
iptables blocked suspicious connection from 10.0.0.1
```

## Advanced Rules

### Rule 100004: Brute Force Attack Pattern (Level 15)
**Purpose**: Detect sophisticated brute force attacks using invalid usernames.

**Trigger Conditions**:
- Base rule: 100001
- Match: "invalid user"
- Frequency: 3 attempts within 300 seconds (5 minutes)

**Alert Level**: 15 (Critical severity)
**Groups**: brute_force, authentication_failures, critical

### Rule 100005: Privilege Escalation Attempt (Level 13)
**Purpose**: Detect attempts to access privilege escalation files.

**Trigger Conditions**:
- Base rule: 100002
- Match: "/etc/sudoers|/etc/passwd|/etc/shadow"

**Alert Level**: 13 (High severity)
**Groups**: privilege_escalation, file_access, critical

### Rule 100006: Suspicious External Connections (Level 11)
**Purpose**: Monitor suspicious connections from external IP addresses.

**Trigger Conditions**:
- Base rule: 100003
- Source IP: Not in 192.168.0.0/16 range

**Alert Level**: 11 (Medium severity)
**Groups**: network, external_threat

## Testing the Rules

Run the setup script to test all rules:
```bash
sudo ./wazuh_alert_rules.sh
```

## Monitoring Alerts

Check alerts in real-time:
```bash
tail -f /var/ossec/logs/alerts/alerts.log
```

## Integration with GRC Portal

These rules integrate with the GRC Portal's incident detection system:
- Alerts are automatically correlated with other security events
- Incident severity is calculated based on alert levels
- Timeline analysis includes alert data
- Automated response actions can be triggered

## Maintenance

- Review and update rules quarterly
- Monitor false positive rates
- Adjust thresholds based on environment
- Update documentation when rules are modified
EOF

    success "Documentation created: ~/wazuh_custom_rules_README.md"
}

# Main function
main() {
    echo "Wazuh Custom Alert Rules Setup Script"
    echo "===================================="

    create_custom_rules
    test_alert_rules
    verify_rules
    restart_services
    monitor_alerts
    create_documentation

    success "Wazuh custom alert rules setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Monitor alerts: tail -f /var/ossec/logs/alerts/alerts.log"
    echo "2. Review documentation: cat ~/wazuh_custom_rules_README.md"
    echo "3. Test rules manually by generating test events"
    echo "4. Integrate with GRC Portal incident detection"
}

# Run main function
main "$@"