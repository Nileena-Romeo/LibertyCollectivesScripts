# WebSphere Liberty Collective - Reusable Assets

## Overview

This collection provides comprehensive tools and documentation for troubleshooting and managing WebSphere Liberty Collective environments. These assets are designed to help support engineers and administrators quickly diagnose and resolve common collective-related issues.

## Contents

1. **LibertyCollectiveTroubleshootingGuide.md** - Comprehensive troubleshooting guide
2. **LibertyCollectiveDiagnostics.py** - Python-based diagnostic automation tool
3. **liberty_collective_quick_check.sh** - Shell script for quick health checks
4. **LIBERTY_COLLECTIVE_README.md** - This file

---

## Quick Start

### Prerequisites

- WebSphere Liberty 8.5.5 or later
- Python 3.6+ (for Python diagnostics tool)
- Bash shell (for shell script)
- Administrative access to Liberty servers

### Basic Usage

#### 1. Quick Health Check (Shell Script)

```bash
# Make script executable
chmod +x liberty_collective_quick_check.sh

# Check local controller
./liberty_collective_quick_check.sh \
  -w /opt/IBM/WebSphere/Liberty \
  -s controller1

# Check member with controller connectivity test
./liberty_collective_quick_check.sh \
  -w /opt/IBM/WebSphere/Liberty \
  -s member1 \
  -c controller.example.com \
  -p 9443

# Full check with admin credentials
./liberty_collective_quick_check.sh \
  -w /opt/IBM/WebSphere/Liberty \
  -s controller1 \
  -u admin \
  -P password \
  -v
```

#### 2. Comprehensive Diagnostics (Python Tool)

```bash
# Basic diagnostics
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home /opt/IBM/WebSphere/Liberty \
  --server controller1

# With controller connectivity test
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home /opt/IBM/WebSphere/Liberty \
  --server member1 \
  --controller-host controller.example.com \
  --controller-port 9443

# Collect support data
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home /opt/IBM/WebSphere/Liberty \
  --server controller1 \
  --collect-support-data \
  --output-dir /tmp/support_data

# Verbose mode
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home /opt/IBM/WebSphere/Liberty \
  --server controller1 \
  --verbose
```

---

## Common Use Cases

### Use Case 1: Controller Not Starting

**Problem:** Collective controller fails to start

**Solution Steps:**

1. Run quick check:
```bash
./liberty_collective_quick_check.sh -w $WLP_HOME -s controller1 -v
```

2. Check the output for:
   - Port conflicts
   - Certificate issues
   - Configuration errors

3. Review the troubleshooting guide section: "Controller Not Starting"

4. Common fixes:
```bash
# Check if ports are in use
netstat -an | grep 9443

# Verify certificates
keytool -list -keystore $WLP_HOME/usr/servers/controller1/resources/security/key.p12 \
  -storepass Liberty -storetype PKCS12

# Check logs
tail -f $WLP_HOME/usr/servers/controller1/logs/messages.log
```

### Use Case 2: Member Cannot Join Collective

**Problem:** Member registration fails with authentication or connectivity errors

**Solution Steps:**

1. Test connectivity from member to controller:
```bash
./liberty_collective_quick_check.sh \
  -w $WLP_HOME \
  -s member1 \
  -c controller.example.com \
  -p 9443
```

2. Run full diagnostics:
```bash
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home $WLP_HOME \
  --server member1 \
  --controller-host controller.example.com
```

3. Common fixes:
```bash
# Remove and re-join member
$WLP_HOME/bin/collective remove controller1 \
  --host=member.example.com \
  --server=member1 \
  --user=admin \
  --password=password

$WLP_HOME/bin/collective join member1 \
  --host=controller.example.com \
  --port=9443 \
  --user=admin \
  --password=password \
  --keystorePassword=Liberty
```

### Use Case 3: Certificate Expiration

**Problem:** SSL certificate has expired or is about to expire

**Solution Steps:**

1. Check certificate status:
```bash
./liberty_collective_quick_check.sh -w $WLP_HOME -s controller1
```

2. Regenerate certificates:
```bash
# Backup existing certificates
cp -r $WLP_HOME/usr/servers/controller1/resources/security \
     $WLP_HOME/usr/servers/controller1/resources/security.backup

# Generate new certificate
$WLP_HOME/bin/securityUtility createSSLCertificate \
  --server=controller1 \
  --password=Liberty

# Update collective
$WLP_HOME/bin/collective updateHost controller1 \
  --host=$(hostname) \
  --user=admin \
  --password=password

# Restart server
$WLP_HOME/bin/server restart controller1
```

### Use Case 4: Performance Issues

**Problem:** Collective operations are slow or timing out

**Solution Steps:**

1. Collect comprehensive diagnostics:
```bash
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home $WLP_HOME \
  --server controller1 \
  --collect-support-data \
  --verbose
```

2. Review the generated report for:
   - Thread pool exhaustion
   - Memory issues
   - Network latency

3. Apply tuning recommendations from the troubleshooting guide

### Use Case 5: Collecting Support Data for IBM

**Problem:** Need to open a PMR with IBM Support

**Solution Steps:**

1. Collect comprehensive support data:
```bash
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home $WLP_HOME \
  --server controller1 \
  --collect-support-data \
  --output-dir /tmp/ibm_support_data
```

2. The tool will create:
   - Server dump (heap, thread, system)
   - Configuration files
   - Diagnostic results in JSON format
   - Comprehensive report

3. Compress and upload to IBM:
```bash
cd /tmp
tar -czf support_data_$(date +%Y%m%d).tar.gz ibm_support_data/
```

---

## Troubleshooting Guide Reference

The **LibertyCollectiveTroubleshootingGuide.md** contains detailed information on:

### Common Issues
- Controller not starting
- Member registration failures
- SSL/TLS certificate issues
- Collective operations timeout
- Admin Center not accessible

### Diagnostic Commands
- Health check commands
- Log collection
- Certificate management

### Log Analysis
- Key error messages and codes
- Log patterns to search
- Error code reference table

### Configuration Validation
- Controller configuration checklist
- Member configuration checklist
- Required features

### Network and Connectivity
- Port requirements
- Firewall rules
- DNS resolution

### Security and Certificates
- Certificate renewal process
- Trust store management

### Performance Issues
- Thread pool tuning
- Memory configuration
- Monitoring commands

---

## Error Code Quick Reference

| Error Code | Description | Quick Fix |
|------------|-------------|-----------|
| CWWKX0202E | Member registration failed | Check credentials and certificates |
| CWWKX0112E | Operation timeout | Increase timeout, check network |
| CWPKI0823E | Certificate validation failed | Import controller cert to member trust store |
| CWWKX0116E | Member not found | Re-register member |
| CWWKX0213E | Controller not available | Start controller, verify network |
| CWWKS1100A | Authentication failed | Verify user credentials |
| CWWKO0219I | TCP Channel started | Normal - port is listening |

---

## Best Practices

### 1. Regular Health Checks

Schedule regular health checks using the quick check script:

```bash
# Add to crontab for daily checks
0 2 * * * /path/to/liberty_collective_quick_check.sh \
  -w /opt/IBM/WebSphere/Liberty \
  -s controller1 >> /var/log/liberty_health.log 2>&1
```

### 2. Certificate Management

- Monitor certificate expiration dates
- Renew certificates at least 30 days before expiration
- Keep backups of certificate stores
- Document certificate passwords securely

### 3. Log Retention

- Rotate logs regularly to prevent disk space issues
- Keep at least 7 days of logs for troubleshooting
- Archive logs before major changes

### 4. Documentation

- Document your collective topology
- Keep inventory of all controllers and members
- Document custom configurations
- Maintain runbooks for common issues

### 5. Backup and Recovery

```bash
# Backup controller configuration
tar -czf controller_backup_$(date +%Y%m%d).tar.gz \
  $WLP_HOME/usr/servers/controller1/

# Backup certificates
tar -czf certs_backup_$(date +%Y%m%d).tar.gz \
  $WLP_HOME/usr/servers/*/resources/security/
```

---

## Advanced Usage

### Custom Diagnostic Checks

You can extend the Python diagnostics tool with custom checks:

```python
from LibertyCollectiveDiagnostics import LibertyCollectiveDiagnostics

# Initialize
diag = LibertyCollectiveDiagnostics('/opt/IBM/WebSphere/Liberty', 'controller1')

# Run specific checks
diag.check_server_status()
diag.check_certificates()
diag.analyze_logs(log_type='messages', lines=500)

# Generate custom report
diag.generate_report('custom_report.txt')
```

### Automated Remediation

Create automated remediation scripts:

```bash
#!/bin/bash
# auto_remediate.sh

# Check if server is down
if ! ./liberty_collective_quick_check.sh -w $WLP_HOME -s controller1 | grep -q "RUNNING"; then
    echo "Server is down, attempting restart..."
    $WLP_HOME/bin/server start controller1
    
    # Wait and verify
    sleep 10
    if ./liberty_collective_quick_check.sh -w $WLP_HOME -s controller1 | grep -q "RUNNING"; then
        echo "Server successfully restarted"
    else
        echo "Server restart failed, escalating..."
        # Send alert
    fi
fi
```

### Integration with Monitoring Tools

Export diagnostics data for monitoring systems:

```bash
# Export to JSON for monitoring tools
python3 LibertyCollectiveDiagnostics.py \
  --wlp-home $WLP_HOME \
  --server controller1 > diagnostics.json

# Parse and send to monitoring system
# (integrate with your monitoring solution)
```

---

## Troubleshooting the Tools

### Python Script Issues

**Problem:** Import errors

```bash
# Install required packages
pip3 install --user pathlib

# For XML security (recommended)
pip3 install --user defusedxml
```

**Problem:** Permission denied

```bash
# Make script executable
chmod +x LibertyCollectiveDiagnostics.py

# Run with appropriate user
sudo -u wasadmin python3 LibertyCollectiveDiagnostics.py ...
```

### Shell Script Issues

**Problem:** Command not found

```bash
# Ensure script is executable
chmod +x liberty_collective_quick_check.sh

# Run with bash explicitly
bash liberty_collective_quick_check.sh ...
```

**Problem:** Network tools missing

```bash
# Install required tools (RHEL/CentOS)
yum install nc netstat

# Install required tools (Ubuntu/Debian)
apt-get install netcat net-tools
```

---

## Support and Feedback

### Getting Help

1. Review the troubleshooting guide first
2. Run diagnostics and collect logs
3. Check IBM Knowledge Center
4. Open PMR with IBM Support if needed

### Reporting Issues

When reporting issues with these tools:

1. Provide tool version
2. Include error messages
3. Attach diagnostic output
4. Describe expected vs actual behavior

### Contributing

To improve these assets:

1. Document new use cases
2. Add error codes and solutions
3. Share automation scripts
4. Report bugs or enhancement requests

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-04-11 | Initial release |

---

## Additional Resources

### IBM Documentation
- [Liberty Collective Overview](https://www.ibm.com/docs/en/was-liberty/base?topic=liberty-administering-collectives)
- [Collective Commands Reference](https://www.ibm.com/docs/en/was-liberty/base?topic=line-collective-commands)
- [Security Configuration](https://www.ibm.com/docs/en/was-liberty/base?topic=liberty-securing-collectives)

### IBM Support
- [IBM Support Portal](https://www.ibm.com/mysupport)
- [Fix Central](https://www.ibm.com/support/fixcentral)
- [Knowledge Center](https://www.ibm.com/docs/en/was-liberty)

### Community Resources
- [Liberty Dev Community](https://openliberty.io/)
- [Stack Overflow - WebSphere Liberty](https://stackoverflow.com/questions/tagged/websphere-liberty)

---

