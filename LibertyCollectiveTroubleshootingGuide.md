# WebSphere Liberty Collective Troubleshooting Guide

## Table of Contents
1. [Common Issues and Solutions](#common-issues-and-solutions)
2. [Diagnostic Commands](#diagnostic-commands)
3. [Log Analysis](#log-analysis)
4. [Configuration Validation](#configuration-validation)
5. [Network and Connectivity](#network-and-connectivity)
6. [Security and Certificates](#security-and-certificates)
7. [Performance Issues](#performance-issues)
8. [Quick Reference](#quick-reference)

---

## Common Issues and Solutions

### 1. Controller Not Starting

**Symptoms:**
- Controller server fails to start
- Error messages in messages.log
- Collective operations fail

**Common Causes & Solutions:**

```bash
# Check if ports are already in use
netstat -an | grep <https_port>
lsof -i :<https_port>

# Verify server.xml configuration
grep -A 10 "collectiveController" ${WLP_HOME}/usr/servers/<controller>/server.xml

# Check for certificate issues
keytool -list -keystore ${WLP_HOME}/usr/servers/<controller>/resources/security/key.p12 -storepass <password>
```

**Resolution Steps:**
1. Verify port availability
2. Check certificate validity
3. Validate server.xml syntax
4. Review messages.log for specific errors
5. Ensure proper file permissions

### 2. Member Registration Failures

**Symptoms:**
- Members cannot join collective
- "CWWKX0202E" error in logs
- Authentication failures

**Diagnostic Commands:**

```bash
# Test connectivity from member to controller
curl -k https://<controller_host>:<https_port>/ibm/api/collective/v1/status

# Check member configuration
cat ${WLP_HOME}/usr/servers/<member>/server.xml | grep -A 5 "collectiveMember"

# Verify credentials
${WLP_HOME}/bin/collective join <member> \
  --host=<controller_host> \
  --port=<https_port> \
  --user=<admin_user> \
  --password=<admin_password> \
  --keystorePassword=<keystore_password>
```

**Common Fixes:**
- Regenerate certificates
- Verify network connectivity
- Check firewall rules
- Validate admin credentials
- Ensure time synchronization across servers

### 3. SSL/TLS Certificate Issues

**Symptoms:**
- "CWPKI0823E" certificate validation errors
- SSL handshake failures
- Trust store issues

**Resolution:**

```bash
# Export controller certificate
keytool -export -alias default \
  -keystore ${WLP_HOME}/usr/servers/<controller>/resources/security/key.p12 \
  -storepass <password> \
  -file controller_cert.cer

# Import into member trust store
keytool -import -alias controller_cert \
  -keystore ${WLP_HOME}/usr/servers/<member>/resources/security/trust.p12 \
  -storepass <password> \
  -file controller_cert.cer -noprompt

# Verify certificate chain
openssl s_client -connect <controller_host>:<https_port> -showcerts
```

### 4. Collective Operations Timeout

**Symptoms:**
- Operations hang or timeout
- "CWWKX0112E" timeout errors
- Slow response from Admin Center

**Troubleshooting:**

```bash
# Check network latency
ping <controller_host>
traceroute <controller_host>

# Increase timeout values in server.xml
<collectiveController>
  <timeout>300s</timeout>
</collectiveController>

# Monitor thread pools
${WLP_HOME}/bin/server dump <controller> --include=thread

# Check for resource constraints
top -p $(pgrep -f <controller>)
```

### 5. Admin Center Not Accessible

**Symptoms:**
- Cannot access Admin Center UI
- 404 or 500 errors
- Login failures

**Resolution Steps:**

```bash
# Verify adminCenter feature is enabled
grep "adminCenter-1.0" ${WLP_HOME}/usr/servers/<controller>/server.xml

# Check HTTPS port configuration
grep "httpsPort" ${WLP_HOME}/usr/servers/<controller>/server.xml

# Verify user registry configuration
grep -A 10 "basicRegistry" ${WLP_HOME}/usr/servers/<controller>/server.xml

# Test authentication
curl -k -u <admin_user>:<admin_password> \
  https://<controller_host>:<https_port>/adminCenter/
```

---

## Diagnostic Commands

### Health Check Commands

```bash
# Check controller status
${WLP_HOME}/bin/server status <controller>

# List all collective members
${WLP_HOME}/bin/collective list <controller> \
  --user=<admin_user> --password=<admin_password>

# Get detailed member information
${WLP_HOME}/bin/collective describe <controller> \
  --host=<member_host> --server=<member_name> \
  --user=<admin_user> --password=<admin_password>

# Test collective connectivity
${WLP_HOME}/bin/collective ping <controller> \
  --host=<member_host> --server=<member_name> \
  --user=<admin_user> --password=<admin_password>
```

### Log Collection

```bash
# Collect server dump
${WLP_HOME}/bin/server dump <server_name> --archive=server_dump.zip

# Collect specific traces
${WLP_HOME}/bin/server dump <server_name> \
  --include=heap,thread,system

# Enable trace for collective operations
# Add to server.xml:
<logging traceSpecification="com.ibm.ws.collective.*=all:com.ibm.ws.security.*=all"/>

# Tail logs in real-time
tail -f ${WLP_HOME}/usr/servers/<server>/logs/messages.log
tail -f ${WLP_HOME}/usr/servers/<server>/logs/trace.log
```

### Certificate Management

```bash
# List certificates in keystore
keytool -list -v \
  -keystore ${WLP_HOME}/usr/servers/<server>/resources/security/key.p12 \
  -storepass <password>

# Check certificate expiration
keytool -list -v \
  -keystore ${WLP_HOME}/usr/servers/<server>/resources/security/key.p12 \
  -storepass <password> | grep -A 2 "Valid"

# Regenerate collective certificates
${WLP_HOME}/bin/collective updateHost <controller> \
  --host=<new_hostname> \
  --user=<admin_user> --password=<admin_password>
```

---

## Log Analysis

### Key Error Messages

| Error Code | Description | Common Cause | Solution |
|------------|-------------|--------------|----------|
| CWWKX0202E | Member registration failed | Authentication issue | Verify credentials and certificates |
| CWWKX0112E | Operation timeout | Network latency | Increase timeout, check network |
| CWPKI0823E | Certificate validation failed | Trust store issue | Import controller cert to member |
| CWWKX0116E | Member not found | Member removed/offline | Re-register member |
| CWWKX0213E | Controller not available | Controller down | Start controller, check network |

### Log Patterns to Search

```bash
# Find authentication errors
grep "CWWKS" ${WLP_HOME}/usr/servers/<server>/logs/messages.log

# Find collective-specific errors
grep "CWWKX" ${WLP_HOME}/usr/servers/<server>/logs/messages.log

# Find SSL/certificate errors
grep "CWPKI" ${WLP_HOME}/usr/servers/<server>/logs/messages.log

# Find timeout issues
grep -i "timeout" ${WLP_HOME}/usr/servers/<server>/logs/messages.log

# Find connection refused errors
grep -i "connection refused" ${WLP_HOME}/usr/servers/<server>/logs/messages.log
```

---

## Configuration Validation

### Controller Configuration Checklist

```xml
<!-- Minimum required features -->
<featureManager>
    <feature>collectiveController-1.0</feature>
    <feature>adminCenter-1.0</feature>
    <feature>restConnector-2.0</feature>
    <feature>ssl-1.0</feature>
</featureManager>

<!-- HTTPS endpoint -->
<httpEndpoint id="defaultHttpEndpoint"
              host="*"
              httpsPort="9443">
    <tcpOptions soReuseAddr="true"/>
</httpEndpoint>

<!-- Collective controller configuration -->
<collectiveController>
    <timeout>300s</timeout>
</collectiveController>

<!-- User registry -->
<basicRegistry id="basic" realm="BasicRealm">
    <user name="admin" password="{xor}Lz4sLCgwLTs="/>
</basicRegistry>

<!-- Administrator role -->
<administrator-role>
    <user>admin</user>
</administrator-role>

<!-- Keystore configuration -->
<keyStore id="defaultKeyStore" password="{xor}Lz4sLCgwLTs="/>
```

### Member Configuration Checklist

```xml
<!-- Minimum required features -->
<featureManager>
    <feature>collectiveMember-1.0</feature>
    <feature>ssl-1.0</feature>
</featureManager>

<!-- HTTPS endpoint -->
<httpEndpoint id="defaultHttpEndpoint"
              host="*"
              httpsPort="9443">
    <tcpOptions soReuseAddr="true"/>
</httpEndpoint>

<!-- Collective member configuration -->
<collectiveMember>
    <controllerHost>controller.example.com</controllerHost>
    <controllerHttpsPort>9443</controllerHttpsPort>
</collectiveMember>

<!-- Keystore configuration -->
<keyStore id="defaultKeyStore" password="{xor}Lz4sLCgwLTs="/>
```

---

## Network and Connectivity

### Port Requirements

| Port | Protocol | Purpose | Direction |
|------|----------|---------|-----------|
| 9443 | HTTPS | Admin Center, REST API | Controller ← Member |
| 9080 | HTTP | Optional HTTP endpoint | Bidirectional |

### Firewall Rules

```bash
# Allow HTTPS traffic to controller
iptables -A INPUT -p tcp --dport 9443 -j ACCEPT

# Test connectivity
telnet <controller_host> 9443
nc -zv <controller_host> 9443

# Test SSL handshake
openssl s_client -connect <controller_host>:9443 -tls1_2
```

### DNS Resolution

```bash
# Verify hostname resolution
nslookup <controller_host>
dig <controller_host>

# Check /etc/hosts entries
cat /etc/hosts | grep <controller_host>

# Test reverse DNS
nslookup <controller_ip>
```

---

## Security and Certificates

### Certificate Renewal Process

```bash
# Step 1: Backup existing certificates
cp -r ${WLP_HOME}/usr/servers/<server>/resources/security \
      ${WLP_HOME}/usr/servers/<server>/resources/security.backup

# Step 2: Generate new certificates
${WLP_HOME}/bin/securityUtility createSSLCertificate \
  --server=<server> \
  --password=<keystore_password>

# Step 3: Update collective with new certificates
${WLP_HOME}/bin/collective updateHost <controller> \
  --host=<hostname> \
  --user=<admin_user> --password=<admin_password>

# Step 4: Restart servers
${WLP_HOME}/bin/server stop <server>
${WLP_HOME}/bin/server start <server>
```

### Trust Store Management

```bash
# Export all certificates from controller
keytool -exportcert -alias default \
  -keystore ${WLP_HOME}/usr/servers/<controller>/resources/security/key.p12 \
  -storepass <password> \
  -file controller.cer

# Import to all members
for member in member1 member2 member3; do
  keytool -importcert -alias controller \
    -keystore ${WLP_HOME}/usr/servers/${member}/resources/security/trust.p12 \
    -storepass <password> \
    -file controller.cer -noprompt
done
```

---

## Performance Issues

### Thread Pool Tuning

```xml
<!-- Increase executor thread pool -->
<executor name="LibertyExecutor"
          coreThreads="50"
          maxThreads="100"
          keepAlive="60s"
          stealPolicy="STRICT"
          rejectedWorkPolicy="CALLER_RUNS"/>
```

### Memory Configuration

```bash
# Set JVM heap size in jvm.options
echo "-Xms512m" >> ${WLP_HOME}/usr/servers/<server>/jvm.options
echo "-Xmx2048m" >> ${WLP_HOME}/usr/servers/<server>/jvm.options
echo "-XX:MaxMetaspaceSize=512m" >> ${WLP_HOME}/usr/servers/<server>/jvm.options

# Enable GC logging
echo "-Xverbosegclog:${WLP_HOME}/usr/servers/<server>/logs/gc.log" >> \
  ${WLP_HOME}/usr/servers/<server>/jvm.options
```

### Monitoring Commands

```bash
# Monitor JVM memory
jstat -gc $(pgrep -f <server>) 1000

# Monitor threads
jstack $(pgrep -f <server>) > thread_dump.txt

# Monitor network connections
netstat -an | grep <https_port>

# Check file descriptors
lsof -p $(pgrep -f <server>) | wc -l
```

---

## Quick Reference

### Emergency Recovery Steps

1. **Controller Down:**
   ```bash
   ${WLP_HOME}/bin/server start <controller>
   tail -f ${WLP_HOME}/usr/servers/<controller>/logs/messages.log
   ```

2. **Member Cannot Connect:**
   ```bash
   # Remove member
   ${WLP_HOME}/bin/collective remove <controller> \
     --host=<member_host> --server=<member> \
     --user=<admin_user> --password=<admin_password>
   
   # Re-join member
   ${WLP_HOME}/bin/collective join <member> \
     --host=<controller_host> --port=9443 \
     --user=<admin_user> --password=<admin_password>
   ```

3. **Certificate Expired:**
   ```bash
   ${WLP_HOME}/bin/securityUtility createSSLCertificate \
     --server=<server> --password=<password>
   ${WLP_HOME}/bin/server restart <server>
   ```

### Useful REST API Endpoints

```bash
# Get collective status
curl -k -u admin:password \
  https://<controller>:9443/ibm/api/collective/v1/status

# List members
curl -k -u admin:password \
  https://<controller>:9443/ibm/api/collective/v1/hosts

# Get member details
curl -k -u admin:password \
  https://<controller>:9443/ibm/api/collective/v1/hosts/<host>/servers/<server>
```

### Support Data Collection

```bash
# Collect all diagnostic data
${WLP_HOME}/bin/server dump <server> --archive=support_data.zip \
  --include=heap,thread,system

# Collect logs
tar -czf logs_$(date +%Y%m%d_%H%M%S).tar.gz \
  ${WLP_HOME}/usr/servers/<server>/logs/

# Collect configuration
tar -czf config_$(date +%Y%m%d_%H%M%S).tar.gz \
  ${WLP_HOME}/usr/servers/<server>/*.xml \
  ${WLP_HOME}/usr/servers/<server>/jvm.options \
  ${WLP_HOME}/usr/servers/<server>/bootstrap.properties
```

---

## Additional Resources

- IBM Knowledge Center: https://www.ibm.com/docs/en/was-liberty
- Liberty Collective Documentation: https://www.ibm.com/docs/en/was-liberty/base?topic=liberty-administering-collectives
- Support Portal: https://www.ibm.com/mysupport

---

**Last Updated:** 2025-04-11
**Version:** 1.0