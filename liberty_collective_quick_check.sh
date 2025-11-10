#!/bin/bash
################################################################################
# WebSphere Liberty Collective Quick Check Script
#
# This script performs quick health checks and diagnostics for Liberty
# Collective environments.
#
# Author: IBM Support
# Version: 1.0
# Date: 2025-04-11
################################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
WLP_HOME=""
SERVER_NAME=""
CONTROLLER_HOST=""
CONTROLLER_PORT="9443"
ADMIN_USER=""
ADMIN_PASSWORD=""
VERBOSE=false

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[VERBOSE] $1${NC}"
    fi
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

WebSphere Liberty Collective Quick Check Script

OPTIONS:
    -w, --wlp-home PATH         WebSphere Liberty installation directory (required)
    -s, --server NAME           Liberty server name (required)
    -c, --controller HOST       Collective controller hostname
    -p, --port PORT             Controller HTTPS port (default: 9443)
    -u, --user USERNAME         Admin username
    -P, --password PASSWORD     Admin password
    -v, --verbose               Enable verbose output
    -h, --help                  Display this help message

EXAMPLES:
    # Check local server status
    $0 -w /opt/IBM/WebSphere/Liberty -s controller1

    # Check member connectivity to controller
    $0 -w /opt/IBM/WebSphere/Liberty -s member1 \\
       -c controller.example.com -u admin -P password

    # Verbose mode
    $0 -w /opt/IBM/WebSphere/Liberty -s controller1 -v

EOF
    exit 1
}

################################################################################
# Validation Functions
################################################################################

validate_wlp_home() {
    if [ ! -d "$WLP_HOME" ]; then
        print_error "Liberty home directory not found: $WLP_HOME"
        exit 1
    fi
    
    if [ ! -f "$WLP_HOME/bin/server" ]; then
        print_error "Liberty server script not found: $WLP_HOME/bin/server"
        exit 1
    fi
    
    print_success "Liberty home directory validated: $WLP_HOME"
}

validate_server() {
    local server_dir="$WLP_HOME/usr/servers/$SERVER_NAME"
    
    if [ ! -d "$server_dir" ]; then
        print_error "Server directory not found: $server_dir"
        exit 1
    fi
    
    if [ ! -f "$server_dir/server.xml" ]; then
        print_warning "server.xml not found in $server_dir"
    fi
    
    print_success "Server directory validated: $server_dir"
}

################################################################################
# Check Functions
################################################################################

check_server_status() {
    print_header "Checking Server Status"
    
    local status_output
    status_output=$("$WLP_HOME/bin/server" status "$SERVER_NAME" 2>&1)
    local status_rc=$?
    
    log_verbose "Status command output: $status_output"
    
    if echo "$status_output" | grep -q "is running"; then
        print_success "Server $SERVER_NAME is RUNNING"
        
        # Get PID if available
        local pid=$(echo "$status_output" | grep -oP 'process id: \K\d+' || echo "")
        if [ -n "$pid" ]; then
            print_info "Process ID: $pid"
            
            # Check memory usage
            if command -v ps &> /dev/null; then
                local mem_usage=$(ps -p "$pid" -o %mem --no-headers 2>/dev/null || echo "N/A")
                print_info "Memory usage: ${mem_usage}%"
            fi
        fi
        return 0
    else
        print_error "Server $SERVER_NAME is NOT RUNNING"
        return 1
    fi
}

check_ports() {
    print_header "Checking Port Configuration"
    
    local server_xml="$WLP_HOME/usr/servers/$SERVER_NAME/server.xml"
    
    if [ ! -f "$server_xml" ]; then
        print_warning "server.xml not found, skipping port check"
        return 1
    fi
    
    # Extract HTTP and HTTPS ports
    local http_port=$(grep -oP 'httpPort="\K\d+' "$server_xml" | head -1)
    local https_port=$(grep -oP 'httpsPort="\K\d+' "$server_xml" | head -1)
    
    if [ -n "$http_port" ]; then
        print_info "HTTP Port: $http_port"
        check_port_listening "$http_port" "HTTP"
    fi
    
    if [ -n "$https_port" ]; then
        print_info "HTTPS Port: $https_port"
        check_port_listening "$https_port" "HTTPS"
    fi
}

check_port_listening() {
    local port=$1
    local port_name=$2
    
    if command -v netstat &> /dev/null; then
        if netstat -an | grep -q ":$port.*LISTEN"; then
            print_success "$port_name port $port is LISTENING"
        else
            print_error "$port_name port $port is NOT LISTENING"
        fi
    elif command -v ss &> /dev/null; then
        if ss -an | grep -q ":$port.*LISTEN"; then
            print_success "$port_name port $port is LISTENING"
        else
            print_error "$port_name port $port is NOT LISTENING"
        fi
    elif command -v lsof &> /dev/null; then
        if lsof -i ":$port" -sTCP:LISTEN &> /dev/null; then
            print_success "$port_name port $port is LISTENING"
        else
            print_error "$port_name port $port is NOT LISTENING"
        fi
    else
        print_warning "No network tools available to check port $port"
    fi
}

check_collective_type() {
    print_header "Checking Collective Configuration"
    
    local server_xml="$WLP_HOME/usr/servers/$SERVER_NAME/server.xml"
    
    if [ ! -f "$server_xml" ]; then
        print_warning "server.xml not found"
        return 1
    fi
    
    local is_controller=false
    local is_member=false
    
    if grep -q "collectiveController" "$server_xml"; then
        is_controller=true
        print_success "Server is configured as COLLECTIVE CONTROLLER"
    fi
    
    if grep -q "collectiveMember" "$server_xml"; then
        is_member=true
        print_success "Server is configured as COLLECTIVE MEMBER"
        
        # Extract controller information
        local controller_host=$(grep -oP '<controllerHost>\K[^<]+' "$server_xml" || echo "")
        local controller_port=$(grep -oP '<controllerHttpsPort>\K[^<]+' "$server_xml" || echo "")
        
        if [ -n "$controller_host" ]; then
            print_info "Configured Controller Host: $controller_host"
        fi
        if [ -n "$controller_port" ]; then
            print_info "Configured Controller Port: $controller_port"
        fi
    fi
    
    if [ "$is_controller" = false ] && [ "$is_member" = false ]; then
        print_warning "Server is NOT configured for collective"
    fi
}

check_certificates() {
    print_header "Checking SSL Certificates"
    
    local keystore="$WLP_HOME/usr/servers/$SERVER_NAME/resources/security/key.p12"
    
    if [ ! -f "$keystore" ]; then
        print_warning "Keystore not found: $keystore"
        return 1
    fi
    
    print_success "Keystore found: $keystore"
    
    # Check certificate validity using keytool
    if command -v keytool &> /dev/null; then
        local cert_info=$(keytool -list -v -keystore "$keystore" -storepass Liberty -storetype PKCS12 2>/dev/null || echo "")
        
        if [ -n "$cert_info" ]; then
            # Extract validity dates
            local valid_from=$(echo "$cert_info" | grep -oP 'Valid from: \K.*?(?= until)' | head -1)
            local valid_until=$(echo "$cert_info" | grep -oP 'until: \K.*' | head -1)
            
            if [ -n "$valid_from" ]; then
                print_info "Certificate Valid From: $valid_from"
            fi
            if [ -n "$valid_until" ]; then
                print_info "Certificate Valid Until: $valid_until"
                
                # Check if certificate is expiring soon (within 30 days)
                if command -v date &> /dev/null; then
                    local expiry_epoch=$(date -d "$valid_until" +%s 2>/dev/null || echo "0")
                    local current_epoch=$(date +%s)
                    local days_until_expiry=$(( ($expiry_epoch - $current_epoch) / 86400 ))
                    
                    if [ "$days_until_expiry" -lt 0 ]; then
                        print_error "Certificate has EXPIRED!"
                    elif [ "$days_until_expiry" -lt 30 ]; then
                        print_warning "Certificate expires in $days_until_expiry days"
                    else
                        print_success "Certificate is valid for $days_until_expiry days"
                    fi
                fi
            fi
        else
            print_warning "Could not read certificate information"
        fi
    else
        print_warning "keytool not found, skipping certificate validation"
    fi
}

check_logs() {
    print_header "Analyzing Recent Logs"
    
    local messages_log="$WLP_HOME/usr/servers/$SERVER_NAME/logs/messages.log"
    
    if [ ! -f "$messages_log" ]; then
        print_warning "messages.log not found"
        return 1
    fi
    
    print_success "Log file found: $messages_log"
    
    # Count recent errors and warnings (last 100 lines)
    local error_count=$(tail -100 "$messages_log" | grep -c " E " || echo "0")
    local warning_count=$(tail -100 "$messages_log" | grep -c " W " || echo "0")
    local collective_errors=$(tail -100 "$messages_log" | grep -c "CWWKX" || echo "0")
    local cert_errors=$(tail -100 "$messages_log" | grep -c "CWPKI" || echo "0")
    
    print_info "Recent Errors (last 100 lines): $error_count"
    print_info "Recent Warnings (last 100 lines): $warning_count"
    
    if [ "$collective_errors" -gt 0 ]; then
        print_warning "Collective-related errors found: $collective_errors"
        echo -e "\nRecent collective errors:"
        tail -100 "$messages_log" | grep "CWWKX" | tail -5
    fi
    
    if [ "$cert_errors" -gt 0 ]; then
        print_warning "Certificate-related errors found: $cert_errors"
        echo -e "\nRecent certificate errors:"
        tail -100 "$messages_log" | grep "CWPKI" | tail -5
    fi
    
    if [ "$error_count" -eq 0 ] && [ "$warning_count" -eq 0 ]; then
        print_success "No recent errors or warnings found"
    fi
}

test_controller_connectivity() {
    print_header "Testing Controller Connectivity"
    
    if [ -z "$CONTROLLER_HOST" ]; then
        print_warning "Controller host not specified, skipping connectivity test"
        return 0
    fi
    
    print_info "Testing connection to $CONTROLLER_HOST:$CONTROLLER_PORT"
    
    # Test TCP connectivity
    if command -v nc &> /dev/null; then
        if nc -z -w5 "$CONTROLLER_HOST" "$CONTROLLER_PORT" 2>/dev/null; then
            print_success "TCP connection to controller successful"
        else
            print_error "Cannot establish TCP connection to controller"
            return 1
        fi
    elif command -v telnet &> /dev/null; then
        if timeout 5 telnet "$CONTROLLER_HOST" "$CONTROLLER_PORT" 2>&1 | grep -q "Connected"; then
            print_success "TCP connection to controller successful"
        else
            print_error "Cannot establish TCP connection to controller"
            return 1
        fi
    else
        print_warning "No network testing tools available (nc or telnet)"
    fi
    
    # Test HTTPS connectivity
    if command -v curl &> /dev/null; then
        local url="https://$CONTROLLER_HOST:$CONTROLLER_PORT/ibm/api/collective/v1/status"
        print_info "Testing HTTPS endpoint: $url"
        
        local curl_output=$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null || echo "000")
        
        if [ "$curl_output" = "200" ] || [ "$curl_output" = "401" ]; then
            print_success "HTTPS endpoint is accessible (HTTP $curl_output)"
        else
            print_error "HTTPS endpoint not accessible (HTTP $curl_output)"
        fi
    fi
}

list_collective_members() {
    print_header "Listing Collective Members"
    
    if [ -z "$ADMIN_USER" ] || [ -z "$ADMIN_PASSWORD" ]; then
        print_warning "Admin credentials not provided, skipping member list"
        return 0
    fi
    
    if [ ! -f "$WLP_HOME/bin/collective" ]; then
        print_warning "collective command not found"
        return 1
    fi
    
    print_info "Querying collective members..."
    
    local list_output=$("$WLP_HOME/bin/collective" list "$SERVER_NAME" \
        --user="$ADMIN_USER" --password="$ADMIN_PASSWORD" 2>&1 || echo "")
    
    if echo "$list_output" | grep -q "CWWKX"; then
        print_error "Error listing collective members"
        log_verbose "$list_output"
    else
        echo "$list_output"
    fi
}

################################################################################
# Main Execution
################################################################################

main() {
    print_header "WebSphere Liberty Collective Quick Check"
    
    # Validate inputs
    validate_wlp_home
    validate_server
    
    # Run checks
    check_server_status
    check_ports
    check_collective_type
    check_certificates
    check_logs
    
    # Optional checks
    if [ -n "$CONTROLLER_HOST" ]; then
        test_controller_connectivity
    fi
    
    if [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASSWORD" ]; then
        list_collective_members
    fi
    
    print_header "Quick Check Complete"
    print_info "For detailed diagnostics, use LibertyCollectiveDiagnostics.py"
}

################################################################################
# Parse Command Line Arguments
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        -w|--wlp-home)
            WLP_HOME="$2"
            shift 2
            ;;
        -s|--server)
            SERVER_NAME="$2"
            shift 2
            ;;
        -c|--controller)
            CONTROLLER_HOST="$2"
            shift 2
            ;;
        -p|--port)
            CONTROLLER_PORT="$2"
            shift 2
            ;;
        -u|--user)
            ADMIN_USER="$2"
            shift 2
            ;;
        -P|--password)
            ADMIN_PASSWORD="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required parameters
if [ -z "$WLP_HOME" ] || [ -z "$SERVER_NAME" ]; then
    echo "Error: Missing required parameters"
    usage
fi

# Run main function
main

exit 0


