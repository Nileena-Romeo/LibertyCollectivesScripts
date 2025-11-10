#!/usr/bin/env python3
"""
WebSphere Liberty Collective Diagnostics Utility

This script provides automated diagnostics and troubleshooting capabilities
for WebSphere Liberty Collective environments.

Author: IBM Support
Version: 1.0
Date: 2025-04-11
"""

import os
import sys
import json
import subprocess
import argparse
import logging
import socket
import ssl
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('liberty_collective_diagnostics.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class LibertyCollectiveDiagnostics:
    """Main class for Liberty Collective diagnostics"""
    
    def __init__(self, wlp_home: str, server_name: str):
        """
        Initialize diagnostics utility
        
        Args:
            wlp_home: WebSphere Liberty installation directory
            server_name: Name of the Liberty server
        """
        self.wlp_home = Path(wlp_home)
        self.server_name = server_name
        self.server_dir = self.wlp_home / 'usr' / 'servers' / server_name
        self.results = {}
        
        if not self.wlp_home.exists():
            raise ValueError(f"Liberty home directory not found: {wlp_home}")
        
        if not self.server_dir.exists():
            raise ValueError(f"Server directory not found: {self.server_dir}")
    
    def run_command(self, command: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """
        Execute a shell command and return results
        
        Args:
            command: Command to execute as list
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.wlp_home)
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            return -1, "", "Command timed out"
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return -1, "", str(e)
    
    def check_server_status(self) -> Dict:
        """Check Liberty server status"""
        logger.info(f"Checking status of server: {self.server_name}")
        
        server_script = self.wlp_home / 'bin' / 'server'
        rc, stdout, stderr = self.run_command([str(server_script), 'status', self.server_name])
        
        status = {
            'server_name': self.server_name,
            'running': 'is running' in stdout.lower(),
            'output': stdout,
            'error': stderr,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        self.results['server_status'] = status
        return status
    
    def check_ports(self) -> Dict:
        """Check if required ports are available and listening"""
        logger.info("Checking port availability")
        
        ports_to_check = self._get_configured_ports()
        port_status = {}
        
        for port_name, port_num in ports_to_check.items():
            try:
                # Check if port is listening
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('localhost', port_num))
                sock.close()
                
                port_status[port_name] = {
                    'port': port_num,
                    'listening': result == 0,
                    'status': 'LISTENING' if result == 0 else 'NOT LISTENING'
                }
            except Exception as e:
                port_status[port_name] = {
                    'port': port_num,
                    'listening': False,
                    'status': f'ERROR: {str(e)}'
                }
        
        self.results['port_status'] = port_status
        return port_status
    
    def _get_configured_ports(self) -> Dict[str, int]:
        """Extract configured ports from server.xml"""
        ports = {}
        server_xml = self.server_dir / 'server.xml'
        
        if not server_xml.exists():
            logger.warning(f"server.xml not found: {server_xml}")
            return ports
        
        try:
            tree = ET.parse(server_xml)
            root = tree.getroot()
            
            # Find httpEndpoint elements
            for endpoint in root.findall('.//httpEndpoint'):
                http_port = endpoint.get('httpPort')
                https_port = endpoint.get('httpsPort')
                
                if http_port:
                    ports['httpPort'] = int(http_port)
                if https_port:
                    ports['httpsPort'] = int(https_port)
        
        except Exception as e:
            logger.error(f"Error parsing server.xml: {e}")
        
        return ports
    
    def check_certificates(self) -> Dict:
        """Check SSL certificates validity"""
        logger.info("Checking SSL certificates")
        
        cert_info = {}
        keystore_path = self.server_dir / 'resources' / 'security' / 'key.p12'
        
        if not keystore_path.exists():
            cert_info['status'] = 'Keystore not found'
            cert_info['path'] = str(keystore_path)
            self.results['certificate_status'] = cert_info
            return cert_info
        
        # Use keytool to list certificates
        keytool_cmd = ['keytool', '-list', '-v', '-keystore', str(keystore_path), 
                       '-storepass', 'Liberty', '-storetype', 'PKCS12']
        
        rc, stdout, stderr = self.run_command(keytool_cmd)
        
        if rc == 0:
            cert_info['status'] = 'SUCCESS'
            cert_info['details'] = self._parse_certificate_info(stdout)
        else:
            cert_info['status'] = 'ERROR'
            cert_info['error'] = stderr
        
        self.results['certificate_status'] = cert_info
        return cert_info
    
    def _parse_certificate_info(self, keytool_output: str) -> List[Dict]:
        """Parse keytool output to extract certificate information"""
        certificates = []
        current_cert = {}
        
        for line in keytool_output.split('\n'):
            line = line.strip()
            
            if line.startswith('Alias name:'):
                if current_cert:
                    certificates.append(current_cert)
                current_cert = {'alias': line.split(':', 1)[1].strip()}
            
            elif line.startswith('Valid from:'):
                current_cert['validity'] = line.split(':', 1)[1].strip()
            
            elif line.startswith('Owner:'):
                current_cert['owner'] = line.split(':', 1)[1].strip()
        
        if current_cert:
            certificates.append(current_cert)
        
        return certificates
    
    def check_collective_configuration(self) -> Dict:
        """Check collective controller/member configuration"""
        logger.info("Checking collective configuration")
        
        config = {
            'type': None,
            'features': [],
            'configuration': {}
        }
        
        server_xml = self.server_dir / 'server.xml'
        
        if not server_xml.exists():
            config['error'] = 'server.xml not found'
            self.results['collective_config'] = config
            return config
        
        try:
            tree = ET.parse(server_xml)
            root = tree.getroot()
            
            # Check features
            feature_manager = root.find('.//featureManager')
            if feature_manager is not None:
                for feature in feature_manager.findall('feature'):
                    feature_text = feature.text
                    config['features'].append(feature_text)
                    
                    if 'collectiveController' in feature_text:
                        config['type'] = 'controller'
                    elif 'collectiveMember' in feature_text:
                        config['type'] = 'member'
            
            # Check collective controller configuration
            controller = root.find('.//collectiveController')
            if controller is not None:
                config['configuration']['controller'] = {
                    'timeout': controller.get('timeout', 'default')
                }
            
            # Check collective member configuration
            member = root.find('.//collectiveMember')
            if member is not None:
                config['configuration']['member'] = {
                    'controllerHost': member.findtext('controllerHost', 'not configured'),
                    'controllerHttpsPort': member.findtext('controllerHttpsPort', 'not configured')
                }
        
        except Exception as e:
            config['error'] = str(e)
            logger.error(f"Error parsing collective configuration: {e}")
        
        self.results['collective_config'] = config
        return config
    
    def analyze_logs(self, log_type: str = 'messages', lines: int = 100) -> Dict:
        """Analyze server logs for errors and warnings"""
        logger.info(f"Analyzing {log_type} log (last {lines} lines)")
        
        log_file = self.server_dir / 'logs' / f'{log_type}.log'
        
        if not log_file.exists():
            return {'error': f'Log file not found: {log_file}'}
        
        analysis = {
            'file': str(log_file),
            'errors': [],
            'warnings': [],
            'collective_errors': [],
            'certificate_errors': []
        }
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()[-lines:]
            
            for line in log_lines:
                line_lower = line.lower()
                
                # Check for errors
                if ' e ' in line_lower or 'error' in line_lower:
                    analysis['errors'].append(line.strip())
                
                # Check for warnings
                if ' w ' in line_lower or 'warning' in line_lower:
                    analysis['warnings'].append(line.strip())
                
                # Check for collective-specific errors
                if 'cwwkx' in line_lower:
                    analysis['collective_errors'].append(line.strip())
                
                # Check for certificate errors
                if 'cwpki' in line_lower or 'certificate' in line_lower:
                    analysis['certificate_errors'].append(line.strip())
        
        except Exception as e:
            analysis['error'] = str(e)
            logger.error(f"Error analyzing logs: {e}")
        
        self.results['log_analysis'] = analysis
        return analysis
    
    def test_collective_connectivity(self, controller_host: str, 
                                    controller_port: int = 9443) -> Dict:
        """Test connectivity to collective controller"""
        logger.info(f"Testing connectivity to controller: {controller_host}:{controller_port}")
        
        connectivity = {
            'controller_host': controller_host,
            'controller_port': controller_port,
            'tcp_connection': False,
            'ssl_handshake': False,
            'details': {}
        }
        
        # Test TCP connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((controller_host, controller_port))
            sock.close()
            
            connectivity['tcp_connection'] = result == 0
            connectivity['details']['tcp_status'] = 'SUCCESS' if result == 0 else f'FAILED (code: {result})'
        
        except Exception as e:
            connectivity['details']['tcp_error'] = str(e)
        
        # Test SSL handshake
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((controller_host, controller_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=controller_host) as ssock:
                    connectivity['ssl_handshake'] = True
                    connectivity['details']['ssl_version'] = ssock.version()
                    connectivity['details']['cipher'] = ssock.cipher()
        
        except Exception as e:
            connectivity['details']['ssl_error'] = str(e)
        
        self.results['connectivity_test'] = connectivity
        return connectivity
    
    def collect_support_data(self, output_dir: Optional[str] = None) -> Dict:
        """Collect comprehensive support data"""
        logger.info("Collecting support data")
        
        if output_dir is None:
            output_dir = f"support_data_{self.server_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        collection_results = {
            'output_directory': str(output_path),
            'collected_files': []
        }
        
        # Run server dump
        logger.info("Creating server dump...")
        dump_file = output_path / f"{self.server_name}_dump.zip"
        server_script = self.wlp_home / 'bin' / 'server'
        
        rc, stdout, stderr = self.run_command(
            [str(server_script), 'dump', self.server_name, 
             f'--archive={dump_file}', '--include=heap,thread,system'],
            timeout=120
        )
        
        if rc == 0:
            collection_results['collected_files'].append(str(dump_file))
        else:
            collection_results['dump_error'] = stderr
        
        # Copy configuration files
        config_files = ['server.xml', 'bootstrap.properties', 'jvm.options']
        for config_file in config_files:
            src = self.server_dir / config_file
            if src.exists():
                dst = output_path / config_file
                try:
                    import shutil
                    shutil.copy2(src, dst)
                    collection_results['collected_files'].append(str(dst))
                except Exception as e:
                    logger.error(f"Error copying {config_file}: {e}")
        
        # Save diagnostic results
        results_file = output_path / 'diagnostic_results.json'
        try:
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            collection_results['collected_files'].append(str(results_file))
        except Exception as e:
            logger.error(f"Error saving diagnostic results: {e}")
        
        self.results['support_data_collection'] = collection_results
        return collection_results
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate comprehensive diagnostic report"""
        if output_file is None:
            output_file = f"diagnostic_report_{self.server_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("WebSphere Liberty Collective Diagnostic Report")
        report_lines.append("=" * 80)
        report_lines.append(f"Server Name: {self.server_name}")
        report_lines.append(f"Liberty Home: {self.wlp_home}")
        report_lines.append(f"Report Generated: {datetime.datetime.now().isoformat()}")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Server Status
        if 'server_status' in self.results:
            report_lines.append("SERVER STATUS")
            report_lines.append("-" * 80)
            status = self.results['server_status']
            report_lines.append(f"Running: {status.get('running', 'Unknown')}")
            report_lines.append(f"Output: {status.get('output', 'N/A')}")
            report_lines.append("")
        
        # Port Status
        if 'port_status' in self.results:
            report_lines.append("PORT STATUS")
            report_lines.append("-" * 80)
            for port_name, port_info in self.results['port_status'].items():
                report_lines.append(f"{port_name}: {port_info['port']} - {port_info['status']}")
            report_lines.append("")
        
        # Collective Configuration
        if 'collective_config' in self.results:
            report_lines.append("COLLECTIVE CONFIGURATION")
            report_lines.append("-" * 80)
            config = self.results['collective_config']
            report_lines.append(f"Type: {config.get('type', 'Not configured')}")
            report_lines.append(f"Features: {', '.join(config.get('features', []))}")
            report_lines.append("")
        
        # Certificate Status
        if 'certificate_status' in self.results:
            report_lines.append("CERTIFICATE STATUS")
            report_lines.append("-" * 80)
            cert_status = self.results['certificate_status']
            report_lines.append(f"Status: {cert_status.get('status', 'Unknown')}")
            if 'details' in cert_status:
                for cert in cert_status['details']:
                    report_lines.append(f"  Alias: {cert.get('alias', 'N/A')}")
                    report_lines.append(f"  Validity: {cert.get('validity', 'N/A')}")
            report_lines.append("")
        
        # Log Analysis
        if 'log_analysis' in self.results:
            report_lines.append("LOG ANALYSIS")
            report_lines.append("-" * 80)
            analysis = self.results['log_analysis']
            report_lines.append(f"Errors Found: {len(analysis.get('errors', []))}")
            report_lines.append(f"Warnings Found: {len(analysis.get('warnings', []))}")
            report_lines.append(f"Collective Errors: {len(analysis.get('collective_errors', []))}")
            report_lines.append(f"Certificate Errors: {len(analysis.get('certificate_errors', []))}")
            
            if analysis.get('collective_errors'):
                report_lines.append("\nRecent Collective Errors:")
                for error in analysis['collective_errors'][-5:]:
                    report_lines.append(f"  {error}")
            report_lines.append("")
        
        # Connectivity Test
        if 'connectivity_test' in self.results:
            report_lines.append("CONNECTIVITY TEST")
            report_lines.append("-" * 80)
            conn = self.results['connectivity_test']
            report_lines.append(f"Controller: {conn.get('controller_host')}:{conn.get('controller_port')}")
            report_lines.append(f"TCP Connection: {'SUCCESS' if conn.get('tcp_connection') else 'FAILED'}")
            report_lines.append(f"SSL Handshake: {'SUCCESS' if conn.get('ssl_handshake') else 'FAILED'}")
            report_lines.append("")
        
        report_lines.append("=" * 80)
        report_lines.append("End of Report")
        report_lines.append("=" * 80)
        
        report_content = '\n'.join(report_lines)
        
        # Write to file
        try:
            with open(output_file, 'w') as f:
                f.write(report_content)
            logger.info(f"Report generated: {output_file}")
        except Exception as e:
            logger.error(f"Error writing report: {e}")
        
        return report_content
    
    def run_full_diagnostics(self, controller_host: Optional[str] = None,
                            controller_port: int = 9443) -> Dict:
        """Run all diagnostic checks"""
        logger.info("Running full diagnostics...")
        
        # Check server status
        self.check_server_status()
        
        # Check ports
        self.check_ports()
        
        # Check certificates
        self.check_certificates()
        
        # Check collective configuration
        self.check_collective_configuration()
        
        # Analyze logs
        self.analyze_logs()
        
        # Test connectivity if controller host provided
        if controller_host:
            self.test_collective_connectivity(controller_host, controller_port)
        
        # Generate report
        report = self.generate_report()
        
        logger.info("Full diagnostics completed")
        return self.results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='WebSphere Liberty Collective Diagnostics Utility'
    )
    parser.add_argument('--wlp-home', required=True,
                       help='WebSphere Liberty installation directory')
    parser.add_argument('--server', required=True,
                       help='Liberty server name')
    parser.add_argument('--controller-host',
                       help='Collective controller hostname (for connectivity test)')
    parser.add_argument('--controller-port', type=int, default=9443,
                       help='Collective controller HTTPS port (default: 9443)')
    parser.add_argument('--collect-support-data', action='store_true',
                       help='Collect comprehensive support data')
    parser.add_argument('--output-dir',
                       help='Output directory for support data')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Initialize diagnostics
        diagnostics = LibertyCollectiveDiagnostics(args.wlp_home, args.server)
        
        # Run full diagnostics
        results = diagnostics.run_full_diagnostics(
            controller_host=args.controller_host,
            controller_port=args.controller_port
        )
        
        # Collect support data if requested
        if args.collect_support_data:
            diagnostics.collect_support_data(args.output_dir)
        
        # Print summary
        print("\n" + "=" * 80)
        print("DIAGNOSTIC SUMMARY")
        print("=" * 80)
        print(f"Server: {args.server}")
        print(f"Status: {'Running' if results.get('server_status', {}).get('running') else 'Not Running'}")
        print(f"Collective Type: {results.get('collective_config', {}).get('type', 'Not configured')}")
        print(f"Errors Found: {len(results.get('log_analysis', {}).get('errors', []))}")
        print(f"Warnings Found: {len(results.get('log_analysis', {}).get('warnings', []))}")
        print("=" * 80)
        print(f"\nDetailed report saved to: diagnostic_report_{args.server}_*.txt")
        
        return 0
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())


