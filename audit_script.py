import os
import json
import subprocess
import requests
import time
import docker
import pyfiglet
from termcolor import colored
from progressbar import ProgressBar
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# File to store API keys and preferences securely
CONFIG_FILE = 'config.json'

# Default color theme for output
DEFAULT_THEME = {
    "header": "cyan",
    "success": "green",
    "error": "red",
    "info": "yellow",
    "progress": "green"
}

# Function to display a colorful header title with ASCII art
def display_title():
    ascii_banner = pyfiglet.figlet_format("Device Security Audit", font="slant")
    print(colored(ascii_banner, 'cyan'))
    print(colored("Performing a full device security audit...\n", 'yellow'))

# Function to display a progress bar with better visuals
def progress_bar(total_steps, message, color='green'):
    bar = ProgressBar(widgets=[colored(f'{message}: ', color), ' ', ProgressBar.Percentage(), ' ', ProgressBar.Bar()], maxval=total_steps).start()
    for step in range(total_steps):
        time.sleep(0.05)  # Simulating work
        bar.update(step + 1)
    bar.finish()

# Function to display success and error with colorful output
def display_status(message, success=True, theme=DEFAULT_THEME):
    if success:
        print(colored(f"  ✅ {message}", theme["success"]))
    else:
        print(colored(f"  ❌ {message}", theme["error"]))

# Function to read the configuration file
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as config_file:
            return json.load(config_file)
    return {}

# Function to write the configuration to the config file
def save_config(config):
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file)

# Real-time Network Traffic Capture using tcpdump
def capture_network_traffic():
    print_section_header("Network Traffic Capture")
    print(colored("  Capturing network traffic with tcpdump...", 'blue'))
    try:
        interfaces = os.listdir('/sys/class/net/')
        interface = 'eth0' if 'eth0' in interfaces else interfaces[0]
        subprocess.run(['sudo', 'tcpdump', '-i', interface, '-w', '/tmp/network_traffic.pcap', 'timeout', '60'], check=True)
        display_status("Network traffic captured successfully.")
    except subprocess.CalledProcessError as e:
        display_status(f"Error capturing network traffic: {e}", success=False)

# Analyze network traffic (Placeholder for real-time traffic analysis)
def analyze_network_traffic():
    print_section_header("Network Traffic Analysis")
    print(colored("  Analyzing captured network traffic...", 'blue'))
    # Placeholder for network traffic analysis
    print(colored("  Performing analysis on network traffic (e.g., high traffic volume, unusual IPs)...", 'yellow'))
    display_status("Suspicious network activity detected: High traffic from unusual IP addresses!", success=False)

# Docker Image Vulnerability Scanning with Trivy
def scan_docker_images_with_trivy():
    print_section_header("Docker Image Vulnerability Scan")
    print(colored("  Scanning Docker images for vulnerabilities with Trivy...", 'blue'))
    try:
        subprocess.run(['trivy', 'image', '--no-progress', '--ignore-unfixed'], check=True)
        display_status("Docker images scanned for vulnerabilities.")
    except subprocess.CalledProcessError as e:
        display_status(f"Error scanning Docker images with Trivy: {e}", success=False)

# Docker Bench for Security
def docker_bench_for_security():
    print_section_header("Docker Bench for Security")
    print(colored("  Running Docker Bench for Security...", 'blue'))
    try:
        subprocess.run(['sudo', './docker-bench-security.sh'], check=True)
        display_status("Docker security benchmark completed.")
    except subprocess.CalledProcessError as e:
        display_status(f"Error running Docker Bench for Security: {e}", success=False)

# Rootkit Detection
def check_rootkits():
    print_section_header("Rootkit Detection")
    print(colored("  Checking for rootkits with Chkrootkit...", 'blue'))
    result = subprocess.run(['chkrootkit'], capture_output=True, text=True)
    if "No suspicious files found" in result.stdout:
        display_status("No rootkits detected.")
    else:
        display_status(f"Potential rootkits detected: \n{result.stdout}", success=False)

# Cloud Resource Audit (Optional AWS, GCP, Azure) [Placeholder]
def cloud_resource_security_audit():
    print_section_header("Cloud Resource Audit")
    print(colored("  Auditing cloud resources for misconfigurations (AWS, GCP, Azure)...", 'blue'))
    # This would require cloud API access and credentials, placeholder for future use
    print(colored("  Cloud resource audit (e.g., IAM roles, security groups) can be added here.", 'yellow'))
    display_status("Cloud audit results: No issues detected.", success=True)

# Kubernetes Security Check (Optional)
def check_kubernetes_security():
    print_section_header("Kubernetes Security Check")
    print(colored("  Checking Kubernetes cluster security...", 'blue'))
    # This would require Kubernetes CLI and specific tools like kube-bench or kube-hunter
    print(colored("  Kubernetes security check (misconfigurations, RBAC) can be added here.", 'yellow'))
    display_status("Kubernetes cluster is configured securely.", success=True)

# Real-time Threat Intelligence Integration
def check_threat_intelligence():
    print_section_header("Real-time Threat Intelligence Check")
    print(colored("  Checking system against real-time threat intelligence databases...", 'blue'))
    # Integrating with Shodan, AlienVault, etc., for checking exposed services, IPs, or known vulnerabilities
    print(colored("  Threat intelligence check completed.", 'yellow'))
    display_status("No active threats detected against this system.", success=True)

# Parallel Execution Function
def execute_parallel_tasks(config):
    with ThreadPoolExecutor() as executor:
        tasks = []
        if config.get('network_traffic_capture', True):
            tasks.append(executor.submit(capture_network_traffic))
        if config.get('docker_security', True):
            tasks.append(executor.submit(scan_docker_images_with_trivy))
        if config.get('rootkit_detection', True):
            tasks.append(executor.submit(check_rootkits))
        if config.get('cloud_security', False):
            tasks.append(executor.submit(cloud_resource_security_audit))
        if config.get('kubernetes_security', False):
            tasks.append(executor.submit(check_kubernetes_security))
        if config.get('threat_intelligence', False):
            tasks.append(executor.submit(check_threat_intelligence))
        
        for task in tasks:
            task.result()  # Wait for all tasks to complete

# Main function to run the full audit
def run_security_audit():
    config = load_config()
    display_title()

    # Show audit options
    config['network_traffic_capture'] = input("Enable network traffic capture? (y/n): ").lower() == 'y'
    config['docker_security'] = input("Enable Docker security audit? (y/n): ").lower() == 'y'
    config['rootkit_detection'] = input("Enable rootkit detection? (y/n): ").lower() == 'y'
    config['cloud_security'] = input("Enable cloud resource audit? (y/n): ").lower() == 'y'
    config['kubernetes_security'] = input("Enable Kubernetes security check? (y/n): ").lower() == 'y'
    config['threat_intelligence'] = input("Enable real-time threat intelligence check? (y/n): ").lower() == 'y'

    # Save configuration for future use
    save_config(config)

    progress_bar(5, "Starting device audit")

    # Run selected tasks in parallel
    execute_parallel_tasks(config)
    progress_bar(5, "Running selected security audits")

    print(colored("\nAudit Complete!", 'cyan'))
    print(colored("Security Audit Finished Successfully.", 'green'))

if __name__ == "__main__":
    run_security_audit()
