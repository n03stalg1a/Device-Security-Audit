# Device Security Audit Script

This is a Python-based device security audit script designed to run various security checks on a system. It performs audits for Docker container security, rootkit detection, network traffic capture, cloud and Kubernetes security checks, and more. It also supports customizable audit options and parallel execution of tasks for efficiency.

## Features
- Real-time network traffic capture with `tcpdump`.
- Docker image vulnerability scanning using **Trivy**.
- Docker security hardening with **Docker Bench for Security**.
- Rootkit detection using **Chkrootkit**.
- Cloud resource auditing for AWS, GCP, and Azure (optional).
- Kubernetes security check (optional).
- Real-time threat intelligence integration (Shodan, AlienVault, VirusTotal).

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/Device-Security-Audit.git
    cd Device-Security-Audit
    ```

2. Install required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

3. **Optional**: If you plan to use Docker, install Docker on your system.

## Usage

Run the script using:

```bash
python audit_script.py
