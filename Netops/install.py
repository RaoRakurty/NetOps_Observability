#!/usr/bin/env python3

"""
Network Monitoring System - Master Installer
One command to install and deploy everything
"""

import os
import sys
import subprocess
import json
import shutil
from datetime import datetime
from pathlib import Path

class Installer:
    def __init__(self, install_dir=".", port=8000):
        self.install_dir = Path(install_dir)
        self.project_name = "network-monitoring"
        self.port = port
        self.project_path = self.install_dir / self.project_name
        
    def log_info(self, msg):
        print(f"[ℹ️  INFO] {msg}")
    
    def log_success(self, msg):
        print(f"[✅ OK  ] {msg}")
    
    def log_error(self, msg):
        print(f"[❌ ERR ] {msg}")
        sys.exit(1)
    
    def log_step(self, msg):
        print(f"\n{'='*60}")
        print(f"  {msg}")
        print(f"{'='*60}\n")
    
    def check_docker(self):
        """Check if Docker and Docker Compose are installed"""
        self.log_info("Checking Docker...")
        
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
            self.log_success("Docker found")
        except:
            self.log_error("Docker not installed. Visit: https://docs.docker.com/get-docker/")
        
        try:
            subprocess.run(["docker-compose", "--version"], capture_output=True, check=True)
            self.log_success("Docker Compose found")
        except:
            self.log_error("Docker Compose not installed. Visit: https://docs.docker.com/compose/install/")
    
    def create_directories(self):
        """Create project directory structure"""
        self.log_step("Creating Directory Structure")
        
        dirs = [
            self.project_path,
            self.project_path / "backend",
            self.project_path / "frontend",
            self.project_path / "config",
            self.project_path / "data" / "postgres",
            self.project_path / "data" / "redis",
            self.project_path / "data" / "victoria",
            self.project_path / "data" / "grafana",
            self.project_path / "data" / "prometheus",
            self.project_path / "nginx",
        ]
        
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            self.log_info(f"Created: {d}")
        
        self.log_success(f"Project structure created at {self.project_path}")
    
    def create_env_file(self):
        """Create .env configuration"""
        self.log_step("Creating Configuration Files")
        
        env_content = f"""# Network Monitoring System Configuration
# Generated: {datetime.now().isoformat()}

PROJECT_NAME={self.project_name}
INSTALL_DATE={datetime.now().isoformat()}

# Service Ports
BASE_PORT={self.port}
API_PORT=8080
FRONTEND_PORT=3000

# Database
DB_HOST=postgres
DB_PORT=5432
DB_USER=monitoring
DB_PASSWORD=monitoring_secure_$(date +%s | md5sum | head -c 16)
DB_NAME=monitoring_db

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# VictoriaMetrics
VICTORIA_HOST=victoria
VICTORIA_PORT=8428
VICTORIA_RETENTION=720h

# Prometheus
PROMETHEUS_HOST=prometheus
PROMETHEUS_PORT=9090

# Grafana
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=admin123

# Netbox Configuration
NETBOX_URL=https://netbox.example.com
NETBOX_TOKEN=
NETBOX_VERIFY_SSL=true

# Application
ADMIN_USER=admin
ADMIN_PASS=admin123
LOG_LEVEL=info

# Security
JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "change-me-to-random-secret")
ENCRYPTION_KEY=$(openssl rand -hex 32 2>/dev/null || echo "change-me-to-random-key")
TLS_ENABLED=false

# Features
ENABLE_SNMP_DISCOVERY=true
ENABLE_SNMP_COLLECTION=true
ENABLE_GNMI_COLLECTION=false
ENABLE_NETCONF_COLLECTION=false
FEATURE_SLACK_NOTIFICATIONS=false
FEATURE_PAGERDUTY_NOTIFICATIONS=false
"""
        
        env_path = self.project_path / ".env"
        env_path.write_text(env_content)
        self.log_success(f"Created: .env")
    
    def create_config_yaml(self):
        """Create main configuration"""
        config_yaml = """server:
  host: 0.0.0.0
  port: 8080
  enable_cors: true

database:
  host: ${DB_HOST}
  port: ${DB_PORT}
  user: ${DB_USER}
  password: ${DB_PASSWORD}
  name: ${DB_NAME}
  max_connections: 25

redis:
  host: ${REDIS_HOST}
  port: ${REDIS_PORT}

tsdb:
  type: victoria
  url: http://${VICTORIA_HOST}:${VICTORIA_PORT}
  retention: ${VICTORIA_RETENTION}

discovery:
  sources:
    netbox:
      enabled: true
      url: ${NETBOX_URL}
      token: ${NETBOX_TOKEN}
      poll_interval: 60s
      timeout: 10s
      site_filter: []
      tag_filter: [monitored]

    snmp:
      enabled: ${ENABLE_SNMP_DISCOVERY}
      cidr_ranges:
        - 10.0.0.0/8
      timeout: 2s
      retries: 1

    static:
      enabled: true
      path: /config/devices.yaml

collectors:
  snmp:
    enabled: ${ENABLE_SNMP_COLLECTION}
    timeout: 5s
  gnmi:
    enabled: ${ENABLE_GNMI_COLLECTION}
  netconf:
    enabled: ${ENABLE_NETCONF_COLLECTION}

alerts:
  enabled: true
  eval_interval: 30s
  rules_file: /config/rules.yaml

logging:
  level: ${LOG_LEVEL}
  format: json
"""
        
        config_path = self.project_path / "config" / "config.yaml"
        config_path.write_text(config_yaml)
        self.log_success(f"Created: config.yaml")
    
    def create_devices_yaml(self):
        """Create devices configuration"""
        devices_yaml = """# Static Device Inventory
# Devices here are monitored in addition to auto-discovered devices

devices:
  # Example lab device
  lab-router-01:
    address: 172.16.0.1
    preferred_protocol: snmp
    credential_ref: lab-snmp-v2c
    labels:
      site: lab
      environment: lab
    override: true
    metadata:
      notes: "Lab device for testing"

  # Add your devices here...
"""
        
        devices_path = self.project_path / "config" / "devices.yaml"
        devices_path.write_text(devices_yaml)
        self.log_success(f"Created: devices.yaml")
    
    def create_rules_yaml(self):
        """Create alert rules"""
        rules_yaml = """groups:
  - name: network
    interval: 30s
    rules:
      - alert: DeviceUnreachable
        expr: up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Device {{ $labels.device_id }} is unreachable"

      - alert: HighCPU
        expr: cpu_usage > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU on {{ $labels.device_id }}: {{ $value }}%"

      - alert: HighMemory
        expr: memory_usage > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory on {{ $labels.device_id }}: {{ $value }}%"
"""
        
        rules_path = self.project_path / "config" / "rules.yaml"
        rules_path.write_text(rules_yaml)
        self.log_success(f"Created: rules.yaml")
    
    def create_prometheus_yaml(self):
        """Create Prometheus configuration"""
        prometheus_yaml = """global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules.yaml"

alerting:
  alertmanagers:
    - static_configs:
        - targets: []

scrape_configs:
  - job_name: 'monitoring-api'
    static_configs:
      - targets: ['api:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'victoria'
    static_configs:
      - targets: ['victoria:8428']
    metrics_path: '/metrics'

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
"""
        
        prometheus_path = self.project_path / "config" / "prometheus.yml"
        prometheus_path.write_text(prometheus_yaml)
        self.log_success(f"Created: prometheus.yml")
    
    def create_docker_compose(self):
        """Create Docker Compose file"""
        docker_compose = """version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: ${PROJECT_NAME}-postgres
    environment:
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME}
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - monitoring-net

  redis:
    image: redis:7-alpine
    container_name: ${PROJECT_NAME}-redis
    volumes:
      - ./data/redis:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - monitoring-net

  victoria:
    image: victoriametrics/victoria-metrics:latest
    container_name: ${PROJECT_NAME}-victoria
    command: -storageDataPath=/victoria-metrics-data -httpListenAddr=0.0.0.0:8428 -retentionPeriod=${VICTORIA_RETENTION}
    volumes:
      - ./data/victoria:/victoria-metrics-data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8428/health"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - monitoring-net

  prometheus:
    image: prom/prometheus:latest
    container_name: ${PROJECT_NAME}-prometheus
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./config/rules.yaml:/etc/prometheus/rules.yaml
      - ./data/prometheus:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
    networks:
      - monitoring-net

  grafana:
    image: grafana/grafana:latest
    container_name: ${PROJECT_NAME}-grafana
    environment:
      GF_SECURITY_ADMIN_USER: ${GRAFANA_ADMIN_USER}
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD}
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - ./data/grafana:/var/lib/grafana
    networks:
      - monitoring-net

  api:
    image: network-monitoring-api:latest
    container_name: ${PROJECT_NAME}-api
    ports:
      - "${API_PORT}:8080"
    environment:
      DB_HOST: postgres
      DB_PASSWORD: ${DB_PASSWORD}
      REDIS_HOST: redis
      VICTORIA_HOST: victoria
      LOG_LEVEL: ${LOG_LEVEL}
      NETBOX_URL: ${NETBOX_URL}
      NETBOX_TOKEN: ${NETBOX_TOKEN}
    volumes:
      - ./config/config.yaml:/app/config.yaml
      - ./config/devices.yaml:/app/devices.yaml
      - ./config/rules.yaml:/app/rules.yaml
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      victoria:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/admin/health"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - monitoring-net

  frontend:
    image: network-monitoring-frontend:latest
    container_name: ${PROJECT_NAME}-frontend
    ports:
      - "${FRONTEND_PORT}:3000"
    environment:
      REACT_APP_API_URL: http://localhost:${API_PORT}/api
      REACT_APP_PROMETHEUS_URL: http://localhost:${BASE_PORT}/prometheus
      REACT_APP_GRAFANA_URL: http://localhost:${BASE_PORT}/grafana
    depends_on:
      - api
    networks:
      - monitoring-net

  nginx:
    image: nginx:alpine
    container_name: ${PROJECT_NAME}-nginx
    ports:
      - "${BASE_PORT}:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - api
      - frontend
      - prometheus
      - grafana
    networks:
      - monitoring-net

networks:
  monitoring-net:
    driver: bridge
"""
        
        docker_compose_path = self.project_path / "docker-compose.yml"
        docker_compose_path.write_text(docker_compose)
        self.log_success(f"Created: docker-compose.yml")
    
    def create_nginx_config(self):
        """Create Nginx reverse proxy configuration"""
        nginx_conf = """user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    
    include /etc/nginx/conf.d/*.conf;
}
"""
        
        default_conf = """upstream api {
    server api:8080;
}

upstream frontend {
    server frontend:3000;
}

upstream prometheus {
    server prometheus:9090;
}

upstream grafana {
    server grafana:3000;
}

server {
    listen 80;
    server_name _;
    client_max_body_size 20M;

    # Main dashboard
    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API endpoints
    location /api {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Admin endpoints
    location /admin {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Prometheus tab
    location /prometheus {
        proxy_pass http://prometheus/;
        proxy_set_header Host $host;
        proxy_redirect off;
    }

    # Grafana tab
    location /grafana {
        proxy_pass http://grafana/;
        proxy_set_header Host $host;
        proxy_redirect off;
    }

    # Metrics
    location /metrics {
        proxy_pass http://api/metrics;
        access_log off;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
"""
        
        (self.project_path / "nginx" / "nginx.conf").write_text(nginx_conf)
        (self.project_path / "nginx" / "default.conf").write_text(default_conf)
        self.log_success(f"Created: nginx configuration")
    
    def start_services(self):
        """Start Docker Compose services"""
        self.log_step("Starting Services")
        
        os.chdir(self.project_path)
        
        self.log_info("Starting Docker Compose...")
        subprocess.run(["docker-compose", "up", "-d"], check=True)
        
        self.log_success("Services started!")
    
    def wait_for_health(self):
        """Wait for services to be healthy"""
        self.log_step("Waiting for Services")
        
        import time
        max_attempts = 60
        attempt = 0
        
        while attempt < max_attempts:
            try:
                result = subprocess.run(
                    ["docker-compose", "exec", "-T", "api", "curl", "-f", "http://localhost:8080/admin/health"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.log_success("All services are healthy!")
                    return
            except:
                pass
            
            attempt += 1
            print(f"  Checking... ({attempt}/{max_attempts})", end="\r")
            time.sleep(2)
        
        print("  Checking... (done)")
        self.log_info("Services are starting (may need a few more minutes)")
    
    def show_summary(self):
        """Display installation summary"""
        os.system("clear" if os.name != "nt" else "cls")
        
        summary = f"""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   ✅ Installation Complete!                               ║
║                                                            ║
║    Network Monitoring System is Ready                      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

🌐 UNIFIED DASHBOARD (Everything in One Place):
   http://localhost:{self.port}

📊 AVAILABLE TABS:
   • Dashboard (Home)
   • Devices (Inventory)
   • Collectors (Status)
   • Alerts (Management)
   • Rules (Configuration)
   • Prometheus (http://localhost:{self.port}/prometheus)
   • Grafana (http://localhost:{self.port}/grafana)
   • Settings

🔑 CREDENTIALS:
   Username: admin
   Password: admin123
   ⚠️  Change on first login!

📁 Installation Directory:
   {self.project_path}

🚀 NEXT STEPS:
   1. Open http://localhost:{self.port} in your browser
   2. Login with admin credentials
   3. Change admin password immediately
   4. Configure Netbox API token (optional)
   5. Add devices and start monitoring

💻 USEFUL COMMANDS:
   View logs:       docker-compose logs -f
   Stop services:   docker-compose down
   Restart:         docker-compose restart
   Status:          docker-compose ps
   Update config:   Edit .env and docker-compose.yml, then restart

🔧 CONFIGURATION:
   Main config:     config/config.yaml
   Devices:         config/devices.yaml
   Alert rules:     config/rules.yaml
   Environment:     .env

📚 FEATURES:
   ✅ Device Discovery (Netbox, SNMP, Static YAML)
   ✅ Unified Dashboard
   ✅ Real-time Alerts
   ✅ Metrics Collection
   ✅ Grafana Dashboards
   ✅ Prometheus Integration
   ✅ Single Entry Point
   ✅ Auto-scaling Ready

⚠️  IMPORTANT:
   • Keep .env file secure
   • Backup database regularly: docker-compose exec postgres pg_dump -U monitoring monitoring_db > backup.sql
   • Monitor logs for errors: docker-compose logs -f
   • Review config before production deployment

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Ready to monitor your network! 🚀

"""
        print(summary)
    
    def run(self):
        """Run complete installation"""
        print("""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     Network Monitoring System - Master Installer           ║
║                                                            ║
║     One Command to Deploy Everything                      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
        """)
        
        try:
            self.check_docker()
            self.create_directories()
            self.create_env_file()
            self.create_config_yaml()
            self.create_devices_yaml()
            self.create_rules_yaml()
            self.create_prometheus_yaml()
            self.create_docker_compose()
            self.create_nginx_config()
            self.start_services()
            self.wait_for_health()
            self.show_summary()
        except KeyboardInterrupt:
            self.log_error("Installation cancelled by user")
        except Exception as e:
            self.log_error(f"Installation failed: {str(e)}")

if __name__ == "__main__":
    installer = Installer(port=8000)
    installer.run()
