#!/bin/bash

################################################################################
# Network Monitoring System - Master Installer  
# One command to install and deploy everything
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Config
INSTALL_DIR="${INSTALL_DIR:-.}"
PROJECT_NAME="network-monitoring"
PORT="${PORT:-8000}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
DB_PASS="monitor_$(date +%s | md5sum | head -c 16)"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

check_requirements() {
    log_info "Checking requirements..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Install from: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose not found. Install from: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    log_success "Docker requirements OK"
}

create_structure() {
    log_info "Creating project structure..."
    
    mkdir -p "$PROJECT_NAME"/{backend,frontend,config,data/{postgres,redis,victoria,grafana},nginx}
    cd "$PROJECT_NAME"
    
    log_success "Directory structure created"
}

create_all_configs() {
    log_info "Creating configuration files..."
    
    # .env file
    cat > .env << 'ENVEOF'
PROJECT_NAME=network-monitoring
DB_USER=monitoring
DB_PASSWORD=monitoring_secure
DB_NAME=monitoring_db
REDIS_HOST=redis
VICTORIA_HOST=victoria
ADMIN_USER=admin
ADMIN_PASS=admin123
LOG_LEVEL=info
NETBOX_URL=https://netbox.example.com
NETBOX_TOKEN=
JWT_SECRET=your-secret-key-change-this
ENCRYPTION_KEY=your-encryption-key-change-this
ENVEOF

    # config.yaml
    cat > config/config.yaml << 'CFGEOF'
server:
  host: 0.0.0.0
  port: 8080
  enable_cors: true

database:
  host: postgres
  port: 5432
  user: monitoring
  password: monitoring_secure
  name: monitoring_db
  max_connections: 25

redis:
  host: redis
  port: 6379

discovery:
  sources:
    netbox:
      enabled: true
      url: https://netbox.example.com
      poll_interval: 60s
    snmp:
      enabled: true
      cidr_ranges:
        - 10.0.0.0/8
      timeout: 2s
    static:
      enabled: true
      path: /config/devices.yaml

collectors:
  snmp:
    enabled: true
    timeout: 5s
  gnmi:
    enabled: false
  netconf:
    enabled: false

alerts:
  enabled: true
  eval_interval: 30s
  rules_file: /config/rules.yaml

logging:
  level: info
  format: json
CFGEOF

    # devices.yaml
    cat > config/devices.yaml << 'DEVEOF'
devices:
  lab-device-01:
    address: 172.16.0.1
    preferred_protocol: snmp
    credential_ref: lab-snmp
    labels:
      site: lab
      environment: lab
    override: true
DEVEOF

    # rules.yaml
    cat > config/rules.yaml << 'RULESEOF'
groups:
  - name: network
    interval: 30s
    rules:
      - alert: DeviceDown
        expr: up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Device unreachable"
RULESEOF

    # prometheus.yml
    cat > config/prometheus.yml << 'PROMEOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules.yaml"

scrape_configs:
  - job_name: 'api'
    static_configs:
      - targets: ['api:8080']
    metrics_path: '/metrics'
PROMEOF

    log_success "Configuration files created"
}

create_docker_compose() {
    log_info "Creating Docker Compose..."
    
    cat > docker-compose.yml << 'DCEOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: monitoring
      POSTGRES_PASSWORD: monitoring_secure
      POSTGRES_DB: monitoring_db
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U monitoring"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - monitoring-net

  redis:
    image: redis:7-alpine
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
    command: -storageDataPath=/victoria-metrics-data -httpListenAddr=0.0.0.0:8428
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
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./config/rules.yaml:/etc/prometheus/rules.yaml
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
    networks:
      - monitoring-net

  grafana:
    image: grafana/grafana:latest
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin123
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - ./data/grafana:/var/lib/grafana
    networks:
      - monitoring-net

  api:
    image: network-monitoring-api:latest
    ports:
      - "8080:8080"
    environment:
      DB_HOST: postgres
      DB_PASSWORD: monitoring_secure
      REDIS_HOST: redis
      VICTORIA_HOST: victoria
      LOG_LEVEL: info
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
    ports:
      - "3001:3000"
    environment:
      REACT_APP_API_URL: http://localhost:8080/api
    depends_on:
      - api
    networks:
      - monitoring-net

  nginx:
    image: nginx:alpine
    ports:
      - "8000:80"
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
DCEOF

    log_success "Docker Compose created"
}

create_nginx() {
    log_info "Creating Nginx configuration..."
    
    cat > nginx/nginx.conf << 'NGEOF'
user nginx;
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
NGEOF

    cat > nginx/default.conf << 'NGCONFEOF'
upstream api {
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
    }
    
    # API
    location /api {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    # Admin
    location /admin {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # Prometheus tab
    location /prometheus {
        proxy_pass http://prometheus/;
        proxy_set_header Host $host;
    }
    
    # Grafana tab
    location /grafana {
        proxy_pass http://grafana/;
        proxy_set_header Host $host;
    }
    
    # Metrics
    location /metrics {
        proxy_pass http://api/metrics;
        access_log off;
    }
    
    # WebSocket
    location /ws {
        proxy_pass http://api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
NGCONFEOF

    log_success "Nginx config created"
}

start_services() {
    log_info "Starting Docker services..."
    
    docker-compose up -d
    
    log_success "Services started!"
}

wait_healthy() {
    log_info "Waiting for services to be healthy..."
    
    local count=0
    while [ $count -lt 60 ]; do
        if docker-compose exec -T api curl -f http://localhost:8080/admin/health &>/dev/null 2>&1; then
            log_success "All services healthy!"
            return 0
        fi
        count=$((count + 1))
        echo -ne "  Checking... ($count/60)\r"
        sleep 2
    done
    
    log_warning "Services taking longer than expected, continuing..."
    return 0
}

show_summary() {
    clear
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   ✅ Installation Complete!                               ║"
    echo "║                                                            ║"
    echo "║    Network Monitoring System Ready                         ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    echo "🌐 UNIFIED DASHBOARD (All Components in One Place):"
    echo "   ${GREEN}http://localhost:${PORT}${NC}"
    echo ""
    
    echo "📊 TABS AVAILABLE:"
    echo "   • Dashboard (Home)"
    echo "   • Devices"
    echo "   • Collectors"
    echo "   • Alerts"
    echo "   • Rules"
    echo "   • Prometheus (${GREEN}http://localhost:${PORT}/prometheus${NC})"
    echo "   • Grafana (${GREEN}http://localhost:${PORT}/grafana${NC})"
    echo "   • Settings"
    echo ""
    
    echo "🔑 CREDENTIALS:"
    echo "   Username: ${ADMIN_USER}"
    echo "   Password: ${ADMIN_PASS}"
    echo ""
    
    echo "📁 Project Location:"
    echo "   ${GREEN}$(pwd)${NC}"
    echo ""
    
    echo "🚀 NEXT STEPS:"
    echo "   1. Open http://localhost:${PORT} in your browser"
    echo "   2. Login with admin credentials"
    echo "   3. Change admin password"
    echo "   4. Configure Netbox API token (optional)"
    echo "   5. Add devices and start monitoring"
    echo ""
    
    echo "💻 USEFUL COMMANDS:"
    echo "   View logs:       docker-compose logs -f"
    echo "   Stop services:   docker-compose down"
    echo "   Restart:         docker-compose restart"
    echo "   Status:          docker-compose ps"
    echo ""
    
    echo "📖 DOCUMENTATION:"
    echo "   • README.md in project directory"
    echo "   • API docs at: http://localhost:${PORT}/api"
    echo "   • Prometheus: http://localhost:${PORT}/prometheus"
    echo "   • Grafana: http://localhost:${PORT}/grafana"
    echo ""
}

main() {
    clear
    
    cat << "EOF"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     Network Monitoring System - Master Installer           ║
║                                                            ║
║     One Command to Deploy Everything                      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
