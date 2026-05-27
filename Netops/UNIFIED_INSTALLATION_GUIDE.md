# Network Monitoring System - Unified Installer & Dashboard

A **production-ready network monitoring platform** that installs completely in one command with a unified dashboard where all components are accessible from a single entry point.

## 🎯 What You Get

✅ **One-Command Installation** - Everything deploys with a single script  
✅ **Unified Dashboard** - All tools accessible from one URL with tabs  
✅ **No Separate URLs** - No need to access Netbox, Prometheus, Grafana separately  
✅ **Integrated UI** - Beautiful dashboard with Netbox, Collectors, Alerts all in one place  
✅ **SNMP Discovery** - Automatically discover devices via SNMP scanning  
✅ **Full Stack** - PostgreSQL, Redis, VictoriaMetrics, Prometheus, Grafana included  
✅ **Production Ready** - Docker Compose, health checks, auto-recovery  

## 🚀 Quick Start (30 Seconds)

### Option 1: Python Installer (Recommended)

```bash
# Download and run installer
python3 install.py

# That's it! Open http://localhost:8000
```

### Option 2: Bash Installer

```bash
bash install.sh

# Open http://localhost:8000
```

Both installers will:
1. Check Docker/Docker Compose
2. Create all configuration files
3. Set up project structure
4. Start all services
5. Show you the access URL

### Option 3: Manual Installation

```bash
# 1. Clone/extract project
cd monitoring-system

# 2. Create env file
cp .env.example .env

# 3. Start services
docker-compose up -d

# 4. Wait for health (2-3 minutes)
docker-compose ps

# 5. Open dashboard
open http://localhost:8000
```

## 🌐 Unified Dashboard

Everything accessible from **http://localhost:8000** with tabs:

### Main Tabs
- **Dashboard** - System overview, KPIs, recent alerts
- **Devices** - Device inventory with discovery
- **Collectors** - Collector status and metrics
- **Alerts** - Alert history and management
- **Rules** - Create and edit alert rules
- **Prometheus** - Metrics explorer (embedded)
- **Grafana** - Dashboards (embedded)
- **Settings** - System configuration

### No Separate URLs Needed!
Instead of:
- ❌ http://localhost:8080/api
- ❌ http://localhost:9090 (Prometheus)
- ❌ http://localhost:3000 (Grafana)
- ❌ http://netbox.internal (Netbox)

Just use:
- ✅ http://localhost:8000 (Everything!)

## 🔑 Default Credentials

```
Username: admin
Password: admin123

⚠️  Change these on first login!
```

## 📁 Project Structure After Installation

```
network-monitoring/
├── .env                          # Configuration (auto-generated)
├── config/
│   ├── config.yaml              # Main config
│   ├── devices.yaml             # Device inventory
│   ├── rules.yaml               # Alert rules
│   └── prometheus.yml           # Prometheus config
├── docker-compose.yml           # All services
├── nginx/
│   ├── nginx.conf               # Reverse proxy
│   └── default.conf             # Routing config
├── data/                        # Persistent storage
│   ├── postgres/                # Database
│   ├── redis/                   # Cache
│   ├── victoria/                # Metrics
│   ├── grafana/                 # Dashboards
│   └── prometheus/              # Metrics history
├── backend/                     # Go API code
├── frontend/                    # React dashboard code
└── README.md                    # Documentation
```

## 🎨 Unified Dashboard Architecture

```
┌─────────────────────────────────────────────────┐
│  Nginx Reverse Proxy (Port 8000)                │
│  ↓         ↓         ↓         ↓                 │
├──────────────────────────────────────────────────┤
│  / (Dashboard)  /api  /prometheus  /grafana     │
├──────────────────────────────────────────────────┤
│                                                  │
│  Frontend (React)                               │
│  ├─ Dashboard Tab                               │
│  ├─ Devices Tab                                 │
│  ├─ Collectors Tab                              │
│  ├─ Alerts Tab                                  │
│  ├─ Rules Tab                                   │
│  ├─ Prometheus Tab (embedded iframe)            │
│  ├─ Grafana Tab (embedded iframe)               │
│  └─ Settings Tab                                │
│                                                  │
├─────────────────────────────────────────────────┤
│  Backend API (Port 8080)                        │
│  └─ All REST endpoints                          │
├─────────────────────────────────────────────────┤
│  Support Services                               │
│  ├─ Prometheus (9090)                           │
│  ├─ Grafana (3000)                              │
│  ├─ Victoria Metrics (8428)                     │
│  ├─ PostgreSQL (5432)                           │
│  └─ Redis (6379)                                │
└─────────────────────────────────────────────────┘

User Only Sees: http://localhost:8000 ← Single Entry Point!
```

## 🔧 Features

### Discovery
- ✅ **Netbox API** - Auto-discover devices from Netbox
- ✅ **SNMP Scanning** - Auto-discover via SNMP in CIDR ranges
- ✅ **Static YAML** - Manual device definitions
- ✅ **Multi-source** - Combine all three with conflict resolution

### Collection
- ✅ **SNMP** - v2c and v3 polling
- 🔄 **gNMI** - Ready to implement
- 🔄 **NETCONF** - Ready to implement
- 🔄 **Streaming Telemetry** - Ready to implement

### Management
- ✅ **Alert Rules** - Create and edit via UI
- ✅ **Device Inventory** - CRUD operations
- ✅ **Credentials** - Secure credential management
- ✅ **Notifications** - Slack, PagerDuty (configurable)

### Visualization
- ✅ **Dashboard** - Real-time KPIs and charts
- ✅ **Prometheus** - Metrics explorer
- ✅ **Grafana** - Pre-built dashboards
- ✅ **Device Details** - Per-device metrics

## 📊 Services Included

| Service | Purpose | Port | Access |
|---------|---------|------|--------|
| **Nginx** | Reverse Proxy | 8000 | Main entry point |
| **Frontend** | React Dashboard | 3001 | Embedded in Nginx |
| **API** | Go Backend | 8080 | Via `/api` path |
| **Prometheus** | Metrics Storage | 9090 | Via `/prometheus` tab |
| **Grafana** | Dashboarding | 3000 | Via `/grafana` tab |
| **VictoriaMetrics** | Time-Series DB | 8428 | Internal only |
| **PostgreSQL** | Application DB | 5432 | Internal only |
| **Redis** | Cache/Queue | 6379 | Internal only |

## 🚀 Common Operations

### View Logs
```bash
docker-compose logs -f                # All services
docker-compose logs -f api            # Just API
docker-compose logs -f frontend       # Just frontend
```

### Stop Services
```bash
docker-compose down                   # Stop all
docker-compose stop                   # Pause all
```

### Restart Services
```bash
docker-compose restart                # Restart all
docker-compose restart api            # Restart just API
```

### Check Status
```bash
docker-compose ps                     # Service status
```

### Update Configuration
```bash
# Edit configuration
nano config/config.yaml
nano config/devices.yaml
nano config/rules.yaml

# Restart to apply changes
docker-compose restart api
```

### Backup Database
```bash
docker-compose exec postgres pg_dump \
  -U monitoring monitoring_db > backup.sql
```

### Restore Database
```bash
docker-compose exec -i postgres psql \
  -U monitoring monitoring_db < backup.sql
```

## 🔐 Security Configuration

### Change Admin Password
1. Open http://localhost:8000
2. Login with admin/admin123
3. Go to Settings → Change Password
4. Save new password

### Configure Netbox Integration
1. Get API token from your Netbox instance
2. Edit `.env` file:
   ```
   NETBOX_URL=https://netbox.internal
   NETBOX_TOKEN=your_token_here
   ```
3. Restart API: `docker-compose restart api`

### Configure Notifications
Edit `.env` to enable Slack, PagerDuty, email:
```
FEATURE_SLACK_NOTIFICATIONS=true
SLACK_WEBHOOK_URL=https://hooks.slack.com/...

FEATURE_PAGERDUTY_NOTIFICATIONS=true
PAGERDUTY_KEY=your_integration_key

FEATURE_EMAIL_NOTIFICATIONS=true
SMTP_HOST=smtp.example.com
SMTP_FROM=monitoring@example.com
```

## 📈 Scaling

### For 10-100 Devices
- Single docker-compose deployment
- ~2GB RAM required
- Works perfectly

### For 100-1000 Devices  
- Keep single Nginx/Frontend
- Scale API containers horizontally
- Dedicated database recommended

### For 1000+ Devices
- Deploy to Kubernetes cluster
- Helm charts provided
- Prometheus + Victoria federation

## ⚠️ Important Notes

1. **Keep .env secure** - Contains database passwords
2. **Backup regularly** - Database backups essential
3. **Monitor logs** - Check for errors: `docker-compose logs -f`
4. **Change passwords** - Never keep default credentials
5. **Update configs** - Review config.yaml for your environment

## 🆘 Troubleshooting

### Services won't start
```bash
# Check Docker
docker ps
docker-compose ps

# View logs
docker-compose logs api

# Restart everything
docker-compose down -v
docker-compose up -d
```

### Devices not discovered
```bash
# Check discovery health
curl http://localhost:8080/admin/health | jq .discovery

# Check logs
docker-compose logs api | grep discovery

# Verify Netbox connectivity
docker-compose exec api curl -H "Authorization: Token $NETBOX_TOKEN" \
  https://netbox.internal/api/dcim/devices/
```

### Metrics not flowing
```bash
# Check collector status
curl http://localhost:8080/api/collectors

# Check Victoria Metrics
curl http://localhost:8428/api/v1/labels

# Check logs
docker-compose logs api | grep collector
```

### Can't access dashboard
```bash
# Check Nginx is running
docker-compose ps | grep nginx

# Check port
curl http://localhost:8000

# View Nginx logs
docker-compose logs nginx
```

## 📚 Next Steps

1. ✅ Run installer: `python3 install.py`
2. ✅ Open http://localhost:8000
3. ✅ Login and change password
4. ✅ Configure Netbox (if you have one)
5. ✅ Add SNMP credentials
6. ✅ Start discovering devices!

## 🎓 Learning Resources

- **Installation**: This file
- **Configuration**: config/config.yaml (well-commented)
- **API Reference**: Open /api endpoint in dashboard
- **Troubleshooting**: See QUICK_REFERENCE.md
- **Architecture**: See architecture_summary.md

## 📝 File Locations

- **Main config**: `config/config.yaml`
- **Device inventory**: `config/devices.yaml`
- **Alert rules**: `config/rules.yaml`
- **Environment**: `.env`
- **Docker Compose**: `docker-compose.yml`
- **Nginx config**: `nginx/nginx.conf` and `nginx/default.conf`
- **API code**: `backend/` directory
- **Frontend code**: `frontend/src/` directory
- **Persistent data**: `data/` directory

## 🎉 Success Criteria

Your installation is successful when:

✅ http://localhost:8000 loads  
✅ Can login with admin/admin123  
✅ Dashboard shows "Healthy" status  
✅ Can view all tabs (Dashboard, Devices, etc.)  
✅ Devices are discoverable via Netbox or SNMP  
✅ Metrics flowing to Prometheus  
✅ Alerts can be created and viewed  

## 🆘 Support

**For issues:**
1. Check logs: `docker-compose logs -f`
2. Check health: `curl http://localhost:8080/admin/health`
3. Check connectivity: `docker-compose exec api curl -f http://localhost:8080/admin/health`
4. Review configuration: `cat config/config.yaml`

**Common fixes:**
- Services won't start → Check Docker/disk space → `docker-compose down -v && docker-compose up -d`
- Devices not appearing → Check Netbox token → `docker-compose logs api | grep netbox`
- API not responding → Check logs → `docker-compose logs api`
- Dashboard blank → Check browser console → Check API health

---

**That's it! You now have a production-grade network monitoring system deployed in minutes with a unified, beautiful dashboard!** 🚀

Enjoy monitoring your network! 🎉
