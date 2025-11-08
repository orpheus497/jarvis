# Jarvis - Deployment Guide

**Created by orpheus497**

This guide covers production deployment options for Jarvis P2P Encrypted Messenger.

---

## Table of Contents

1. [Deployment Options](#deployment-options)
2. [Docker Deployment](#docker-deployment)
3. [Systemd Deployment](#systemd-deployment)
4. [Manual Deployment](#manual-deployment)
5. [Security Considerations](#security-considerations)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)

---

## Deployment Options

Jarvis can be deployed in several ways:

- **Docker**: Containerized deployment with isolation and easy portability
- **Systemd**: Native Linux daemon for production servers
- **Manual**: Traditional Python installation with virtual environment

Choose based on your infrastructure and requirements.

---

## Docker Deployment

### Prerequisites

- Docker 20.10+ or Docker CE
- Docker Compose 1.29+ (optional but recommended)
- 1GB RAM minimum, 2GB recommended
- 5GB disk space

### Quick Start with Docker Compose

1. **Clone the repository:**
```bash
git clone https://github.com/orpheus497/jarvisapp.git
cd jarvisapp
```

2. **Create data directory:**
```bash
mkdir -p deployment/docker/data
```

3. **Create configuration (optional):**
```bash
cp config.toml.example deployment/docker/config.toml
# Edit config.toml as needed
```

4. **Start the container:**
```bash
cd deployment/docker
docker-compose up -d
```

5. **Check status:**
```bash
docker-compose ps
docker-compose logs -f jarvis-server
```

### Docker Build from Source

If you want to build the Docker image manually:

```bash
docker build -t jarvis:2.3.0 -f deployment/docker/Dockerfile .
```

Run the container:

```bash
docker run -d \
  --name jarvis-server \
  -p 5000:5000 \
  -p 5999:5999 \
  -p 6881:6881 \
  -v jarvis-data:/data/jarvis \
  -e JARVIS_LOG_LEVEL=INFO \
  jarvis:2.3.0
```

### Docker Configuration

Environment variables:

- `JARVIS_DATA_DIR`: Data directory (default: `/data/jarvis`)
- `JARVIS_LOG_LEVEL`: Logging level (default: `INFO`)
- `JARVIS_SERVER_PORT`: P2P port (default: `5000`)
- `JARVIS_IPC_PORT`: IPC port (default: `5999`)
- `JARVIS_DHT_PORT`: DHT port (default: `6881`)

### Docker Networking

**Bridge Mode (default):**
- Isolated network
- Port forwarding required
- Good for most use cases

**Host Mode (better P2P connectivity):**
```yaml
network_mode: host
```
- Direct access to host network
- No port mapping needed
- Better NAT traversal

### Docker Volumes

Persistent data is stored in Docker volumes:

```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect jarvis_jarvis-data

# Backup data
docker run --rm -v jarvis_jarvis-data:/data -v $(pwd):/backup alpine tar czf /backup/jarvis-backup.tar.gz /data

# Restore data
docker run --rm -v jarvis_jarvis-data:/data -v $(pwd):/backup alpine tar xzf /backup/jarvis-backup.tar.gz -C /
```

---

## Systemd Deployment

### Prerequisites

- Linux system with systemd
- Python 3.8+
- Root access for service installation

### Installation Script

Use the automated installation script:

```bash
sudo ./scripts/install.sh
```

This will:
1. Check dependencies
2. Create virtual environment
3. Install Jarvis
4. Create default configuration
5. Optionally install systemd service

### Manual Systemd Setup

1. **Create jarvis user:**
```bash
sudo useradd -r -s /bin/false -d /var/lib/jarvis jarvis
```

2. **Install Jarvis:**
```bash
sudo mkdir -p /opt/jarvis
sudo cp -r src /opt/jarvis/
sudo cp pyproject.toml README.md /opt/jarvis/
cd /opt/jarvis
sudo python3 -m venv venv
sudo venv/bin/pip install -e .
```

3. **Create data directory:**
```bash
sudo mkdir -p /var/lib/jarvis
sudo chown -R jarvis:jarvis /var/lib/jarvis
```

4. **Install service file:**
```bash
sudo cp deployment/systemd/jarvis-server.service /etc/systemd/system/
sudo systemctl daemon-reload
```

5. **Enable and start:**
```bash
sudo systemctl enable jarvis-server
sudo systemctl start jarvis-server
```

### Systemd Management

**Check status:**
```bash
sudo systemctl status jarvis-server
```

**View logs:**
```bash
sudo journalctl -u jarvis-server -f
```

**Restart service:**
```bash
sudo systemctl restart jarvis-server
```

**Stop service:**
```bash
sudo systemctl stop jarvis-server
```

---

## Manual Deployment

### Prerequisites

- Python 3.8+
- pip and venv
- 512MB RAM minimum

### Installation Steps

1. **Clone repository:**
```bash
git clone https://github.com/orpheus497/jarvisapp.git
cd jarvisapp
```

2. **Create virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# Or: venv\Scripts\activate.bat  # Windows
```

3. **Install dependencies:**
```bash
pip install --upgrade pip
pip install -e .
```

4. **Create configuration:**
```bash
mkdir -p ~/.jarvis
cp config.toml.example ~/.jarvis/config.toml
# Edit ~/.jarvis/config.toml as needed
```

5. **Run the server:**
```bash
# In the virtual environment
python -m jarvis.server --data-dir ~/.jarvis --ipc-port 5999
```

### Running as Background Process

**Using screen:**
```bash
screen -dmS jarvis python -m jarvis.server --data-dir ~/.jarvis
screen -r jarvis  # Attach to session
```

**Using nohup:**
```bash
nohup python -m jarvis.server --data-dir ~/.jarvis > jarvis.log 2>&1 &
```

**Using tmux:**
```bash
tmux new -d -s jarvis 'python -m jarvis.server --data-dir ~/.jarvis'
tmux attach -t jarvis
```

---

## Security Considerations

### Firewall Configuration

**Linux (ufw):**
```bash
# P2P messaging port
sudo ufw allow 5000/tcp

# DHT port (if using DHT)
sudo ufw allow 6881/tcp

# IPC port (localhost only - no firewall rule needed)
```

**Linux (iptables):**
```bash
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 6881 -j ACCEPT
```

### Network Security

1. **IPC Port (5999)**: Should ONLY be accessible from localhost
   - Never expose to internet
   - Use firewall to block external access
   - Docker: Don't publish this port

2. **P2P Port (5000)**: Requires internet access for P2P messaging
   - Must be accessible from internet for remote contacts
   - Configure port forwarding if behind NAT
   - Use UPnP if available (automatic)

3. **DHT Port (6881)**: Required for DHT peer discovery
   - Only needed if using DHT
   - Can be firewalled if not using DHT

### System Hardening

The systemd service includes security hardening:
- `NoNewPrivileges=true`: Prevents privilege escalation
- `PrivateTmp=true`: Private /tmp directory
- `ProtectSystem=strict`: Read-only system directories
- `ProtectHome=true`: No access to home directories
- Capability restrictions

### Data Protection

- All sensitive data encrypted at rest
- Master password never stored on disk
- Regular encrypted backups recommended
- Use strong master passwords (20+ characters)

---

## Monitoring

### Health Checks

Use the health check script:

```bash
./scripts/health-check.sh
```

Exit codes:
- `0`: Healthy
- `1`: Down (server not running)
- `2`: Degraded (server running but IPC not responsive)

### Docker Health Check

Built into Docker image:

```bash
docker inspect --format='{{.State.Health.Status}}' jarvis-server
```

### Systemd Health

Check service status:

```bash
systemctl is-active jarvis-server
systemctl is-failed jarvis-server
```

### Log Monitoring

**Docker:**
```bash
docker logs -f jarvis-server
```

**Systemd:**
```bash
journalctl -u jarvis-server -f
```

**Manual:**
```bash
tail -f ~/.jarvis/logs/jarvis.log
```

---

## Troubleshooting

### Server Won't Start

1. **Check logs:**
```bash
# Docker
docker logs jarvis-server

# Systemd
journalctl -u jarvis-server -n 50

# Manual
cat ~/.jarvis/logs/jarvis.log
```

2. **Check port availability:**
```bash
sudo lsof -i :5000
sudo lsof -i :5999
sudo lsof -i :6881
```

3. **Check permissions:**
```bash
# Systemd
ls -la /var/lib/jarvis

# Docker
docker exec jarvis-server ls -la /data/jarvis
```

### Connection Issues

1. **Verify server is running:**
```bash
./scripts/health-check.sh
```

2. **Check firewall:**
```bash
sudo ufw status  # Linux
sudo iptables -L  # Linux
```

3. **Test P2P connectivity:**
```bash
telnet your-ip 5000
```

### Performance Issues

1. **Check resource usage:**
```bash
# Docker
docker stats jarvis-server

# System
top -p $(pgrep -f jarvis.server)
```

2. **Increase resource limits:**
```yaml
# docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 2G
```

### Data Recovery

**From Docker volume:**
```bash
docker run --rm -v jarvis_jarvis-data:/data -v $(pwd):/backup alpine sh -c "cd /data && tar czf /backup/recovery.tar.gz ."
```

**From systemd:**
```bash
sudo tar czf jarvis-recovery.tar.gz /var/lib/jarvis
```

---

## Upgrading

### Docker

```bash
docker-compose pull
docker-compose down
docker-compose up -d
```

### Systemd

```bash
sudo systemctl stop jarvis-server
cd /opt/jarvis
git pull
sudo venv/bin/pip install -e . --upgrade
sudo systemctl start jarvis-server
```

### Manual

```bash
git pull
source venv/bin/activate
pip install -e . --upgrade
# Restart your background process
```

---

## Support

For deployment issues:
- GitHub Issues: https://github.com/orpheus497/jarvisapp/issues
- Documentation: https://github.com/orpheus497/jarvisapp
- README: https://github.com/orpheus497/jarvisapp/blob/main/README.md

**Created by orpheus497**
