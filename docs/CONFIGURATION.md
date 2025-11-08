# Jarvis Messenger - Advanced Configuration Guide

Comprehensive guide for configuring and tuning Jarvis Messenger.

**Created by orpheus497**

**Version:** 2.3.0

---

## Table of Contents

1. [Configuration Overview](#configuration-overview)
2. [Configuration File Format](#configuration-file-format)
3. [Network Configuration](#network-configuration)
4. [Security Configuration](#security-configuration)
5. [Performance Tuning](#performance-tuning)
6. [Connection Pooling](#connection-pooling)
7. [Message Batching](#message-batching)
8. [Search Optimization](#search-optimization)
9. [Backup Configuration](#backup-configuration)
10. [Environment Variables](#environment-variables)
11. [Troubleshooting](#troubleshooting)

---

## Configuration Overview

Jarvis supports configuration through:

1. **TOML configuration file** (`config.toml`)
2. **Environment variables** (prefixed with `JARVIS_`)
3. **Command-line arguments**

**Priority Order** (highest to lowest):
1. Command-line arguments
2. Environment variables
3. Configuration file
4. Default values

**Configuration Location:**
- Linux/macOS: `~/.jarvis/config.toml`
- Windows: `%APPDATA%\Jarvis\config.toml`

---

## Configuration File Format

Create `~/.jarvis/config.toml`:

```toml
# Jarvis Messenger Configuration
# Created by orpheus497

[network]
# P2P network settings
listen_port = 5000
ipc_port = 5999
max_connections = 50
connection_timeout = 30
reconnect_interval = 60
enable_upnp = true
enable_stun = true
enable_mdns = true

[network.pooling]
# Connection pooling configuration
enabled = true
max_size = 50
min_size = 5
idle_timeout = 300  # 5 minutes
health_check_interval = 60  # 1 minute
reuse_threshold = 100

[security]
# Security and rate limiting
enable_rate_limiting = true
messages_per_minute = 60
connections_per_ip = 3
ban_threshold = 10
ban_duration = 3600  # 1 hour
enable_ip_filtering = true
whitelist = []  # Add trusted IPs
blacklist = []  # Add blocked IPs

[encryption]
# Cryptographic settings
enable_double_ratchet = true
enable_post_quantum = false  # Requires liboqs-python
argon2_time_cost = 3
argon2_memory_cost = 65536  # 64 MB
argon2_parallelism = 4

[messages]
# Message handling
max_message_size = 10485760  # 10 MB
max_text_size = 102400  # 100 KB
enable_batching = true
batch_size = 100
batch_timeout = 1.0  # seconds
queue_max_size = 1000
queue_max_age = 604800  # 7 days

[files]
# File transfer configuration
enable_file_transfer = true
max_file_size = 104857600  # 100 MB
chunk_size = 1048576  # 1 MB
transfer_timeout = 300  # 5 minutes
retry_attempts = 3

[search]
# Search engine configuration
enable_caching = true
cache_max_size = 1000
cache_ttl = 300  # 5 minutes
results_per_page = 50
max_results = 1000

[backup]
# Automatic backup settings
enabled = true
interval = 86400  # 24 hours
retention_days = 30
max_backups = 10
compression_level = 6

[voice]
# Voice message settings (requires optional dependencies)
enabled = false
max_duration = 300  # 5 minutes
sample_rate = 44100
channels = 1

[ui]
# User interface settings
refresh_rate = 10  # Hz
max_history = 1000
notification_timeout = 5
typing_timeout = 3
enable_animations = true

[logging]
# Logging configuration
level = "INFO"  # DEBUG, INFO, WARNING, ERROR
max_bytes = 10485760  # 10 MB
backup_count = 5
log_to_file = true
log_to_console = true
```

---

## Network Configuration

### Basic Network Settings

```toml
[network]
listen_port = 5000  # P2P listening port
ipc_port = 5999  # IPC communication port
max_connections = 50  # Maximum concurrent connections
connection_timeout = 30  # Seconds before connection timeout
reconnect_interval = 60  # Seconds between reconnection attempts
```

### NAT Traversal

```toml
[network]
enable_upnp = true  # Automatic port mapping
enable_stun = true  # Public IP discovery
enable_mdns = true  # Local peer discovery

# STUN servers (default list used if not specified)
stun_servers = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
]
```

**Environment Variables:**
```bash
export JARVIS_LISTEN_PORT=5000
export JARVIS_IPC_PORT=5999
export JARVIS_ENABLE_UPNP=true
```

---

## Security Configuration

### Rate Limiting

```toml
[security]
enable_rate_limiting = true
messages_per_minute = 60  # Max messages per minute per contact
connections_per_ip = 3  # Max connections from same IP
ban_threshold = 10  # Failed attempts before ban
ban_duration = 3600  # Ban duration in seconds
```

### IP Filtering

```toml
[security]
enable_ip_filtering = true

# Whitelist (trusted IPs, bypasses rate limits)
whitelist = [
    "192.168.1.100",
    "10.0.0.5",
]

# Blacklist (blocked IPs)
blacklist = [
    "203.0.113.0/24",  # Example block
]
```

### Encryption

```toml
[encryption]
enable_double_ratchet = true  # Forward secrecy
enable_post_quantum = false  # Post-quantum crypto (requires liboqs-python)

# Argon2id parameters (password hashing)
argon2_time_cost = 3  # Iterations
argon2_memory_cost = 65536  # Memory in KB (64 MB)
argon2_parallelism = 4  # Threads
```

**Security Recommendations:**
- Keep `enable_double_ratchet = true` for forward secrecy
- Increase `argon2_time_cost` and `argon2_memory_cost` for stronger protection
- Use IP whitelisting for known contacts
- Enable `enable_post_quantum = true` for quantum resistance (requires installation)

---

## Performance Tuning

### Connection Pooling

Connection pooling reduces overhead by reusing established connections.

```toml
[network.pooling]
enabled = true
max_size = 50  # Maximum pooled connections
min_size = 5  # Minimum connections to maintain
idle_timeout = 300  # Seconds before recycling idle connection
health_check_interval = 60  # Health check frequency (seconds)
reuse_threshold = 100  # Max reuses before forced refresh
```

**Tuning Guidelines:**

| Contacts | max_size | min_size | idle_timeout |
|----------|----------|----------|--------------|
| 1-10     | 20       | 2        | 600          |
| 10-50    | 50       | 5        | 300          |
| 50-100   | 100      | 10       | 180          |
| 100+     | 200      | 20       | 120          |

**Environment Variables:**
```bash
export JARVIS_POOL_MAX_SIZE=50
export JARVIS_POOL_MIN_SIZE=5
export JARVIS_IDLE_TIMEOUT=300
```

### Message Batching

Message batching processes multiple messages in a single operation.

```toml
[messages]
enable_batching = true
batch_size = 100  # Messages per batch
batch_timeout = 1.0  # Max seconds to wait for batch
queue_max_size = 1000  # Maximum queued messages
```

**Tuning for Different Scenarios:**

**High-Volume Messaging:**
```toml
batch_size = 200
batch_timeout = 0.5
queue_max_size = 2000
```

**Low-Latency Priority:**
```toml
batch_size = 10
batch_timeout = 0.1
queue_max_size = 500
```

**Balanced (Default):**
```toml
batch_size = 100
batch_timeout = 1.0
queue_max_size = 1000
```

---

## Search Optimization

### Search Caching

Search result caching significantly improves repeat query performance.

```toml
[search]
enable_caching = true
cache_max_size = 1000  # Maximum cached queries
cache_ttl = 300  # Cache lifetime (seconds)
results_per_page = 50  # Results per page
max_results = 1000  # Maximum total results
```

**Cache Performance Tuning:**

For **large message histories** (100K+ messages):
```toml
cache_max_size = 2000
cache_ttl = 600
results_per_page = 100
```

For **limited resources**:
```toml
cache_max_size = 500
cache_ttl = 120
results_per_page = 25
```

**Cache Statistics:**

Monitor cache effectiveness:
```python
stats = search_engine.get_cache_statistics()
print(f"Hit rate: {stats['hit_rate']:.2%}")
print(f"Size: {stats['size']}/{stats['max_size']}")
```

---

## Backup Configuration

### Automatic Backups

```toml
[backup]
enabled = true
interval = 86400  # 24 hours
retention_days = 30  # Keep backups for 30 days
max_backups = 10  # Maximum backup files
compression_level = 6  # gzip level (0-9)
```

**Backup Strategies:**

**Minimal (space-constrained):**
```toml
retention_days = 7
max_backups = 3
compression_level = 9
```

**Standard:**
```toml
retention_days = 30
max_backups = 10
compression_level = 6
```

**Archival (maximum retention):**
```toml
retention_days = 90
max_backups = 30
compression_level = 3
```

### Manual Backups

Create backup via CLI:
```bash
jarvis-cli backup create --password mypassword
```

Via Python API:
```python
backup_path = backup_manager.create_backup(password="mypassword")
```

---

## Environment Variables

All configuration options can be overridden with environment variables.

**Format:** `JARVIS_<SECTION>_<KEY>=value`

**Examples:**

```bash
# Network
export JARVIS_NETWORK_LISTEN_PORT=5000
export JARVIS_NETWORK_ENABLE_UPNP=true
export JARVIS_NETWORK_MAX_CONNECTIONS=100

# Security
export JARVIS_SECURITY_MESSAGES_PER_MINUTE=30
export JARVIS_SECURITY_BAN_THRESHOLD=5

# Connection Pooling
export JARVIS_POOLING_MAX_SIZE=75
export JARVIS_POOLING_IDLE_TIMEOUT=180

# Message Batching
export JARVIS_MESSAGES_BATCH_SIZE=150
export JARVIS_MESSAGES_BATCH_TIMEOUT=0.8

# Search Caching
export JARVIS_SEARCH_CACHE_MAX_SIZE=1500
export JARVIS_SEARCH_CACHE_TTL=600

# Backup
export JARVIS_BACKUP_ENABLED=true
export JARVIS_BACKUP_INTERVAL=43200  # 12 hours

# Logging
export JARVIS_LOGGING_LEVEL=DEBUG
```

---

## Troubleshooting

### Connection Pooling Issues

**Problem:** Connections timing out frequently

**Solution:**
```toml
[network.pooling]
idle_timeout = 600  # Increase timeout
health_check_interval = 30  # More frequent checks
```

**Problem:** High memory usage

**Solution:**
```toml
[network.pooling]
max_size = 25  # Reduce pool size
reuse_threshold = 50  # Recycle connections more often
```

### Message Batching Issues

**Problem:** Messages delayed

**Solution:**
```toml
[messages]
batch_timeout = 0.1  # Reduce batch wait time
batch_size = 10  # Smaller batches
```

**Problem:** High CPU usage

**Solution:**
```toml
[messages]
batch_size = 50  # Reduce batch size
batch_timeout = 2.0  # Less frequent processing
```

### Search Performance Issues

**Problem:** Slow search queries

**Solution:**
```toml
[search]
enable_caching = true
cache_max_size = 2000
results_per_page = 25  # Reduce page size
```

**Problem:** High memory usage

**Solution:**
```toml
[search]
cache_max_size = 500
cache_ttl = 120
max_results = 500
```

### Performance Monitoring

Check system resource usage:

```bash
# Connection pool statistics
jarvis-cli stats connection-pool

# Message batch statistics
jarvis-cli stats message-batching

# Search cache statistics
jarvis-cli stats search-cache

# Overall system stats
jarvis-cli stats all
```

---

## DHT Bootstrap Configuration

The Distributed Hash Table (DHT) enables peer discovery over the internet without a central server.

### Setting Up Bootstrap Nodes

To use DHT, you need at least one bootstrap node to join the network:

**Option 1: Use existing nodes (if available):**
```toml
[dht]
enabled = true
port = 6881
bootstrap_nodes = [
    ["dht.example.com", 6881],
    ["192.0.2.100", 6881]
]
```

**Option 2: Set up your own bootstrap node:**
1. Run Jarvis on a server with a static IP
2. Configure firewall to allow port 6881
3. Share your IP and port with friends
4. Everyone adds your node as a bootstrap node

**Option 3: Peer-to-peer bootstrap:**
- Each user adds their own node as a bootstrap node
- Share your public IP:port with contacts
- Gradually builds a distributed network

### DHT Configuration Options

```toml
[dht]
# Enable/disable DHT
enabled = true

# Port for DHT communication
port = 6881

# Bootstrap nodes (at least one recommended)
bootstrap_nodes = [
    ["friend1.ddns.net", 6881],
    ["192.0.2.50", 6881]
]

# Number of nodes to replicate data to
replication_factor = 3

# How often to refresh DHT entries (seconds)
refresh_interval = 300
```

### Troubleshooting DHT

**DHT not discovering peers:**
1. Verify firewall allows port 6881
2. Check bootstrap nodes are reachable
3. Ensure at least one bootstrap node configured
4. Enable DEBUG logging to see DHT activity

**Finding your public IP for DHT:**
```bash
# Jarvis will auto-detect via STUN
# Or manually check:
curl ifconfig.me
```

---

## Voice Message Configuration

Voice messages require optional audio dependencies.

### Installing Audio Dependencies

**Linux:**
```bash
# Install system audio libraries
sudo apt-get install portaudio19-dev libsndfile1

# Install Python packages
pip install sounddevice soundfile
```

**macOS:**
```bash
# Install via Homebrew
brew install portaudio libsndfile

# Install Python packages
pip install sounddevice soundfile
```

**Windows:**
```bash
# Python packages (includes binaries)
pip install sounddevice soundfile
```

### Enabling Voice Messages

After installing dependencies, enable in config:

```toml
[features]
voice_messages = true

[voice]
max_duration = 300  # 5 minutes
sample_rate = 44100
channels = 1  # Mono
chunk_duration = 10  # seconds
```

### Voice Configuration Options

```toml
[voice]
# Maximum recording duration (seconds)
max_duration = 300

# Audio quality
sample_rate = 44100  # 44.1 kHz (CD quality)
# sample_rate = 22050  # 22 kHz (voice quality, smaller files)

# Channels (1 = mono, 2 = stereo)
channels = 1

# Chunk size for streaming (seconds)
chunk_duration = 10

# Audio format for storage
# format = "FLAC"  # Lossless compression
# format = "OGG"   # Lossy compression, smaller files
```

### Troubleshooting Voice Messages

**ImportError: No module named 'sounddevice':**
```bash
pip install sounddevice soundfile
```

**PortAudio library not found:**
```bash
# Linux
sudo apt-get install portaudio19-dev

# macOS
brew install portaudio
```

**No audio devices found:**
```bash
# List available audio devices
python -m sounddevice
```

---

## Advanced Scenarios

### High-Performance Configuration

For powerful systems with many contacts:

```toml
[network.pooling]
max_size = 200
min_size = 20
idle_timeout = 120

[messages]
batch_size = 200
batch_timeout = 0.5
queue_max_size = 5000

[search]
cache_max_size = 5000
cache_ttl = 900
results_per_page = 100
```

### Resource-Constrained Configuration

For limited resources (e.g., Raspberry Pi):

```toml
[network.pooling]
max_size = 10
min_size = 2
idle_timeout = 900

[messages]
batch_size = 25
batch_timeout = 2.0
queue_max_size = 250

[search]
cache_max_size = 250
cache_ttl = 180
results_per_page = 20
```

### Privacy-Focused Configuration

Maximum security and privacy:

```toml
[security]
enable_rate_limiting = true
messages_per_minute = 30
connections_per_ip = 1
ban_threshold = 3
enable_ip_filtering = true

[encryption]
enable_double_ratchet = true
enable_post_quantum = true
argon2_time_cost = 5
argon2_memory_cost = 131072  # 128 MB

[messages]
queue_max_age = 86400  # 1 day only

[backup]
enabled = true
interval = 21600  # Every 6 hours
```

---

## Configuration Validation

Validate configuration:

```bash
jarvis-cli config validate
```

Show effective configuration (including defaults):

```bash
jarvis-cli config show
```

Generate default configuration file:

```bash
jarvis-cli config generate > ~/.jarvis/config.toml
```

---

## License

MIT License - See LICENSE file.

**Created by orpheus497**
