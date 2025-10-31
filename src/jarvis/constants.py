"""
Jarvis - Global Constants and Configuration Values

This module defines all constants used throughout the Jarvis application.
All magic numbers and configuration defaults are centralized here.

Author: orpheus497
Version: 2.0.0
"""

# Version Information
VERSION = "2.1.0"
APP_NAME = "Jarvis"
AUTHOR = "orpheus497"

# Network Constants
DEFAULT_SERVER_PORT = 5000
DEFAULT_HOST = "0.0.0.0"
LOCALHOST = "127.0.0.1"

# Connection Timeouts (seconds)
CONNECTION_TIMEOUT = 30
SOCKET_TIMEOUT = 10
HEARTBEAT_INTERVAL = 30
HEARTBEAT_TIMEOUT = 90

# Retry Configuration
MAX_RECONNECT_ATTEMPTS = 5
RECONNECT_DELAY = 5  # seconds
RECONNECT_BACKOFF_MULTIPLIER = 2
MAX_RECONNECT_DELAY = 300  # 5 minutes

# Message Limits
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_TEXT_MESSAGE_SIZE = 100 * 1024  # 100 KB
MAX_USERNAME_LENGTH = 64
MAX_GROUP_NAME_LENGTH = 100
MAX_CONTACT_NAME_LENGTH = 100

# Rate Limiting Constants
RATE_LIMIT_MESSAGES_PER_MINUTE = 60
RATE_LIMIT_MESSAGES_BURST = 10
RATE_LIMIT_CONNECTIONS_PER_MINUTE = 5
RATE_LIMIT_BAN_DURATION = 300  # 5 minutes in seconds
RATE_LIMIT_CLEANUP_INTERVAL = 60  # 1 minute

# File Transfer Constants
FILE_CHUNK_SIZE = 1024 * 1024  # 1 MB chunks
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
FILE_TRANSFER_TIMEOUT = 300  # 5 minutes
FILE_TRANSFER_RETRY_ATTEMPTS = 3
FILE_TRANSFER_RETRY_DELAY = 2  # seconds

# Cryptography Constants
KEY_SIZE = 32  # 256 bits for X25519
NONCE_SIZE = 12  # 96 bits for ChaCha20-Poly1305
SALT_SIZE = 16  # 128 bits
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
RATCHET_MAX_SKIP = 1000  # Maximum skipped message keys to store
RATCHET_MESSAGE_KEY_LIFETIME = 3600  # 1 hour in seconds

# Voice Message Constants
VOICE_MAX_DURATION = 300  # 5 minutes in seconds
VOICE_SAMPLE_RATE = 44100  # Hz
VOICE_CHANNELS = 1  # Mono
VOICE_CHUNK_DURATION = 10  # seconds

# Backup Configuration
BACKUP_RETENTION_DAYS = 30
BACKUP_MAX_COUNT = 10
BACKUP_COMPRESSION_LEVEL = 6  # gzip compression level (0-9)
BACKUP_SCHEDULE_INTERVAL = 86400  # 24 hours in seconds

# UI Configuration
UI_REFRESH_RATE = 10  # Hz
UI_MAX_MESSAGE_HISTORY = 1000
UI_NOTIFICATION_TIMEOUT = 5  # seconds
UI_TYPING_INDICATOR_TIMEOUT = 3  # seconds

# File Paths
DEFAULT_DATA_DIR = "~/.jarvis"
IDENTITY_FILENAME = "identity.json"
CONTACTS_FILENAME = "contacts.json"
GROUPS_FILENAME = "groups.json"
MESSAGES_DB_FILENAME = "messages.db"
CONFIG_FILENAME = "config.toml"
BACKUP_DIR = "backups"
LOGS_DIR = "logs"

# Logging Configuration
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Search Configuration
SEARCH_RESULTS_PER_PAGE = 50
SEARCH_MAX_RESULTS = 1000
SEARCH_CONTEXT_LINES = 2  # Lines before/after match

# Group Chat Constants
MAX_GROUP_MEMBERS = 100
MAX_GROUP_DESCRIPTION_LENGTH = 500

# Protocol Version
PROTOCOL_VERSION = "2.1"

# NAT Traversal Constants (v2.1.0)
NAT_DETECTION_TIMEOUT = 10  # seconds for STUN requests
UPNP_DISCOVERY_TIMEOUT = 3  # seconds for UPnP device discovery
UPNP_LEASE_DURATION = 3600  # 1 hour port mapping lease
UPNP_RENEWAL_INTERVAL = 1800  # 30 minutes (renew before expiry)
STUN_RETRY_ATTEMPTS = 3
STUN_RETRY_DELAY = 2  # seconds
HOLE_PUNCH_ATTEMPTS = 5
HOLE_PUNCH_INTERVAL = 1  # seconds

# Peer Discovery Constants (v2.1.0)
MDNS_SERVICE_TYPE = "_jarvis._tcp.local."
MDNS_ANNOUNCEMENT_INTERVAL = 60  # seconds
DHT_BOOTSTRAP_NODES = [
    # Will be populated with known stable nodes
]
DHT_REPLICATION_FACTOR = 3
DHT_REFRESH_INTERVAL = 300  # 5 minutes
DISCOVERY_CACHE_TTL = 600  # 10 minutes

# Connection State Machine Constants (v2.1.0)
STATE_TRANSITION_TIMEOUT = 30  # seconds
STATE_CONNECTING_TIMEOUT = 15  # seconds
STATE_AUTHENTICATING_TIMEOUT = 10  # seconds
STATE_RECONNECTING_DELAY = 5  # seconds

# Message Queue Constants (v2.1.0)
MESSAGE_QUEUE_MAX_SIZE = 1000  # per recipient
MESSAGE_QUEUE_MAX_AGE = 604800  # 7 days in seconds
MESSAGE_QUEUE_CLEANUP_INTERVAL = 3600  # 1 hour
MESSAGE_DELIVERY_RETRY_ATTEMPTS = 5
MESSAGE_DELIVERY_RETRY_DELAY = 10  # seconds

# Security Manager Constants (v2.1.0)
PREAUTH_CHALLENGE_TIMEOUT = 10  # seconds
IP_BAN_DURATION = 3600  # 1 hour
IP_BAN_THRESHOLD = 10  # failed attempts before ban
CONNECTION_LIMIT_PER_IP = 3
RATE_LIMIT_INTERNET_MESSAGES_PER_MINUTE = 30  # Stricter for internet
RATE_LIMIT_INTERNET_CONNECTIONS_PER_MINUTE = 2

# Feature Flags
FEATURE_DOUBLE_RATCHET = True
FEATURE_FILE_TRANSFER = True
FEATURE_VOICE_MESSAGES = False  # Requires optional dependencies
FEATURE_QR_CODES = False  # Requires optional dependencies
FEATURE_POST_QUANTUM_CRYPTO = False  # Requires optional dependencies
FEATURE_NAT_TRAVERSAL = True  # v2.1.0
FEATURE_PEER_DISCOVERY = True  # v2.1.0
FEATURE_MESSAGE_QUEUE = True  # v2.1.0
FEATURE_ENHANCED_SECURITY = True  # v2.1.0
