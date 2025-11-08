# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **CRITICAL:** Fixed nonce reuse vulnerability in file transfer encryption (file_transfer.py)
  - Replaced deterministic hash-based nonce generation with cryptographically secure random nonces using secrets.token_bytes()
  - Prevents catastrophic nonce reuse attacks in ChaCha20Poly1305 encryption
  - Each file chunk now uses a unique random nonce
- **CRITICAL:** Complete redesign of session management system with encryption and expiration (session.py)
  - Sessions now encrypted with AES-256-GCM using master password-derived key
  - Added HMAC-SHA256 integrity verification for tamper detection
  - Implemented automatic session expiration (7-day absolute timeout, 24-hour idle timeout)
  - Sessions validated on load with expiration and integrity checks
  - Replaced insecure plaintext JSON storage with encrypted binary format
- **HIGH:** Fixed DoS vulnerability in Double Ratchet skip key management (ratchet.py)
  - Implemented aggressive batch cleanup removing 20% of old keys when limit exceeded (not just one)
  - Added timestamp-based expiration for skipped message keys (1-hour lifetime)
  - Enhanced DoS protection against memory exhaustion attacks via message gap manipulation
  - Improved logging for skip key operations and cleanup events
- **HIGH:** Fixed SQLite thread safety vulnerability in message queue (message_queue.py)
  - Added threading.Lock for all database operations
  - Prevents concurrent access to SQLite connection preventing database corruption
  - Protects against race conditions in multi-threaded environment
  - All database operations now atomic and thread-safe
- **HIGH:** Fixed synchronous I/O blocking on message critical path (message.py)
  - Implemented write-behind caching with intelligent batching
  - Messages now saved every 10 messages or every 5 seconds (whichever comes first)
  - Reduces file I/O operations by ~90% under normal load
  - Added flush() method for explicit persistence control
  - Prevents message loss via dirty flag tracking
- **HIGH:** Fixed exception handling and deprecated APIs in network layer (network.py)
  - Replaced bare except clauses with specific exception types in writer cleanup
  - Fixed deprecated asyncio.get_event_loop() calls (replaced with time.time())
  - Added exception handler for unreferenced async state change callback tasks
  - Prevents silent task exception loss and improves error visibility
- **MEDIUM:** Fixed path traversal vulnerability in backup restoration (backup.py)
  - Added _safe_extract() method to validate tar members before extraction
  - Prevents malicious backups from extracting files outside target directory (CWE-22)
  - Validates all member paths against extraction directory
  - Rejects absolute paths and parent directory references
- **MEDIUM:** Strengthened backup encryption key derivation (backup.py)
  - Increased PBKDF2-HMAC-SHA256 iterations from 100,000 to 600,000
  - Meets OWASP 2023 recommendations (exceeds NIST minimum of 210,000)
  - Provides stronger protection against brute-force attacks on backup passwords

### Fixed
- Fixed file transfer encryption to use secrets module for cryptographically secure nonce generation
- Fixed silent exception swallowing in session management preventing error detection
- Fixed broad exception handling in crypto module (crypto.py)
  - Replaced generic Exception catches with specific exception types (KeyError, ValueError, UnicodeDecodeError)
  - Added proper exception chaining using 'from e' syntax for better debugging
  - Distinguishes between authentication failures and other cryptographic errors
- Fixed bare except clauses in utils module (utils.py)
  - Replaced bare except with specific exceptions (ValueError, TypeError, AttributeError)
  - Added logging for timestamp parsing failures
  - Improved error handling in format_timestamp and format_timestamp_relative functions
- Fixed exception handling in Double Ratchet decryption (ratchet.py)
  - Added input validation for ciphertext length
  - Separated authentication failures from other decryption errors
  - Improved error messages with context
- Fixed thread safety issues in message queue (message_queue.py)
  - All database operations now protected by threading.Lock
  - Added exc_info=True to exception logging for better debugging
  - Improved error handling with specific exception information
- Fixed synchronous I/O blocking in message storage (message.py)
  - Every message addition no longer triggers immediate file write
  - Implemented intelligent batching based on count and time
  - Added dirty flag tracking to prevent unnecessary saves
- Fixed bare except clauses in network layer (network.py)
  - Replaced 2 bare except clauses with specific exception handling (OSError, RuntimeError, asyncio.CancelledError)
  - Added debug logging for writer cleanup failures
  - Prevents catching SystemExit and KeyboardInterrupt
- Fixed deprecated asyncio.get_event_loop() usage in network layer (network.py)
  - Replaced 7 instances of deprecated asyncio.get_event_loop().time() with time.time()
  - Modernized timing code to use standard library time module
  - Eliminates deprecation warnings and improves compatibility
- Fixed unreferenced async task in connection state callbacks (network.py)
  - Added exception handler callback to state change notification tasks
  - Prevents silent loss of exceptions in async callbacks
  - Added _handle_callback_exception method for proper error logging
- Fixed path traversal vulnerability in backup restoration (backup.py)
  - tar.extractall() now replaced with validated extraction
  - Added _safe_extract() method to check all tar member paths
  - Prevents CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
  - Rejects dangerous paths containing ".." or absolute paths
- Added proper error handling and logging to file transfer operations
- Added OSError-specific exception handling for file I/O operations in file transfer
- Session manager now uses atomic file writes (temp file + rename) to prevent corruption

### Changed
- File transfer nonce generation now uses secrets.token_bytes() instead of deterministic hashing
- Session storage migrated from plaintext JSON to AES-256-GCM encrypted format with HMAC
- Session tokens now generated using secrets.token_urlsafe() for improved security
- Enhanced exception handling in file transfer with proper error propagation using 'from e' syntax
- Improved logging throughout file transfer and session management modules
- Double Ratchet skip key storage now includes timestamps for expiration tracking
- Ratchet skip key cleanup now removes batches of old keys instead of single keys
- Message queue now uses threading.Lock for thread-safe database access
- All message queue methods now protected against concurrent access
- Message storage now uses write-behind caching with configurable batch size
- Message persistence strategy changed from immediate to batched writes
- Network layer timing now uses time.time() instead of deprecated asyncio.get_event_loop().time()
- Network layer writer cleanup now uses specific exception types instead of bare except
- Connection state callbacks now properly track and log async task exceptions
- Backup restoration now uses validated extraction instead of direct tar.extractall()
- Backup PBKDF2 key derivation increased from 100,000 to 600,000 iterations

### Added
- Atomic file writes in session manager to prevent data corruption during crashes
- Session expiration mechanism with configurable absolute and idle timeouts
- Session revocation API for disabling compromised sessions
- HMAC-based integrity verification for encrypted session files
- Cleanup method for removing expired sessions
- Enhanced file transfer error messages with context and troubleshooting information
- Time-based expiration for Double Ratchet skipped message keys
- Aggressive batch cleanup for skip keys to prevent DoS attacks
- Cleanup methods for expired and oldest skip keys in ratchet
- Enhanced logging throughout ratchet, crypto, and utils modules
- Exception handler callback (_handle_callback_exception) for async state change notifications in network layer
- Debug logging for network writer cleanup failures
- Path traversal protection via _safe_extract() method in backup restoration
- Validation for tar member paths to prevent directory escape attacks
- **NEW:** Comprehensive application metrics and monitoring system (metrics.py)
  - ApplicationMetrics class for centralized metric collection
  - Thread-safe counters, gauges, and histograms
  - Health check monitoring for all components
  - Historical data retention (60-minute rolling window)
  - Per-connection quality metrics (latency, throughput, packet loss)
  - Quality indicators (1-5 bars) based on connection performance
  - Metric snapshots for trending and analysis
  - Global singleton pattern for easy access (get_app_metrics())
- **NEW:** Metrics integration throughout application subsystems
  - Network layer (network.py) tracks connection attempts, successes, failures, and active connections
  - File transfer (file_transfer.py) tracks files sent/received/failed, transfer duration, and file sizes
  - Message handling tracks messages sent/received/failed/queued/delivered
  - Connection quality tracking with latency histograms
  - Error tracking by category (network, crypto, I/O errors)
  - Incoming/rejected connection monitoring
  - Queue-based message delivery tracking

### Performance
- Reduced memory usage in Double Ratchet by removing expired skip keys automatically
- Improved skip key cleanup efficiency with batch operations
- **Reduced message storage I/O by ~90%** through write-behind caching
- Batched message writes (every 10 messages or 5 seconds) drastically improve throughput
- Eliminated file I/O bottleneck on message receive critical path

## [2.4.0] - 2025-11-08

### Security
- Fixed critical command injection vulnerability in notification system (notification.py)
- Notification system now sanitizes all user-supplied input before shell command construction
- macOS notifications sanitize input for AppleScript safety
- Windows notifications sanitize input for PowerShell and XML safety
- Linux and Termux notifications validate input parameters
- Replaced SHA-1 with SHA-256 (truncated to 160 bits) in Kademlia DHT node ID generation (discovery.py)
- Added comprehensive input sanitization system to prevent injection attacks across all modules

### Fixed
- Version inconsistency resolved: pyproject.toml synchronized to version 2.4.0
- Version inconsistency resolved: __init__.py updated to 2.4.0
- Version inconsistency resolved: constants.py updated to 2.4.0
- Notification system injection vulnerabilities patched with input validation and sanitization
- Dependency duplication resolved: sounddevice, soundfile, and pyzbar moved to optional dependencies only

### Added
- New sanitization module (sanitization.py) with comprehensive input validation
- Input sanitization for shell commands preventing command injection attacks
- Input sanitization for AppleScript preventing script injection
- Input sanitization for XML/HTML preventing markup injection
- Input sanitization for terminal display preventing ANSI escape sequence attacks
- Timeout parameters added to all subprocess calls to prevent hanging operations
- Logging statements added to notification system for production debugging
- Optional dependency groups in pyproject.toml for voice and QR features
- Voice dependencies (sounddevice, soundfile) now installable via `pip install jarvis-messenger[voice]`
- QR dependencies (pyzbar) now installable via `pip install jarvis-messenger[qr]`
- All features installable via `pip install jarvis-messenger[all]`

### Changed
- Application version synchronized to 2.4.0 across all module docstrings
- Protocol version updated from 2.1 to 2.3 for consistency with application version
- QR code feature flag enabled (FEATURE_QR_CODES = True) reflecting fully implemented scanning functionality
- Voice message feature flag documentation updated with installation instructions reference
- Feature flag comments enhanced with version annotations and implementation status
- Configuration module documentation version updated to 2.4.0
- README version badge and header updated to 2.4.0
- requirements.txt version comment updated to 2.4.0
- DHT bootstrap node configuration updated with comprehensive setup documentation
- Bootstrap nodes default list now includes configuration instructions and documentation reference

### Added
- Systemd service file for Linux daemon deployment (deployment/systemd/jarvis-server.service)
- Systemd service includes security hardening directives (NoNewPrivileges, PrivateTmp, ProtectSystem)
- Systemd service includes resource limits (LimitNOFILE, TasksMax)
- Docker support with multi-stage Dockerfile for minimal image size (deployment/docker/Dockerfile)
- Docker image runs as non-root user for enhanced security
- Docker health check for container monitoring
- Docker Compose configuration for simplified deployment (deployment/docker/docker-compose.yml)
- Docker Compose includes resource limits and health checks
- Docker Compose volume configuration for persistent data storage
- Dockerignore file for optimized build context (deployment/docker/.dockerignore)
- Installation script with dependency checking and automated setup (scripts/install.sh)
- Installation script supports both user and system-wide installation
- Installation script includes optional systemd service setup
- Health check script for monitoring daemon status with exit codes (scripts/health-check.sh)
- Health check supports multiple validation methods (nc, Python socket)
- Configuration template file with comprehensive options and documentation (config.toml.example)
- Configuration template includes all feature categories with inline comments
- Type hint marker file (src/jarvis/py.typed) for improved IDE support and type checking
- Deployment documentation with Docker, systemd, and manual deployment instructions (docs/DEPLOYMENT.md)
- Deployment documentation includes security considerations and troubleshooting
- Deployment documentation covers firewall configuration and network security
- DHT bootstrap configuration section in CONFIGURATION.md with setup instructions
- DHT bootstrap documentation includes three setup options (existing nodes, own node, peer-to-peer)
- DHT troubleshooting guide with common issues and solutions
- Voice message configuration section in CONFIGURATION.md with installation instructions
- Voice message setup instructions for Linux, macOS, and Windows platforms
- Voice message audio dependency installation guide
- Voice message configuration options with quality and format settings
- Voice message troubleshooting section with common audio issues
- Configuration documentation version updated to 2.4.0

### Fixed
- Version inconsistency resolved: All module docstrings updated from 2.0.0 to 2.4.0
- Feature flag accuracy: QR_CODES flag now reflects actual implementation status
- Documentation accuracy: All version references synchronized to 2.4.0

### Removed
- SUMMARY.txt file (outdated documentation referencing v2.1.0)

## [2.3.0] - 2025-11-08

### Added
- **QR Code Scanning:** Complete implementation of QR code scanning from image files using pyzbar library
- pyzbar>=0.1.9 dependency for QR code decoding functionality
- scan_qr_code() function in qr_code.py with support for PNG, JPG, and other image formats
- Automatic detection and decoding of multiple QR codes in single image (uses first valid code)
- Comprehensive error handling for missing files, invalid images, and decode failures
- **Kademlia DHT Implementation:** Full Kademlia-based distributed hash table for internet peer discovery
- KBucket class implementing k-bucket routing table with contact management
- 160-bit ID space using SHA-1 for Kademlia standard compatibility
- XOR distance metric for node proximity calculation
- Local storage with automatic expiration (24-hour TTL)
- Periodic maintenance loop for cleaning expired DHT entries
- Bootstrap node support for network joining
- Announce and find_peer methods with local caching
- Comprehensive DHT statistics (total contacts, bucket utilization, storage size)
- **DHT Network RPCs:** Complete network communication layer for Kademlia DHT
- RPC server listening on configurable port (default 6881) for DHT operations
- PING RPC for node liveness checking
- STORE RPC for storing key-value pairs on remote nodes
- FIND_NODE RPC for discovering closest nodes to target ID
- FIND_VALUE RPC for iterative value lookup across DHT
- Iterative lookups with concurrent queries (ALPHA=3 parameter)
- Bootstrap process with automatic peer discovery
- RPC statistics tracking (ping, store, find_node, find_value counts)
- Network announce with distribution to K closest nodes
- Comprehensive error handling and timeouts for all RPCs
- **Advanced Metrics Visualization:** ASCII-based charts and graphs for terminal display
- BarChart widget for visualizing metric distributions with horizontal bars
- SparklineChart widget for showing metric trends over time
- GaugeChart widget for displaying percentage-based metrics
- Automatic value scaling and formatting (K/M suffixes)
- Support for multiple data series in charts
- Visual quality indicators based on metric thresholds
- Real-time chart updates with data refresh methods
- **Connection Metrics Integration:** NetworkManager.get_connection_metrics() method for retrieving per-peer connection statistics
- Connection metrics now properly displayed in UI statistics dashboard
- Latency, throughput, packet loss, and quality indicators available per contact
- Graceful handling of unavailable metrics with status indicators
- **Connection Pooling:** ConnectionPool and ConnectionPoolEntry classes in network.py implementing connection reuse, health checking, idle timeout, and automatic connection recycling for network efficiency
- Connection pool configuration constants in constants.py: CONNECTION_POOL_MAX_SIZE (50), CONNECTION_POOL_MIN_SIZE (5), CONNECTION_IDLE_TIMEOUT (300s), CONNECTION_HEALTH_CHECK_INTERVAL (60s), CONNECTION_REUSE_THRESHOLD (100)
- ConnectionPool health check background task with automatic removal of unhealthy and idle connections
- Connection reuse tracking and statistics (total_connections, healthy_connections, idle_connections, average_reuse_count)
- **Search Result Caching:** SearchResultCache class in search.py implementing LRU cache with TTL expiration for search query results
- Search cache configuration constants in constants.py: SEARCH_CACHE_MAX_SIZE (1000), SEARCH_CACHE_TTL (300s), SEARCH_CACHE_CLEANUP_INTERVAL (60s)
- LRU eviction policy in search cache with automatic removal of oldest entries when max size reached
- TTL-based expiration with automatic cleanup of expired cache entries
- Cache statistics tracking (hits, misses, hit_rate, size, max_size, ttl)
- get_cache_statistics() and clear_cache() methods in MessageSearchEngine for cache management
- **Performance Features:** Feature flags in constants.py for connection pooling (FEATURE_CONNECTION_POOLING), message batching (FEATURE_MESSAGE_BATCHING), and search caching (FEATURE_SEARCH_CACHING)
- **API Reference Documentation:** Complete docs/API.md covering all modules, classes, and functions with usage examples and parameter documentation
- **Advanced Configuration Guide:** Comprehensive docs/CONFIGURATION.md with TOML configuration, environment variables, performance tuning, troubleshooting, and scenario-specific configurations

### Changed
- scan_qr_code() in qr_code.py now fully functional (replaced placeholder implementation)
- SimpleDHT class upgraded from placeholder to full Kademlia implementation with routing table, storage, and network RPCs
- DHT announce() now distributes peer information to K closest nodes via STORE RPC
- DHT find_peer() now performs iterative lookups across network using FIND_VALUE RPC
- DHT start() now launches RPC server and bootstrap process with automatic peer discovery
- UI statistics dashboard now retrieves actual connection metrics instead of placeholder zeros
- Connection status indicators enhanced to show "disconnected" or "metrics_unavailable" when data not available
- Statistics displays can now include visual charts (bar charts, sparklines, gauges) for better data comprehension
- NetworkManager now initializes ConnectionPool instance for managing P2P connections
- NetworkManager.start_server() now starts connection pool health checks automatically
- NetworkManager.stop_server() now stops connection pool health checks and clears pool on shutdown
- MessageSearchEngine.__init__() now accepts enable_cache parameter (default: True) to control result caching
- MessageSearchEngine.search() now checks cache before database query and stores results in cache after query
- All search methods (search, search_by_contact, search_by_date) now benefit from automatic result caching

### Dependencies
- Added pyzbar>=0.1.9 (MIT license) for QR code scanning from image files

## [2.2.0] - 2025-11-08

### Fixed
- **CRITICAL:** Silent exception handling in contact persistence (contact.py:95-96, 104-105) preventing error detection and causing potential data loss
- **CRITICAL:** Silent exception handling in message persistence (message.py:124-125, 141-142) preventing error detection and causing potential data loss
- **CRITICAL:** Silent exception handling in group persistence (group.py:149-150, 158-159) preventing error detection and causing potential data loss
- **HIGH:** Resource leak in message_queue.py where database connections never closed properly leading to file descriptor exhaustion
- **HIGH:** Unbounded send queue and receive buffer in network.py allowing memory exhaustion via DoS attacks
- **MEDIUM:** Platform incompatibility in server.py using SIGTERM signal unavailable on Windows
- **MEDIUM:** Inadequate IP validation in utils.py accepting loopback, multicast, link-local, and reserved addresses
- All file I/O operations now use UTF-8 encoding explicitly to prevent character encoding issues across platforms
- All save operations now use atomic file writes (write to temporary file then rename) to prevent data corruption during crashes or interruptions
- Corrupted JSON files in persistence layer now handled gracefully (logs warning and continues) instead of crashing
- README installation instructions now reference correct repository name (jarvisapp instead of jarvis)
- Repository clone path corrected from `orpheus497/jarvis` to `orpheus497/jarvisapp`
- pyproject.toml project URLs now point to jarvisapp repository
- README networking section removed external IP discovery via curl ifconfig.me
- Markdown formatting standardized across README sections

### Added
- Async file I/O methods using aiofiles library for non-blocking persistence operations in contact.py, message.py, and group.py
- Comprehensive error logging throughout contact, message, and group management modules with info, debug, and error levels
- Specific exception handling (IOError, OSError, JSONDecodeError) replacing broad exception catching to prevent masking critical errors
- Type hints added to all public methods in contact.py, message.py, and group.py (return types, parameter types) for improved IDE support and type safety
- Logging statements throughout persistence layer providing visibility into save operations, load operations, and error conditions
- Message and contact deletion operations now log counts of items deleted for auditability
- Contact manager now provides both async and sync versions of save methods (save_contacts_async, mark_online_async, mark_offline_async)
- Message store now provides both async and sync versions of save methods (save_messages_async)
- Group manager save operations enhanced with detailed logging
- Context manager support (__enter__, __exit__) for MessageQueue class enabling proper resource cleanup with Python 'with' statement
- Resource limits in network.py: SEND_QUEUE_MAX_SIZE (1000 messages) and RECEIVE_BUFFER_MAX_SIZE (1MB) to prevent memory exhaustion
- Platform-specific signal handling in server.py supporting both Unix SIGTERM and Windows SIGBREAK
- IPv6 support in IP address validation alongside existing IPv4 support
- Configurable IP validation parameters: allow_private and allow_loopback flags in utils.validate_ip()
- Queue timeout handling (5 second timeout) in network.py send operations preventing indefinite blocking
- Buffer overflow protection in network.py receive loop disconnecting connections exceeding 1MB buffer
- Complete UI color palette documentation including red, white, black, grey, purple, cyan, and amber
- docs/COLORS.md with detailed color usage across status indicators, banners, messages, and actions
- docs/DEPENDENCIES.md with comprehensive FOSS dependency attributions, licenses, and upstream links
- Link to docs/COLORS.md in README Interface section
- Link to docs/DEPENDENCIES.md in README Acknowledgements section
- License information for all dependencies in README
- **File Transfer Integration:** Complete server-side file transfer handling in server.py using FileTransferSession for chunked, encrypted file transfers
- **Search Engine Integration:** MessageSearchEngine initialization in server.py enabling SQLite FTS5 full-text search across message history
- **File Transfer Handlers:** _handle_send_file(), _handle_get_file_transfers(), and _handle_cancel_file_transfer() methods with validation and progress tracking
- **Search Handlers:** _handle_search_messages(), _handle_search_by_contact(), and _handle_search_by_date() methods using MessageSearchEngine
- **UI Search Integration:** Search screen now connected to MessageSearchEngine via client_adapter for full-text search with highlighting
- **UI File Transfer Integration:** File transfer screen now populated with active transfers from server including progress information
- FileTransferSession import in server.py for managing file transfer state and chunking
- MessageSearchEngine import in server.py for SQLite-based message search
- **Async Identity I/O:** save_identity_async() method in identity.py using aiofiles for non-blocking file operations
- Comprehensive logging throughout identity.py (load, save, export, delete operations) with info, debug, warning, and error levels
- Specific exception handling in identity.py (CryptoError, JSONDecodeError, IOError) for better error diagnosis
- Atomic file writes in export_complete_account() to prevent corruption during export operations
- **Quality Tooling:** Complete pyproject.toml configuration for black, ruff, mypy, pytest, and coverage
- **Pre-commit Hooks:** .pre-commit-config.yaml with ruff, mypy, security checks (bandit), and file validation
- **Test Infrastructure:** conftest.py with pytest fixtures for temp directories, sample data, and test markers
- **Example Tests:** test_utils.py demonstrating test infrastructure with 30+ unit tests for validation functions
- **CONTRIBUTING.md:** Comprehensive contributor guidelines with development setup, workflow, code style, and testing guidelines
- **ARCHITECTURE.md:** Detailed system architecture documentation with diagrams, data flow, security architecture, and component descriptions
- **Comprehensive Docstrings:** Google-style docstrings added to critical server.py methods with Args, Returns, Raises, and Note sections
- Detailed docstrings for start(), stop(), run(), _handle_client(), _process_command(), _handle_login(), _handle_send_message()
- Detailed docstrings for _handle_send_file(), _handle_search_messages() documenting file transfer and search functionality
- Enhanced return type hints throughout server.py (-> None, -> bool, -> Dict[str, Any]) for IDE support

### Changed
- All persistence save methods now use atomic file writes (temp file + rename) for data safety and crash resistance
- Contact manager save operations now available in both synchronous and asynchronous versions for compatibility
- Message store save operations now available in both synchronous and asynchronous versions for compatibility
- Identity manager save operations now available in both synchronous and asynchronous versions for compatibility
- All file operations in identity.py now use explicit UTF-8 encoding and proper error handling
- All file operations now include proper error handling with specific exception types and error logging
- Error messages now provide actionable context and stack traces instead of silent failures
- File load operations now handle corrupted JSON gracefully by logging warning and starting with empty data instead of crashing application
- MessageQueue.close() method now includes type hint (-> None) for IDE support
- P2PConnection.send_queue initialization changed from unbounded Queue() to Queue(maxsize=1000) preventing memory exhaustion
- P2PConnection send operations (send_message, send_group_message, ping, pong) now use 5-second timeout instead of blocking indefinitely
- IP validation in utils.py migrated from regex-based approach to Python ipaddress module for RFC-compliant validation
- IP validation now rejects loopback (127.0.0.0/8, ::1), unspecified (0.0.0.0, ::), reserved, link-local (169.254.0.0/16, fe80::/10), and multicast addresses by default
- Signal handler setup in server.py now detects platform and uses appropriate signal (SIGTERM on Unix, SIGBREAK on Windows)
- README networking guidance now emphasizes built-in NAT traversal (UPnP/STUN) and local OS tools
- README Interface section explicitly documents complete color palette with usage descriptions
- README Acknowledgements section references centralized dependency documentation
- Networking section reorganized with automatic NAT traversal as primary method

### Security
- Data persistence operations now use atomic file writes to prevent corruption during crashes or interruptions
- Proper exception handling prevents information leakage through uncontrolled error messages
- All file I/O operations validate and handle errors before proceeding to prevent undefined behavior
- UTF-8 encoding explicitly specified to prevent encoding-based injection attacks
- Resource limits (queue size, buffer size) prevent denial-of-service attacks via memory exhaustion
- Database connections in MessageQueue now properly closed via context manager preventing file descriptor leaks
- Receive buffer overflow protection in P2PConnection prevents malicious peers from exhausting memory
- Send queue limits prevent backpressure-based denial-of-service attacks
- IP validation now rejects dangerous address ranges (loopback, reserved, multicast, link-local) preventing connection to invalid endpoints
- Enhanced IP validation using Python ipaddress module provides RFC-compliant security checking

## [2.1.0] - 2025-10-31

### Fixed
- **CRITICAL:** Application crash when server already running on subsequent logins
- Network port conflicts on re-login resolved
- Server detection reliability improved with comprehensive health checks
- Multiple UI instances can now connect to the same server simultaneously
- Server persistence across UI restarts working correctly

### Added
- **Daemon Manager** - Professional server lifecycle management (415 lines)
  - Cross-platform daemon control (Windows + Unix)
  - Reliable server detection (PID + port + connectivity verification)
  - Graceful startup/shutdown with configurable timeouts
  - Health monitoring and detailed status reporting
  - Automatic cleanup of stale state
  - Implemented in `daemon_manager.py` module
  
- **NAT Traversal** - Automatic internet connectivity (438 lines)
  - UPnP IGD automatic port mapping for routers
  - STUN protocol for public IP discovery
  - NAT type detection (7 different types supported)
  - Connection strategy selection based on network topology
  - Multiple STUN servers with automatic fallback
  - Automatic port mapping cleanup on shutdown
  - Implemented in `nat_traversal.py` module
  
- **Connection State Machine** - Reliable connection management (360 lines)
  - Formal finite state machine with 8 connection states
  - 14 events for proper state transitions
  - Comprehensive transition validation
  - Per-state timeout handling
  - State history tracking (last 100 transitions)
  - Statistics and diagnostics for debugging
  - Callback support for state change notifications
  - Implemented in `connection_fsm.py` module
  
- **Message Queue** - Offline message delivery (426 lines)
  - SQLite-based persistent queue for reliability
  - Automatic expiration (7 days configurable)
  - Exponential backoff retry logic for failed deliveries
  - Delivery receipt tracking
  - Queue size limits per recipient (1000 messages)
  - Statistics and monitoring APIs
  - Automatic cleanup of expired messages
  - Implemented in `message_queue.py` module
  
- **Peer Discovery** - Automatic LAN peer finding (490 lines)
  - mDNS/DNS-SD service for local network discovery
  - Automatic peer announcement and detection
  - Real-time peer discovery with callbacks
  - Peer freshness tracking with configurable TTL
  - Automatic address updates for discovered peers
  - SimpleDHT placeholder for future internet discovery
  - Statistics and monitoring
  - Implemented in `discovery.py` module
  
- **Security Manager** - Internet security hardening (475 lines)
  - Pre-authentication challenge-response (HMAC-SHA256)
  - IP whitelisting and blacklisting support
  - Temporary IP banning with configurable duration
  - Connection limits per IP address
  - Aggressive rate limiting for internet connections
  - Security event logging with 1000-event history
  - Failed attempt tracking with auto-ban
  - Implemented in `security_manager.py` module

### Changed
- Server now persists across UI restarts for better reliability
- Logout no longer stops the network server (preserves connections)
- Network manager reused instead of recreated on re-login
- Enhanced logging throughout all modules for better debugging
- Improved error messages with actionable troubleshooting steps
- Connection handling redesigned with FSM for robustness
- Network initialization includes NAT traversal and peer discovery

### Dependencies
- Added `miniupnpc>=2.2.4` for UPnP port mapping (BSD 3-Clause license)
- Added `pystun3>=1.0.0` for STUN protocol (MIT license)
- Added `zeroconf>=0.131.0` for mDNS discovery (LGPL 2.1 license)
- Added `validators>=0.22.0` for input validation (MIT license)
- Added `aiofiles>=23.2.1` for async file I/O (Apache 2.0 license)

### Technical Details
- Protocol version updated to 2.1
- Application version updated to 2.1.0
- Added 50+ new constants for v2.1.0 features
- Total new code: 2,604 lines across 6 modules
- All modules fully integrated into network layer
- Complete error handling and logging in all new code
- Cross-platform compatibility maintained

## [2.0.0] - 2025-10-31

### Added
- **Double Ratchet algorithm** for forward and backward secrecy
  - Signal Protocol-style ratcheting with X25519 Diffie-Hellman
  - Automatic per-message key rotation
  - Separate sending and receiving chains
  - Message keys deleted after use to prevent retroactive decryption
  - Implemented in `ratchet.py` module (557 lines)
- **Encrypted file transfer system** with chunking and resume capability
  - Files split into 1MB chunks for efficient transmission
  - Each chunk encrypted with five-layer encryption
  - Progress tracking with callbacks
  - Automatic retry on failure
  - SHA-256 checksum verification
  - Resume support for interrupted transfers
  - Implemented in `file_transfer.py` module (538 lines)
- **Full-text message search** using SQLite FTS5
  - Instant search across all messages and conversations
  - Filter by contact, date range, or message content
  - Result highlighting and context display
  - Pagination support for large result sets
  - Automatic migration from JSON to SQLite storage
  - Implemented in `search.py` module (300+ lines)
- **Configuration system** with TOML file support
  - User-configurable settings in `config.toml`
  - Environment variable overrides (JARVIS_* prefix)
  - Sensible defaults for all settings
  - Network tuning (ports, timeouts, buffer sizes)
  - UI customization (theme, colors, display options)
  - Backup scheduling configuration
  - Notification preferences
  - Logging configuration
  - Implemented in `config.py` module (300 lines)
- **Automatic encrypted backup system**
  - Scheduled automatic backups (configurable interval)
  - Separate backup password for additional security
  - Compressed archives (tar.gz with encryption)
  - Automatic rotation policy (keep last N backups)
  - Manual backup trigger
  - Full restore functionality
  - Backup verification and integrity checks
  - Implemented in `backup.py` module (300+ lines)
- **Rate limiting and abuse prevention**
  - Token bucket algorithm implementation
  - Per-contact message rate limits (configurable)
  - Per-IP connection rate limits
  - Automatic ban for rate limit violations
  - Ban expiration and management
  - Whitelist support
  - Protection against DoS attacks
  - Implemented in `rate_limiter.py` module (250+ lines)
- **Connection quality metrics and monitoring**
  - Real-time latency measurement
  - Throughput calculation
  - Connection quality indicators (1-5 bars)
  - Packet loss detection
  - Network statistics tracking
  - Performance diagnostics
  - Implemented in `metrics.py` module (200+ lines)
- **Voice message support** (optional feature)
  - Audio recording via microphone
  - Voice encoding for efficient transmission
  - Waveform visualization
  - Playback controls
  - Duration limiting (configurable maximum)
  - Requires sounddevice and soundfile libraries
  - Implemented in `voice.py` module (250+ lines)
- **QR code contact sharing**
  - Generate QR codes from contact cards
  - ASCII art display in terminal
  - PNG export for sharing
  - Scan with mobile device camera
  - Same security as traditional contact exchange
  - Requires qrcode and pillow libraries
  - Implemented in `qr_code.py` module (150+ lines)
- **Message reactions and emoji support**
  - React to messages with emojis
  - Multiple reactions per message
  - Real-time reaction updates
  - Reaction count display
  - Unicode emoji set support
  - New message types: REACTION, REACTION_REMOVE
- **Typing indicators**
  - Real-time typing status display
  - Automatic timeout (configurable)
  - Privacy-respecting (only for active conversations)
  - New message type: TYPING_INDICATOR
- **Rich text formatting** with Markdown support
  - Bold, italic, strikethrough formatting
  - Inline code and code blocks
  - Link display (non-clickable for security)
  - Syntax highlighting in code blocks
  - Backward compatible with plain text
  - Uses Rich library's Markdown renderer
- **Statistics dashboard**
  - Total messages sent/received
  - Data transfer statistics
  - Connection uptime tracking
  - Active contacts list
  - Most active contacts ranking
  - Message frequency visualization
  - Reset statistics option
- **Enhanced error system** with structured error codes
  - Comprehensive error code catalog (E001-E899)
  - Detailed error messages with context
  - Error code categories (crypto, network, identity, etc.)
  - Suggested solutions for common errors
  - Error serialization for IPC
  - Implemented in `errors.py` module (253 lines)
- **Centralized constants module**
  - All magic numbers extracted to constants
  - Network configuration constants
  - Cryptography parameters
  - Rate limiting values
  - File transfer settings
  - UI configuration
  - Backup parameters
  - Implemented in `constants.py` module (148 lines)
- **Additional UI components and screens**
  - File transfer progress widgets
  - Search interface with filtering
  - Statistics dashboard screen
  - Configuration management screen
  - Backup management interface
  - Connection quality indicators
  - Enhanced error dialogs
  - Implemented in `ui_components.py` (300+ lines) and `ui_screens.py` (400+ lines)
- **Comprehensive test infrastructure**
  - 390+ test cases across 10 test modules
  - 5,060+ lines of test code
  - Unit tests for all new modules
  - Integration tests for end-to-end workflows
  - Edge case and error condition coverage
  - Async test support with pytest-asyncio
  - Thread safety tests
  - Performance and load tests
  - Test fixtures and mocking infrastructure
  - Target coverage >70%

### Changed
- **Message storage** migrated from JSON to SQLite
  - Efficient storage for large message histories
  - Full-text search support with FTS5
  - Backward compatibility (automatic JSON import)
  - Improved query performance
  - Transaction support for data integrity
- **Protocol extended** with new message types
  - FILE_START, FILE_CHUNK, FILE_END, FILE_CANCEL - file transfer
  - FILE_REQUEST, FILE_ACCEPT, FILE_REJECT - file transfer handshake
  - VOICE_MESSAGE, VOICE_CHUNK - voice message streaming
  - REACTION, REACTION_REMOVE - message reactions
  - TYPING_INDICATOR - typing status
  - Total message types increased from 20 to 35
- **Network layer enhanced** with monitoring and protection
  - Rate limiter integration for all connections
  - Connection metrics collection
  - Enhanced error messages with error codes
  - Message size validation (max 10MB)
  - Latency measurement
  - Throughput tracking
  - Quality of service indicators
- **Crypto module extended** with Double Ratchet support
  - Optional ratchet mode for forward secrecy
  - Backward compatible with five-layer encryption
  - Post-quantum crypto support (optional, requires liboqs-python)
  - Enhanced key management
  - Key rotation policies
- **Server enhanced** with new command handlers
  - File transfer commands (send, receive, cancel)
  - Search commands (query, filter, paginate)
  - Backup commands (create, restore, list, delete)
  - Voice message commands
  - Configuration commands
  - Statistics commands
  - Rate limiter integration for all operations
- **Client adapter extended** for new features
  - Async/sync wrappers for file transfer
  - Search API methods
  - Backup management methods
  - Voice message methods
  - Reaction methods
  - Statistics retrieval
  - Configuration access
- **UI significantly enhanced** with new features
  - File transfer interface with progress tracking
  - Search dialog with filtering options
  - Statistics dashboard with visualizations
  - Configuration editor
  - Backup management screen
  - Connection quality display
  - Rich text rendering with Markdown
  - Enhanced error display with error codes
  - Voice message recording and playback controls
  - QR code display for contact sharing
- **Dependency updates** to latest stable versions
  - textual 0.47.1 → 0.90.0 (major UI improvements)
  - cryptography 42.0.4 → 44.0.0 (security updates)
  - rich 13.7.0 → 13.9.4 (formatting enhancements)
  - Added pyperclip 1.9.0 (was missing)
  - Added tomli 2.2.1 (TOML support for Python <3.11)
  - Added zstandard 0.23.0 (compression support)
- **Version number** incremented to 2.0.0
  - Major version due to significant new features
  - Semantic versioning compliance
  - Updated in all relevant files

### Security
- **Forward secrecy** implemented via Double Ratchet
  - Past messages cannot be decrypted even if current keys compromised
  - Automatic key rotation per message
  - Protection against future quantum computers (with liboqs-python)
- **Rate limiting** protects against abuse
  - Connection flooding prevention
  - Message spam prevention
  - Automatic ban for violations
  - Configurable thresholds
- **Message size limits** prevent memory exhaustion
  - Maximum message size enforced (10MB)
  - Maximum file size enforced (100MB default, configurable)
  - Protocol-level validation
  - Protection against resource exhaustion attacks
- **Encrypted backups** with separate password
  - Backup files encrypted independently
  - Optional different password for backups
  - Protection against backup theft
  - Secure deletion of old backups
- **Enhanced error handling** prevents information leakage
  - Structured error messages without sensitive data
  - Error codes instead of detailed exceptions
  - Context provided without compromising security
  - Secure logging practices

### Fixed
- SyntaxError in server.py caused by duplicate `async` keywords in async context managers
  - Fixed line 159: async with self.client_lock (stop method)
  - Fixed line 199: async with self.client_lock (handle_client method)
  - Fixed line 243: async with self.client_lock (handle_client cleanup)
  - Fixed line 253: async def _process_command method definition
- AttributeError in ui.py from non-existent ContactCardManager.export_contact_to_card method
  - Removed dead code in _show_contact_info that attempted to export other contacts' cards
  - Only user's own identity can be exported per design specifications
- TypeError from improper async/sync bridging in UI workflows
  - Fixed load_identity_worker to use await with connect_to_server_async()
  - Fixed load_identity_worker to use await with login_async()
  - Fixed load_identity_worker to use await with disconnect_from_server_async()
  - Fixed _show_settings to use await with client.delete_account()
  - Fixed _show_settings to use await with logout_async() and disconnect_from_server_async()
  - Fixed action_quit to run async _quit_app worker with proper cleanup
  - Fixed _connect_to_contact to use await with connect_to_peer_async()
- Code structure issues in client_adapter.py
  - Removed duplicate ServerManagedContactManager class definition (200 lines of redundant code)
  - Removed duplicate ServerManagedGroupManager class definition
  - Removed misplaced methods that were incorrectly placed after group manager
  - File reduced from 692 lines to 492 lines with no functionality loss
- Connection status synchronization issues
  - Added _connection_cache dictionary to ClientAdapter for sync access
  - Modified _handle_connection_state_event to update cache automatically
  - Fixed is_connected() to use cached state instead of attempting async calls from sync context
  - Connection status now properly reflects actual peer connectivity in UI

### Changed
- Converted entire networking architecture from threading to asyncio per technical blueprint
  - **Phase 1 - P2P Network Layer (network.py):**
    - P2P connections use asyncio.open_connection() and asyncio.start_server()
    - All threading.Thread replaced with asyncio.Task
    - Network I/O uses asyncio StreamReader/StreamWriter
    - Non-blocking operations with async/await syntax
    - Connection health monitoring with detailed statistics
    - Comprehensive error handling and logging
    - Exponential backoff for reconnection attempts
    - Proper timeout handling and graceful degradation
  - **Phase 2 - Server IPC Layer (server.py):**
    - IPC server uses asyncio.start_server()
    - All command handlers converted to async coroutines
    - Client handling uses asyncio tasks
    - Event broadcasting fully async
    - Server lifecycle methods (start, stop, run) are async
    - asyncio.run() entry point for daemon
    - Comprehensive error handling and logging
  - **Phase 3 - Client IPC Layer (client.py):**
    - Client connection uses asyncio.open_connection()
    - All public API methods are async coroutines
    - Receive loop runs as asyncio task
    - Request/response uses asyncio.Queue
    - Event callbacks support both sync and async
    - Proper connection cleanup and task cancellation
  - **Phase 4 - Client Adapter (client_adapter.py):**
    - Async/sync bridging for UI compatibility
    - All methods available in async and sync versions
    - Detects running event loop (Textual) vs standalone
    - ServerManagedContactManager with async/sync wrappers
    - ServerManagedGroupManager with async/sync wrappers
    - Maintains NetworkManager-compatible interface
  - Unified asynchronous architecture for integration with Textual UI framework
  - All I/O operations non-blocking throughout application

## [1.2.0] - 2025-10-26

### Added
- Client-server architecture for persistent connections
  - Background server process maintains P2P connections continuously
  - Foreground UI acts as client connecting to background server
  - IPC communication between client and server using JSON-RPC over sockets
  - Server process runs independently and persists when UI closes
  - Single server instance per data directory managed via PID file
  - Automatic server startup when launching UI
  - Server manages all network connections, identity, contacts, messages, and groups
- Server daemon module (`jarvis.server`)
  - Background server process for maintaining P2P connections
  - IPC interface for client communication (default port: 5999)
  - Command handling for all operations (messaging, contacts, groups, identity)
  - Event broadcasting to connected clients for real-time updates
  - PID file management for single instance enforcement
  - Signal handlers for graceful shutdown
  - Unread message tracking and synchronization
  - Mark messages as read functionality
  - Unread count queries per contact, group, and total
- Client API module (`jarvis.client`)
  - Client interface for communicating with background server
  - Asynchronous event handling for server broadcasts
  - Synchronous request-response pattern for commands
  - Event callback system for real-time notifications
  - Complete unread message API support
- Client adapter module (`jarvis.client_adapter`)
  - Compatibility layer providing NetworkManager-like interface
  - Server-managed contact and group managers
  - Minimal changes to UI code required
- Server entry point (`jarvis-server` command)
  - Can be run independently for debugging or advanced usage
  - Supports custom data directory and IPC port configuration
- Connection status indicators with four levels
  - GREEN: All connections active (all peers online and connected)
  - AMBER: Partial connections (some peers online, messages can be sent/received)
  - RED: No active connections (server running but no peers connected)
  - GREY: Server offline (cannot send or receive messages)
- Automatic connection establishment on login
  - Connects to all contacts automatically when user logs in
  - Establishes group connections for all group members
  - Connection status notifications show successful/failed connections
  - Real-time connection status display in main UI
- Connection status indicator in main UI
  - Shows "X/Y online" where X is connected contacts and Y is total
  - Color-coded: green (all connected), yellow (some connected), red (none connected)
  - Updates automatically when connection states change
- Complete account export functionality
  - Export entire account including identity, contacts, messages, and groups
  - Encrypted export preserving all account data
- Connection status tracking for contacts and groups
  - `get_connection_status()` method for individual contacts
  - `get_group_connection_status()` method for groups
  - Real-time status updates based on active connections
- Account deletion functionality with password confirmation
  - Delete identity and all cryptographic keys
  - Delete all contacts
  - Delete all messages (direct and group)
  - Delete all groups
- Lock feature (Ctrl+L) to secure the application when stepping away
  - Keeps network connections active while UI is locked
  - Password verification required to unlock
  - Visual lock screen with animated banner
- Individual contact and group management
  - ContactDetailsScreen for viewing and managing individual contacts
  - GroupDetailsScreen for viewing and managing individual groups
  - Delete individual contacts via Ctrl+I then Delete button or Ctrl+D
  - Delete individual groups via Ctrl+I then Delete button or Ctrl+D
  - View contact status, host, port, fingerprint, and verification status
  - View group members, creation date, and description
- Contact card file sharing system (.jcard format)
  - ContactCardManager utility class for import/export operations
  - Export own identity as contact card from Settings screen
  - Only user's own contact card can be exported (not others' cards)
  - Import contact cards from Add Contact screen
  - Contact cards stored in contact_cards directory within data directory
  - JSON-based .jcard file format with version and type validation
  - Includes UID, username, public key, fingerprint, host, port
- Copy functionality throughout the application
  - Copy UID from Settings screen
  - Copy fingerprint from Settings screen
  - Copy link code from Settings screen
  - Copy contact UID from contact details
  - Copy contact fingerprint from contact details
  - Copy group ID from group details
- Animated ASCII banner on main application screen
  - Matches welcome screen banner for consistency
  - Cycles through color scheme: white, red, bright_white, dark red, purple, grey
- Connection notifications
  - Notifies user when contacts connect/disconnect
  - Shows connection attempts for new contacts
  - Reports connection success/failure with counts
- User guidance throughout application
  - Welcome screen explains password recovery warning
  - Welcome screen explains port configuration and requirements
  - Add Contact screen provides step-by-step instructions
  - Add Contact screen explains each input field purpose
  - Connection troubleshooting information in README
- Error handling for UI operations
  - Contact selection wrapped in try-except to prevent crashes
  - Message sending includes network availability checks
  - Detailed error messages for failed operations
- Keyboard shortcuts for contact and group management
  - Ctrl+I to view contact or group details
  - Ctrl+D to delete current contact or group

### Changed
- Application architecture refactored to client-server model
  - Server process handles all P2P networking in background
  - UI process acts as lightweight client
  - Connections persist even when UI is closed
  - Multiple UI instances can connect to same server
- Main entry point starts server automatically if not running
  - Checks for existing server via PID file
  - Launches detached server process in background
  - UI connects to server via IPC
- Network initialization now automatically connects to all contacts
  - Removed manual connection requirement
  - Reports connection statistics on startup
- Connection state changes now update UI status display
  - Real-time feedback on peer connectivity
  - Automatic UI refresh on connection events
- Message sending provides better feedback
  - Shows reason for failure (not connected, no members online)
  - Reports number of recipients for group messages
- Contact addition now triggers automatic connection attempt
  - New contacts are immediately available for messaging
  - Connection status updates reflect new contact
- LoadIdentityScreen provides comprehensive guidance
  - Password recovery warning prominently displayed
  - Port configuration explained with examples
  - Subtitle added for clearer identity
- AddContactScreen reorganized for clarity
  - Instructions prioritize easiest methods first
  - Each method clearly separated with labels
  - Warnings about fingerprint verification prominent
- Connection stability and background processing
- Connection management runs in background threads
- Simultaneous host/client P2P model ensures reliable connectivity
- Online status detection based on active peer-to-peer connections
- Settings screen displays UID and fingerprint in copyable input fields
- Settings screen includes Copy UID and Copy Fingerprint buttons
- Settings screen includes Export Contact Card button
- Settings screen includes Export Account button for complete backup
- Contact Details screen no longer exports other contacts' cards
- Add Contact screen includes Import Contact Card button
- Add Contact screen includes Paste from Clipboard button
- Keyboard shortcuts include lock feature (Ctrl+L), info (Ctrl+I), and delete (Ctrl+D)

### Fixed
- Connections now persist across UI restarts
  - Background server maintains connections continuously
  - UI can be closed and reopened without disconnecting from contacts
  - Server handles reconnection logic automatically
- Connections between separate devices now establish automatically
  - Critical bug: `connect_all_contacts()` was defined but never called
  - Server would start but never initiate outgoing connections
  - Contacts on different devices would never detect each other
  - Now automatically connects on login and when contacts are added
- UI crashes from unhandled exceptions
  - Added try-except blocks around contact selection
  - Added try-except blocks around message sending
  - Added network availability checks before operations
- Missing connection status feedback
  - Users couldn't see which contacts were actually connected
  - No indication of connection attempts or failures
  - Status display now shows real-time connection information
- Group creation UI stability when selecting invitees
- Worker-related crashes in modal screens
- Connection state management and automatic reconnection
- P2P connection establishment between separate machine instances
  - Fixed client-side handshake flow to properly wait for HANDSHAKE_RESPONSE
  - Fixed server-side to receive and process client's HANDSHAKE message before sending response
  - Fixed connection state initialization for incoming connections
  - Ensured receive/send threads start only after connection is fully authenticated
  - Added proper socket timeout handling for persistent connections
  - Improved synchronization between connection endpoints

### Security
- Updated cryptography library from 41.0.7 to 42.0.4
  - Fixes NULL pointer dereference vulnerability (CVE-2024-0727)
  - Fixes Bleichenbacher timing oracle attack vulnerability (CVE-2023-50782)
  - All known vulnerabilities in dependencies resolved
- Server process runs with appropriate isolation
  - IPC communication restricted to localhost
  - PID file prevents multiple server instances
  - Server validates all client commands
- Lock feature maintains encryption and connection security
- Account deletion securely removes all sensitive data
- Password verification required for destructive operations
- Contact card files stored locally only, never transmitted automatically

### Removed
- Multi-device login system (parent-child sessions)
  - Removed SessionManagementScreen UI
  - Removed session type (parent/child) distinction
  - Removed identity export/import for child sessions
  - Removed "Export Identity" and "Manage Sessions" buttons from Settings
  - Simplified SessionManager to handle single session type
  - Simplified Identity export to complete account backup only

## [1.0.0] - 2025-10-25

### Added
- Connection status indicators with four levels
  - GREEN: All connections active (all peers online and connected)
  - AMBER: Partial connections (some peers online, messages can be sent/received)
  - RED: No active connections (server running but no peers connected)
  - GREY: Server offline (cannot send or receive messages)
- Automatic connection establishment on login
  - Connects to all contacts automatically when user logs in
  - Establishes group connections for all group members
- Complete account export functionality
  - Export entire account including identity, contacts, messages, and groups
  - Encrypted export preserving all account data
- Connection status tracking for contacts and groups
  - `get_connection_status()` method for individual contacts
  - `get_group_connection_status()` method for groups
  - Real-time status updates based on active connections
- Automatic connection to all contacts via `connect_all_contacts()` method
- Account deletion functionality with password confirmation
  - Delete identity and all cryptographic keys
  - Delete all contacts
  - Delete all messages (direct and group)
  - Delete all groups
- Lock feature (Ctrl+L) to secure the application when stepping away
  - Keeps network connections active while UI is locked
  - Password verification required to unlock
  - Visual lock screen with animated banner
- Individual contact and group management
  - ContactDetailsScreen for viewing and managing individual contacts
  - GroupDetailsScreen for viewing and managing individual groups
  - Delete individual contacts via Ctrl+I then Delete button or Ctrl+D
  - Delete individual groups via Ctrl+I then Delete button or Ctrl+D
  - View contact status, host, port, fingerprint, and verification status
  - View group members, creation date, and description
- Contact card file sharing system (.jcard format)
  - ContactCardManager utility class for import/export operations
  - Export own identity as contact card from Settings screen
  - Only user's own contact card can be exported (not others' cards)
  - Import contact cards from Add Contact screen
  - Contact cards stored in contact_cards directory within data directory
  - JSON-based .jcard file format with version and type validation
  - Includes UID, username, public key, fingerprint, host, port
- Copy functionality throughout the application
  - Copy UID from Settings screen
  - Copy fingerprint from Settings screen
  - Copy link code from Settings screen
  - Copy contact UID from contact details
  - Copy contact fingerprint from contact details
  - Copy group ID from group details
  - Paste from clipboard button in Add Contact screen
- Keyboard shortcuts for contact and group management
  - Ctrl+I to view contact or group details
  - Ctrl+D to delete current contact or group
- Complete account and data wipe functionality
- Delete Account button in Settings screen
- Comprehensive delete account dialog with warnings

### Changed
- Settings screen displays UID and fingerprint in copyable input fields
- Settings screen includes Copy UID and Copy Fingerprint buttons
- Settings screen includes Export Contact Card button
- Settings screen includes Export Account button for complete backup
- Contact Details screen no longer exports other contacts' cards
- Add Contact screen includes Import Contact Card button
- Add Contact screen includes Paste from Clipboard button
- Keyboard shortcuts with lock feature (Ctrl+L), info (Ctrl+I), and delete (Ctrl+D)
- Connection stability and background processing
- Connection management runs in background threads
- Simultaneous host/client P2P model ensures reliable connectivity
- Online status detection based on active peer-to-peer connections

### Fixed
- Group creation UI stability when selecting invitees
- Worker-related crashes in modal screens
- Connection state management and automatic reconnection
- P2P connection establishment between separate machine instances
  - Fixed client-side handshake flow to properly wait for HANDSHAKE_RESPONSE
  - Fixed server-side to receive and process client's HANDSHAKE message before sending response
  - Fixed connection state initialization for incoming connections
  - Ensured receive/send threads start only after connection is fully authenticated
  - Added proper socket timeout handling for persistent connections
  - Improved synchronization between connection endpoints

### Security
- Lock feature maintains encryption and connection security
- Account deletion securely removes all sensitive data
- Password verification required for destructive operations
- Contact card files stored locally only, never transmitted automatically

## [1.0.0] - 2025-10-25

### Added
- Textual-based terminal UI with interactive interface
- Animated ASCII banner with configurable color scheme
- Contact list with online/offline status indicators
- Interactive chat view with message history
- Link code generation system for simplified contact adding
- Link code copy-to-clipboard functionality
- Settings screen displaying identity information
- Group chat creation dialog with member selection
- Message input with send button and keyboard support
- Relative timestamp display
- Color-coded messages
- Group message sender identification
- Keyboard shortcuts (Ctrl+C, Ctrl+G, Ctrl+S, Ctrl+Q, Enter, Escape)
- Dark theme with black, red, grey, white, and dark purple color scheme

### Changed
- Contact adding workflow now supports link codes in addition to manual entry
- Message display now uses relative timestamps instead of absolute
- UI updated from command-line to full Textual TUI
- Action methods now properly use workers for async operations

### Fixed
- Settings screen crash when opening (NoActiveWorker error)
- Add contact screen crash (NoActiveWorker error)
- Create group screen crash (NoActiveWorker error)
- Network manager initialization with proper identity handling
- Message routing for both direct and group messages
- Connection state tracking and UI updates
- Message persistence across application restarts

## [0.1.0] - 2025-10-25

### Added
- Complete peer-to-peer encrypted messenger implementation
- Five-layer encryption architecture with AES-256-GCM and ChaCha20-Poly1305
- X25519 key exchange for secure session establishment
- Argon2id password hashing with memory-hard protection
- Command-line interface for all core functionality
- Direct P2P connections with no intermediary servers
- Group chat support with encrypted multi-party messaging
- Contact management with cryptographic verification
- Message persistence with encrypted local storage
- Cross-platform support (Linux, Windows, macOS, Termux)
- System notifications with platform-specific implementations
- Background operation capabilities
- Comprehensive documentation (README, SECURITY, TESTING)
- Installation scripts for automated setup
- Uninstallation scripts preserving user data
- Development build script with testing tools
- Complete test suite for core functionality
- MIT License for open-source distribution

### Security
- Five independent layers of encryption
- Unique session keys per connection
- Cryptographically secure random number generation
- Fingerprint verification for MITM protection
- Master password never stored on disk
- Encrypted identity storage at rest
- No network connections except direct P2P
- No telemetry, analytics, or tracking
- Zero external API dependencies

### Documentation
- README with comprehensive usage guide
- SECURITY policy with threat model
- TESTING procedures and guidelines
- QUICKREF with keyboard shortcuts
- Inline code documentation with detailed comments
- Installation instructions for all platforms
- Troubleshooting guide
- Network configuration guide
- Platform-specific notes

### Dependencies
- cryptography (Apache 2.0/BSD License) - Cryptographic primitives
- argon2-cffi (MIT License) - Password hashing
- pyperclip (MIT License) - Cross-platform clipboard support

All dependencies are free, open-source, and royalty-free.

---

## Project Information

**Created by:** orpheus497  
**License:** MIT  
**Philosophy:** Complete local control, no external dependencies, supreme security

**Inspired by:** pwick password manager architecture and security philosophy
