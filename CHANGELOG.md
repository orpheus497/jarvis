# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- README installation instructions now reference correct repository name (jarvisapp instead of jarvis)
- Repository clone path corrected from `orpheus497/jarvis` to `orpheus497/jarvisapp`
- pyproject.toml project URLs now point to jarvisapp repository
- README networking section removed external IP discovery via curl ifconfig.me
- Markdown formatting standardized across README sections

### Added
- Complete UI color palette documentation including red, white, black, grey, purple, cyan, and amber
- docs/COLORS.md with detailed color usage across status indicators, banners, messages, and actions
- docs/DEPENDENCIES.md with comprehensive FOSS dependency attributions, licenses, and upstream links
- Link to docs/COLORS.md in README Interface section
- Link to docs/DEPENDENCIES.md in README Acknowledgements section
- License information for all dependencies in README

### Changed
- README networking guidance now emphasizes built-in NAT traversal (UPnP/STUN) and local OS tools
- README Interface section explicitly documents complete color palette with usage descriptions
- README Acknowledgements section references centralized dependency documentation
- Networking section reorganized with automatic NAT traversal as primary method

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
