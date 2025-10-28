# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- Backup files from threading-to-asyncio refactoring cleanup
  - client_adapter_old.py (285 lines)
  - client_old_threading.py (564 lines)
  - network_old_threading.py (850 lines)
  - server_old_threading.py (1,126 lines)
  - Total cleanup: 2,825 lines of obsolete threading code
  - Refactoring to asyncio architecture fully complete

### Fixed
- Missing pyperclip dependency in setup.py install_requires
  - Added pyperclip>=1.8.2 to ensure clipboard functionality works correctly
  - Aligns setup.py with requirements.txt and actual code usage
- Documentation compliance issues per project requirements
  - Removed prohibited subjective language from CHANGELOG (words: better, improved)
  - Updated README.md requirements section to include pyperclip with version and license
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
  - Shows connection attempts for added contacts
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
- Message sending provides feedback on delivery status
  - Shows reason for failure (not connected, no members online)
  - Reports number of recipients for group messages
- Contact addition now triggers automatic connection attempt
  - Added contacts are immediately available for messaging
  - Connection status updates reflect added contact
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
  - Synchronization between connection endpoints corrected

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
  - Synchronization between connection endpoints corrected

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
