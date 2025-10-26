# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Connection status indicators with four levels
  - GREEN: All connections active (all peers online and connected)
  - AMBER: Partial connections (some peers online, messages can be sent/received)
  - RED: No active connections (server running but no peers connected)
  - GREY: Server offline (cannot send or receive messages)
- Automatic connection establishment on login
  - Connects to all contacts automatically when user logs in
  - Establishes group connections for all group members
  - Maintains parent-child session connections
- Complete account export functionality
  - Export entire parent account including identity, contacts, messages, and groups
  - Only available for parent sessions without child sessions
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
  - Only parent sessions can delete accounts
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
- Parent-child session management system for multi-device login
  - SessionManager class for tracking and managing active sessions
  - Parent session can create child sessions via identity export
  - Parent session can view, enable, disable, and delete child sessions
  - Child sessions have full functionality except account deletion
  - Session tracking includes IP address, enabled status, and activity timestamps
  - SessionManagementScreen UI for viewing and managing child sessions
- Identity export/import system (.jidentity format)
  - Export identity from Settings screen (parent sessions only)
  - Creates encrypted identity file for multi-device login
  - Import identity on other devices to create child session
  - Child sessions linked to parent for security monitoring
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
- Delete Account button in Settings screen (parent sessions only)
- Comprehensive delete account dialog with warnings

### Changed
- Settings screen displays session type (Parent or Child)
- Settings screen displays UID and fingerprint in copyable input fields
- Settings screen includes Copy UID and Copy Fingerprint buttons
- Settings screen includes Export Contact Card button
- Settings screen includes Export Identity button (parent sessions only)
- Settings screen includes Manage Sessions button (parent sessions only)
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
