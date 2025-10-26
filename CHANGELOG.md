# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Account deletion functionality with password confirmation
  - Delete identity and all cryptographic keys
  - Delete all contacts
  - Delete all messages (direct and group)
  - Delete all groups
- Lock feature (Ctrl+L) to secure the application when stepping away
  - Keeps network connections active while UI is locked
  - Password verification required to unlock
  - Visual lock screen with animated banner
- Enhanced data management capabilities
  - Individual contact deletion via ContactManager
  - Individual group deletion via GroupManager
  - Conversation deletion support
  - Complete account and data wipe functionality
- Delete Account button in Settings screen
- Comprehensive delete account dialog with warnings

### Changed
- Settings screen now includes account deletion option
- Enhanced keyboard shortcuts with lock feature (Ctrl+L)
- Improved connection stability and background processing
- Connection management runs in background threads
- Simultaneous host/client P2P model ensures reliable connectivity
- Online status detection based on active peer-to-peer connections

### Fixed
- Group creation UI stability when selecting invitees
- Worker-related crashes in modal screens
- Connection state management and automatic reconnection

### Security
- Lock feature maintains encryption and connection security
- Account deletion securely removes all sensitive data
- Password verification required for destructive operations

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
