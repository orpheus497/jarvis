# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete Textual-based terminal UI with interactive interface
- Animated ASCII banner that cycles through colors (cyan, blue, magenta, red, yellow, green)
- Contact list with real-time online/offline status indicators (🟢/🔴)
- Interactive chat view with message history for direct and group conversations
- Link code generation system for simplified contact adding
  - Format: `jarvis://[base64-encoded-contact-info]`
  - Contains UID, username, public key, fingerprint, host, and port
  - One-click contact adding via link code paste
- Link code copy-to-clipboard functionality in settings
- Keyboard shortcuts for common actions:
  - `Ctrl+C`: Add contact
  - `Ctrl+G`: Create new group
  - `Ctrl+S`: Open settings
  - `Ctrl+Q`: Quit application
- Settings screen displaying:
  - Username and UID
  - Formatted fingerprint (with spaces every 4 characters)
  - Listen port
  - Shareable link code
- Group chat creation dialog with member invitation
- Message input with send button and Enter key support
- Real-time message display with timestamps (relative format: "X minutes ago")
- Unread message tracking and marking as read when viewing conversation
- Automatic connection attempts when selecting contacts
- Connection state notifications
- Modal dialogs for identity creation/loading
- Color-coded messages (cyan for sent, yellow for received)
- Support for both direct messages and group messages
- Group message sender identification

### Enhanced
- Contact management system with link code support
- Group chat functionality fully integrated with UI
- Message storage system with conversation history
- Network manager with callback-based event system
- Identity loading with password verification
- Contact verification workflow

### Fixed
- Network manager initialization with proper identity handling
- Message routing for both direct and group messages
- Connection state tracking and UI updates
- Message persistence across application restarts

### Improved
- User experience with modern terminal UI (Textual framework)
- Contact adding workflow (from 5 manual fields to 1 link code)
- Visual feedback with status indicators and notifications
- Message history display with proper formatting
- Group chat usability with integrated member management

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
