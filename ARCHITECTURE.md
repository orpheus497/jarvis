# Jarvis Messenger Architecture

## Overview

Jarvis Messenger is a terminal-based P2P encrypted messaging application built with Python, featuring a client-server architecture with asyncio for non-blocking I/O.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Jarvis UI (Textual)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Main Screen │  │ Chat Screen  │  │Search Screen │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└───────────────────────┬─────────────────────────────────┘
                        │ IPC (JSON over TCP)
┌───────────────────────┴─────────────────────────────────┐
│              Jarvis Server (Background Daemon)          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │  Identity   │  │  Contacts   │  │  Messages   │    │
│  │  Manager    │  │  Manager    │  │   Store     │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │  Network    │  │   Search    │  │ File Trans. │    │
│  │  Manager    │  │   Engine    │  │   Session   │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
└───────────────────────┬─────────────────────────────────┘
                        │ P2P (Encrypted TCP)
┌───────────────────────┴─────────────────────────────────┐
│                     Remote Peers                        │
│         (Other Jarvis instances on the network)         │
└─────────────────────────────────────────────────────────┘
```

## Core Components

### 1. User Interface Layer

**Technology**: Textual (Python TUI framework)
**Location**: `src/jarvis/ui.py`, `src/jarvis/ui_*.py`

- **JarvisApp**: Main application controller
- **Screens**: Login, main menu, chat, search, file transfer
- **Components**: Message lists, contact lists, progress bars
- **Client Adapter**: Bridges sync UI with async server

### 2. Server Layer

**Technology**: Python asyncio
**Location**: `src/jarvis/server.py`

- **JarvisServer**: Background daemon handling all operations
- **IPC Server**: TCP socket for UI communication
- **Command Dispatcher**: Routes commands to appropriate handlers
- **Manager Initialization**: Sets up identity, contacts, messages, search

### 3. Identity Management

**Location**: `src/jarvis/identity.py`

- **Identity**: User identity with UID, username, keypair
- **IdentityManager**: Create, load, save, delete identities
- **Encryption**: Identity files encrypted with Argon2id-derived keys
- **Export**: Complete account export with encryption

### 4. Cryptography Layer

**Technology**: Cryptography library, liboqs (post-quantum)
**Location**: `src/jarvis/crypto.py`, `src/jarvis/ratchet.py`

- **Five-Layer Encryption**: Alternating AES-256-GCM and ChaCha20-Poly1305
- **Double Ratchet**: Signal Protocol for forward secrecy
- **Post-Quantum**: ML-KEM-1024 for quantum-resistant key exchange
- **Key Derivation**: Argon2id for password-based keys

### 5. Network Layer

**Technology**: Python asyncio sockets
**Location**: `src/jarvis/network.py`, `src/jarvis/protocol.py`

- **NetworkManager**: Manages P2P connections
- **P2PConnection**: Individual peer connection handler
- **Protocol**: Message framing and serialization
- **NAT Traversal**: UPnP and STUN support

### 6. Data Persistence

**Technology**: JSON files, SQLite (for search)
**Location**: `src/jarvis/contact.py`, `src/jarvis/message.py`, `src/jarvis/group.py`

- **ContactManager**: Contact storage and management
- **MessageStore**: Message history storage
- **GroupManager**: Group chat management
- **Atomic Writes**: Temp file + rename for data safety
- **Async I/O**: aiofiles for non-blocking operations

### 7. Search Engine

**Technology**: SQLite FTS5 (Full-Text Search)
**Location**: `src/jarvis/search.py`

- **MessageSearchEngine**: Full-text message search
- **FTS5 Virtual Tables**: Fast text indexing
- **Filters**: Contact, group, date range filters
- **Snippets**: Search result highlighting

### 8. File Transfer

**Technology**: Chunked encrypted transfers
**Location**: `src/jarvis/file_transfer.py`

- **FileTransferSession**: Manages file transfer state
- **Chunking**: FILE_CHUNK_SIZE for large files
- **Encryption**: ChaCha20-Poly1305 per chunk
- **Progress Tracking**: Bytes transferred, speed, ETA

## Data Flow

### Message Sending Flow

```
1. User types message in Chat Screen
   ↓
2. UI sends SEND_MESSAGE command to Server via IPC
   ↓
3. Server encrypts message with recipient's ratchet state
   ↓
4. NetworkManager sends encrypted message via P2P connection
   ↓
5. MessageStore saves message to local storage
   ↓
6. SearchEngine indexes message for FTS
   ↓
7. UI receives confirmation and updates display
```

### Message Receiving Flow

```
1. P2PConnection receives encrypted data
   ↓
2. Protocol decodes and validates message
   ↓
3. Ratchet decrypts message (Double Ratchet)
   ↓
4. MessageStore saves received message
   ↓
5. SearchEngine indexes message
   ↓
6. Server broadcasts to connected UI clients
   ↓
7. UI updates chat screen with new message
```

## Security Architecture

### Encryption Layers

1. **Transport Layer**: TLS-like encryption with X25519 key exchange
2. **Message Layer**: Double Ratchet with ChaCha20-Poly1305
3. **Identity Layer**: Argon2id for password-based encryption
4. **File Layer**: Per-chunk ChaCha20-Poly1305
5. **Post-Quantum**: ML-KEM-1024 for future security

### Key Management

- **Identity Keys**: Ed25519 signing, X25519 ECDH
- **Ratchet Keys**: Ephemeral per-message keys
- **Session Keys**: Derived from Double Ratchet
- **File Keys**: Random 32-byte per transfer
- **Storage Keys**: Argon2id-derived from password

## Async Architecture

### Event Loop

- **Server**: Single asyncio event loop for all operations
- **UI**: Textual's event loop + worker threads
- **I/O**: aiofiles for non-blocking file operations
- **Network**: asyncio sockets for P2P connections

### Concurrency

- **Parallel Operations**: Multiple P2P connections
- **Non-blocking I/O**: File saves don't block networking
- **Task Management**: asyncio.create_task for background work
- **Resource Limits**: Queue sizes, buffer limits, timeouts

## Configuration

**Location**: `pyproject.toml`

- **Black**: 100 char lines, Python 3.8-3.12
- **Ruff**: Multiple linters, auto-fix
- **Mypy**: Type checking with stubs
- **Pytest**: Test discovery and execution
- **Coverage**: Source tracking and reporting

## Performance Considerations

### Optimizations

- **Async I/O**: Prevents blocking on file operations
- **Message Batching**: Queue messages for efficiency
- **Connection Pooling**: Reuse P2P connections
- **FTS5 Indexing**: Fast full-text search
- **Chunked Transfers**: Stream large files

### Resource Limits

- **Send Queue**: 1000 messages max
- **Receive Buffer**: 1MB max
- **File Size**: Configurable max (default 100MB)
- **Connections**: Limited by OS file descriptors

## Testing Strategy

### Test Levels

1. **Unit Tests**: Individual function validation
2. **Integration Tests**: Component interaction
3. **E2E Tests**: Full message flow
4. **Security Tests**: Crypto validation

### Coverage Goals

- **Overall**: 80%+ code coverage
- **Critical Paths**: 90%+ (crypto, protocol, network)
- **UI**: Basic interaction tests
- **Fixtures**: Comprehensive test data

## Deployment

### Requirements

- Python 3.8+
- Terminal with color support
- Network connectivity
- File system access

### Installation

```bash
pip install jarvis-messenger
jarvis
```

### Data Locations

- **Identity**: `~/.jarvis/identity.enc`
- **Contacts**: `~/.jarvis/contacts.json`
- **Messages**: `~/.jarvis/messages/`
- **Groups**: `~/.jarvis/groups.json`
- **Search DB**: `~/.jarvis/messages.db`

## Extensibility

### Adding Features

1. Add command to `ServerCommand` enum
2. Implement handler method in JarvisServer
3. Add dispatcher case in `_process_command`
4. Add client adapter method
5. Update UI screens as needed

### Plugin Architecture

Currently not implemented, but could be added:
- Event hooks for plugins
- Custom encryption backends
- Alternative storage backends
- Custom UI themes

## Future Enhancements

- Voice/video calling
- End-to-end encrypted file sync
- Mobile companion app
- Decentralized identity (DID)
- Tor/I2P support

Created by orpheus497
