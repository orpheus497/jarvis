# Jarvis Messenger API Reference

Complete API reference for Jarvis Messenger modules and classes.

**Created by orpheus497**

**Version:** 2.2.0

---

## Table of Contents

1. [Core Modules](#core-modules)
2. [Cryptography API](#cryptography-api)
3. [Network API](#network-api)
4. [Identity Management API](#identity-management-api)
5. [Data Management API](#data-management-api)
6. [Server API](#server-api)
7. [Client API](#client-api)
8. [Search API](#search-api)
9. [File Transfer API](#file-transfer-api)
10. [Utilities API](#utilities-api)

---

## Core Modules

### jarvis.constants

Global constants and configuration values.

**Constants:**
- `VERSION` (str): Application version
- `APP_NAME` (str): Application name
- `AUTHOR` (str): Project author
- `DEFAULT_SERVER_PORT` (int): Default P2P port (5000)
- `MAX_MESSAGE_SIZE` (int): Maximum message size (10 MB)
- `FILE_CHUNK_SIZE` (int): File transfer chunk size (1 MB)
- `CONNECTION_POOL_MAX_SIZE` (int): Maximum connections (50)
- `MESSAGE_BATCH_SIZE` (int): Messages per batch (100)
- `SEARCH_CACHE_MAX_SIZE` (int): Cached queries (1000)

**Feature Flags:**
- `FEATURE_DOUBLE_RATCHET` (bool): Double Ratchet encryption
- `FEATURE_FILE_TRANSFER` (bool): File transfer support
- `FEATURE_NAT_TRAVERSAL` (bool): NAT traversal support
- `FEATURE_CONNECTION_POOLING` (bool): Connection pooling
- `FEATURE_MESSAGE_BATCHING` (bool): Message batch processing
- `FEATURE_SEARCH_CACHING` (bool): Search result caching

---

## Cryptography API

### jarvis.crypto

Multi-layer encryption and cryptographic operations.

#### IdentityKeyPair

```python
class IdentityKeyPair:
    """
    User identity key pair for P2P communication using X25519 ECDH.

    Attributes:
        private_key (X25519PrivateKey): Private key
        public_key (X25519PublicKey): Public key
    """

    def __init__(self, private_key: Optional[X25519PrivateKey] = None)
    def get_public_key_bytes(self) -> bytes
    def get_private_key_bytes(self) -> bytes
    def to_dict(self) -> Dict[str, str]

    @staticmethod
    def from_dict(data: Dict[str, str]) -> IdentityKeyPair

    @staticmethod
    def from_public_bytes(public_bytes: bytes) -> X25519PublicKey
```

#### Functions

```python
def derive_identity_key(username: str, password: str, salt: bytes) -> bytes:
    """
    Derive identity seed using Argon2id.

    Args:
        username: User's username
        password: User's password
        salt: Random salt (16 bytes)

    Returns:
        32-byte derived key
    """

def perform_key_exchange(
    local_private: X25519PrivateKey,
    remote_public: X25519PublicKey
) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
    """
    Perform X25519 key exchange and derive five session keys.

    Args:
        local_private: Local private key
        remote_public: Remote public key

    Returns:
        Tuple of five 32-byte session keys
    """

def encrypt_five_layer(
    plaintext: bytes,
    key1: bytes,
    key2: bytes,
    key3: bytes,
    key4: bytes,
    key5: bytes
) -> bytes:
    """
    Encrypt data through five layers (AES-GCM + ChaCha20-Poly1305).

    Args:
        plaintext: Data to encrypt
        key1-key5: Five 32-byte encryption keys

    Returns:
        Encrypted ciphertext
    """

def decrypt_five_layer(
    ciphertext: bytes,
    key1: bytes,
    key2: bytes,
    key3: bytes,
    key4: bytes,
    key5: bytes
) -> bytes:
    """
    Decrypt five-layer encrypted data.

    Args:
        ciphertext: Encrypted data
        key1-key5: Five 32-byte decryption keys

    Returns:
        Decrypted plaintext
    """

def generate_fingerprint(public_key: bytes) -> str:
    """
    Generate SHA-256 fingerprint of public key.

    Args:
        public_key: Public key bytes

    Returns:
        Hex-encoded fingerprint
    """
```

### jarvis.ratchet

Double Ratchet algorithm for forward secrecy.

#### RatchetSession

```python
class RatchetSession:
    """
    Double Ratchet session for secure messaging.

    Provides forward secrecy and self-healing properties based on
    the Signal Protocol.
    """

    def __init__(self, shared_secret: bytes, sending: bool = True)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypt message with automatic key rotation.

        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data

        Returns:
            Tuple of (dh_public_key, ciphertext)
        """

    def decrypt(
        self,
        dh_public: bytes,
        ciphertext: bytes,
        associated_data: bytes = b""
    ) -> bytes:
        """
        Decrypt message and update ratchet.

        Args:
            dh_public: Sender's DH public key
            ciphertext: Encrypted message
            associated_data: Additional authenticated data

        Returns:
            Decrypted plaintext
        """
```

---

## Network API

### jarvis.network

Peer-to-peer networking layer with connection pooling.

#### ConnectionPool

```python
class ConnectionPool:
    """
    Manages connection pooling for P2P connections.

    Features:
    - Connection reuse tracking
    - Idle connection timeout
    - Health check monitoring
    - Automatic connection recycling
    """

    def __init__(
        self,
        max_size: int = 50,
        min_size: int = 5,
        idle_timeout: int = 300,
        health_check_interval: int = 60,
        reuse_threshold: int = 100
    )

    async def add_connection(self, uid: str, connection: P2PConnection) -> None
    async def get_connection(self, uid: str) -> Optional[P2PConnection]
    async def remove_connection(self, uid: str) -> None
    async def start_health_checks(self) -> None
    async def stop_health_checks(self) -> None
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get pool statistics.

        Returns:
            {
                'total_connections': int,
                'healthy_connections': int,
                'idle_connections': int,
                'average_reuse_count': float,
                'max_size': int,
                'min_size': int
            }
        """
    async def clear(self) -> None
```

#### P2PConnection

```python
class P2PConnection:
    """Asynchronous P2P connection with encryption."""

    CONNECT_TIMEOUT = 10  # seconds
    HANDSHAKE_TIMEOUT = 15  # seconds
    SEND_QUEUE_MAX_SIZE = 1000
    RECEIVE_BUFFER_MAX_SIZE = 1024 * 1024  # 1MB

    def __init__(
        self,
        contact: Contact,
        identity: IdentityKeyPair,
        my_uid: str,
        my_username: str,
        rate_limiter: Optional[RateLimiter] = None,
        metrics: Optional[ConnectionMetrics] = None
    )

    async def connect(self) -> bool
    async def disconnect(self) -> None
    async def send_message(self, content: str, message_id: str, timestamp: int) -> bool
    async def send_group_message(
        self,
        group_id: str,
        content: str,
        message_id: str,
        timestamp: int
    ) -> bool
```

#### NetworkManager

```python
class NetworkManager:
    """Manages all P2P connections with connection pooling."""

    def __init__(
        self,
        identity: IdentityKeyPair,
        my_uid: str,
        my_username: str,
        listen_port: int,
        contact_manager: ContactManager,
        data_dir: Optional[Path] = None
    )

    async def start_server(self) -> bool
    async def stop_server(self) -> None
    async def connect(self, contact_uid: str) -> bool
    async def disconnect(self, contact_uid: str) -> None
    async def send_message(self, recipient_uid: str, content: str) -> bool
    async def send_group_message(self, group_id: str, content: str) -> bool
    def is_connected(self, contact_uid: str) -> bool
    def get_connection_status(self) -> str  # GREEN, AMBER, RED, GREY
```

---

## Identity Management API

### jarvis.identity

Identity creation and management.

#### Identity

```python
class Identity:
    """User identity with encryption keys."""

    def __init__(
        self,
        uid: str,
        username: str,
        keypair: IdentityKeyPair,
        fingerprint: str,
        listen_port: int,
        created_at: str
    )

    def to_dict(self) -> Dict[str, Any]

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> Identity
```

#### IdentityManager

```python
class IdentityManager:
    """Manages user identity persistence."""

    def __init__(self, data_dir: str)

    def create_identity(
        self,
        username: str,
        password: str,
        listen_port: int = 5000
    ) -> Identity

    def load_identity(self, password: str) -> Optional[Identity]
    def save_identity(self, identity: Identity, password: str) -> None
    async def save_identity_async(self, identity: Identity, password: str) -> None
    def has_identity(self) -> bool
    def delete_identity(self, password: str) -> bool
    def export_complete_account(
        self,
        password: str,
        export_password: Optional[str] = None
    ) -> Path
```

---

## Data Management API

### jarvis.contact

Contact management with persistence.

#### Contact

```python
class Contact:
    """Represents a contact."""

    def __init__(
        self,
        uid: str,
        username: str,
        public_key: str,
        fingerprint: str,
        host: str,
        port: int,
        verified: bool = False
    )

    def to_dict(self) -> Dict[str, Any]

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> Contact
```

#### ContactManager

```python
class ContactManager:
    """Manages contact persistence."""

    def __init__(self, data_dir: str)

    def add_contact(self, contact: Contact) -> None
    def remove_contact(self, uid: str) -> None
    def get_contact(self, uid: str) -> Optional[Contact]
    def get_all_contacts(self) -> List[Contact]
    def update_contact(self, contact: Contact) -> None
    def save_contacts(self) -> None
    async def save_contacts_async(self) -> None
    def mark_online(self, uid: str) -> None
    def mark_offline(self, uid: str) -> None
```

### jarvis.message

Message storage and persistence.

#### MessageStore

```python
class MessageStore:
    """Manages message persistence."""

    def __init__(self, data_dir: str)

    def add_message(
        self,
        contact_uid: str,
        content: str,
        sent_by_me: bool,
        timestamp: int,
        message_id: str
    ) -> None

    def get_messages(self, contact_uid: str, limit: int = 100) -> List[Dict]
    def mark_read(self, contact_uid: str, message_id: str) -> None
    def get_unread_count(self, contact_uid: str) -> int
    def delete_messages(self, contact_uid: str) -> int
    def save_messages(self) -> None
    async def save_messages_async(self) -> None
```

### jarvis.group

Group chat management.

#### Group

```python
class Group:
    """Represents a group chat."""

    def __init__(
        self,
        group_id: str,
        name: str,
        created_by: str,
        created_at: str,
        members: List[str]
    )

    def to_dict(self) -> Dict[str, Any]

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> Group
```

#### GroupManager

```python
class GroupManager:
    """Manages group persistence."""

    def __init__(self, data_dir: str)

    def create_group(self, name: str, creator_uid: str, members: List[str]) -> Group
    def delete_group(self, group_id: str) -> None
    def get_group(self, group_id: str) -> Optional[Group]
    def get_all_groups(self) -> List[Group]
    def add_member(self, group_id: str, uid: str) -> None
    def remove_member(self, group_id: str, uid: str) -> None
```

---

## Server API

### jarvis.server

Background server daemon with IPC.

#### JarvisServer

```python
class JarvisServer:
    """Background server maintaining P2P connections."""

    def __init__(self, data_dir: str, ipc_port: int = 5999)

    async def start(self) -> bool
    async def stop(self) -> None
    async def run(self) -> None
```

**Server Commands:**
- `LOGIN` - Authenticate user
- `LOGOUT` - Log out user
- `SEND_MESSAGE` - Send direct message
- `SEND_GROUP_MESSAGE` - Send group message
- `GET_MESSAGES` - Retrieve messages
- `ADD_CONTACT` - Add new contact
- `REMOVE_CONTACT` - Remove contact
- `CREATE_GROUP` - Create group chat
- `SEARCH_MESSAGES` - Search messages
- `SEND_FILE` - Transfer file
- `CREATE_BACKUP` - Create backup
- `SHUTDOWN` - Stop server

---

## Client API

### jarvis.client

Client library for server communication.

#### JarvisClient

```python
class JarvisClient:
    """Client for communicating with background server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5999)

    async def connect(self) -> bool
    async def disconnect(self) -> None
    async def login(self, password: str) -> Dict[str, Any]
    async def logout(self) -> Dict[str, Any]
    async def send_message(self, recipient_uid: str, content: str) -> Dict[str, Any]
    async def get_messages(self, contact_uid: str, limit: int = 100) -> Dict[str, Any]
    async def add_contact(self, contact_data: Dict) -> Dict[str, Any]
    async def search_messages(self, query: str, **filters) -> Dict[str, Any]
```

---

## Search API

### jarvis.search

Full-text search with FTS5.

#### MessageSearchEngine

```python
class MessageSearchEngine:
    """SQLite FTS5 search engine with caching."""

    def __init__(self, db_path: Path)

    def index_message(
        self,
        message_id: str,
        sender: str,
        content: str,
        timestamp: int,
        recipient: Optional[str] = None,
        group_id: Optional[str] = None
    ) -> None

    def search(
        self,
        query: str,
        contact: Optional[str] = None,
        group_id: Optional[str] = None,
        start_date: Optional[int] = None,
        end_date: Optional[int] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict]:
        """
        Search messages with FTS5.

        Returns:
            List of results with highlighted snippets
        """

    def search_by_contact(self, contact: str, limit: int = 100) -> List[Dict]
    def search_by_date(self, start: int, end: int, limit: int = 100) -> List[Dict]
```

---

## File Transfer API

### jarvis.file_transfer

Chunked encrypted file transfers.

#### FileTransferSession

```python
class FileTransferSession:
    """Manages file transfer session."""

    def __init__(
        self,
        transfer_id: str,
        encryption_key: bytes,
        progress_callback: Optional[Callable] = None
    )

    def chunk_file(self, file_path: Path) -> FileMetadata
    async def send_chunk(self, chunk_number: int) -> ChunkInfo
    async def receive_chunk(self, chunk_info: ChunkInfo) -> None
    async def reassemble_file(self, output_path: Path) -> bool
    def get_progress(self) -> Dict[str, Any]
```

---

## Utilities API

### jarvis.utils

Utility functions.

```python
def validate_port(port: int) -> bool
def validate_ip(ip: str, allow_loopback: bool = False, allow_private: bool = True) -> bool
def validate_hostname(hostname: str) -> bool
def validate_uid(uid: str) -> bool
def format_fingerprint(fingerprint: str) -> str
def truncate_string(text: str, max_length: int, suffix: str = "...") -> str
def sanitize_filename(filename: str) -> str
```

---

## Error Handling

All exceptions inherit from `JarvisError`:

```python
class JarvisError(Exception):
    """Base exception."""
    def __init__(self, code: ErrorCode, message: str, context: Dict = None)

class CryptoError(JarvisError): pass
class NetworkError(JarvisError): pass
class IdentityError(JarvisError): pass
class ContactError(JarvisError): pass
class GroupError(JarvisError): pass
class FileTransferError(JarvisError): pass
class ServerError(JarvisError): pass
class ConfigError(JarvisError): pass
```

---

## License

MIT License - See LICENSE file.

**Created by orpheus497**
