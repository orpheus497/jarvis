# Asyncio Refactoring Plan

## Overview
Per the technical blueprint document, the entire Jarvis project must be refactored to use Python's native `asyncio` library with a unified asynchronous architecture. This is required for integration with the Textual UI framework and to ensure non-blocking operations throughout.

## Current Status
The codebase currently uses `threading.Thread` extensively for:
- P2P network connections (network.py)
- IPC communication (server.py, client.py)
- Background tasks (keepalive, reconnection manager)

## Refactoring Phases

### Phase 1: Network Layer ✅ (IN PROGRESS)
- [x] Create async-based P2PConnection using asyncio.open_connection/start_server
- [x] Replace threading.Thread with asyncio.Task
- [x] Convert to async coroutines with async/await
- [x] Use asyncio.StreamReader/StreamWriter for I/O
- [ ] Test async P2P connections
- [ ] Replace old network.py with network_async.py

### Phase 2: Server IPC Layer (TODO)
- [ ] Convert server.py to use asyncio
- [ ] Use Unix Domain Sockets (POSIX) or local TCP (Windows) for IPC
- [ ] Implement async start_unix_server / start_server for IPC
- [ ] Convert all command handlers to async coroutines
- [ ] Update event broadcasting to use async

### Phase 3: Client IPC Layer (TODO)
- [ ] Convert client.py to use asyncio
- [ ] Use asyncio.open_unix_connection or asyncio.open_connection
- [ ] Convert all request/response methods to async
- [ ] Update event callback system for async

### Phase 4: Client Adapter (TODO)
- [ ] Update client_adapter.py for async compatibility
- [ ] Ensure compatibility with async NetworkManager

### Phase 5: UI Integration (TODO)
- [ ] Verify Textual UI async integration
- [ ] Ensure all UI callbacks work with async backend
- [ ] Test UI responsiveness with async event loop

### Phase 6: Background Tasks (TODO)
- [ ] Convert all background processes to async tasks
- [ ] Daemon process management with asyncio
- [ ] System integration (notifications, etc.)

### Phase 7: Testing & Validation (TODO)
- [ ] Update all tests for async
- [ ] Test P2P connections between instances
- [ ] Test IPC communication
- [ ] Test UI responsiveness
- [ ] Load testing
- [ ] Cross-platform testing

### Phase 8: Documentation & Cleanup (TODO)
- [ ] Update CHANGELOG
- [ ] Update README if needed
- [ ] Remove old threading-based code
- [ ] Code review and optimization

## Technical Requirements from Blueprint

1. **Unified Async Architecture**: All I/O operations must be non-blocking
2. **IPC Strategy**:
   - POSIX (Linux/macOS/Termux): Unix Domain Sockets
   - Windows: Local TCP socket (127.0.0.1)
3. **P2P Networking**: asyncio.start_server() and asyncio.open_connection()
4. **No Threading**: Replace all threading.Thread with asyncio.Task
5. **Event Loop Integration**: Single event loop for UI and networking

## Implementation Notes

- This is a complete architectural refactoring, not incremental improvements
- Backwards compatibility with current threading-based code cannot be maintained
- All modules that interact with networking must be updated
- Testing must be comprehensive as this affects core functionality
- The refactoring must be done carefully to avoid introducing bugs

## Dependencies
All required dependencies are already in requirements.txt:
- asyncio (Python standard library)
- Textual (already async-based)
- Other libraries are compatible with async
