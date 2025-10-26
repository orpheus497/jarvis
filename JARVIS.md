  Jarvis Project Summary  body { font-family: 'Inter', sans-serif; } /\* Custom scrollbar for a cleaner look \*/ ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #1e293b; /\* slate-800 \*/ } ::-webkit-scrollbar-thumb { background: #334155; /\* slate-700 \*/ border-radius: 3px; } ::-webkit-scrollbar-thumb:hover { background: #475569; /\* slate-600 \*/ } .ascii-art { font-family: 'Courier New', Courier, monospace; white-space: pre; line-height: 1.2; font-size: 0.75rem; /\* text-xs \*/ letter-spacing: 0.1em; text-align: center; color: #38bdf8; /\* sky-500 \*/ text-shadow: 0 0 5px rgba(56, 189, 248, 0.3); } .slide { min-height: 80vh; display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 4rem 2rem; border-bottom: 1px solid #1e293b; /\* slate-800 \*/ } .slide-title { @apply text-4xl font-bold text-sky-400 mb-4; } .slide-subtitle { @apply text-xl text-slate-400 mb-12 text-center max-w-2xl; } .card { @apply bg-slate-800 p-6 rounded-lg shadow-xl transition-all duration-300 hover:shadow-2xl hover:-translate-y-1; } .icon { @apply w-8 h-8 text-sky-400; } .diagram-box { @apply bg-slate-800 border-2 border-sky-700 p-4 rounded-lg text-center shadow-lg; } .diagram-arrow { @apply text-slate-500 font-mono my-2 text-sm; }

Jarvis 🛡️
==========

A terminal-based, peer-to-peer, end-to-end encrypted messenger.

░        ░░░      ░░░       ░░░  ░░░░  ░░        ░░░      ░░
▒▒▒▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒▒▒
▓▓▓▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓       ▓▓▓▓  ▓▓  ▓▓▓▓▓▓  ▓▓▓▓▓▓      ▓▓
█  ████  ██        ██  ███  █████    ███████  ███████████  █
██      ███  ████  ██  ████  █████  █████        ███      ██

Created by orpheus497

Your Conversations. Your Control.
---------------------------------

Jarvis is built on a foundation of total user control and privacy.

### No Cloud, No Servers

Messages are transmitted directly between peers using TCP sockets. No central server to compromise or monitor.

### No Tracking, No Telemetry

No analytics, no usage tracking, and no error reporting. Your activity is your own, period.

### Total Privacy

Only you and your intended contacts have the keys to read your messages.

### Supreme Encryption

A defense-in-depth, five-layer encryption model protects every single message you send.

### Open Source

All code is open, auditable, and free to use. Trust through transparency.

Core Features
-------------

### Uncompromising Security

*   \*\*Five-Layer Encryption\*\* (AES & ChaCha20-Poly1305)
*   \*\*Modern Key Exchange\*\* (X25519)
*   \*\*Strong Password Protection\*\* (Argon2id)
*   \*\*MITM Protection\*\* (SHA-256 Fingerprints)

### Direct P2P Connections

No servers. No intermediaries. Just you and your contacts.

### Cross-Platform

Works seamlessly on Linux, Windows, macOS, and Termux (Android).

### Persistent Daemon

A background process handles connections so you never miss a message, even with the UI closed.

### Modern TUI

A beautiful and responsive terminal UI powered by the modern Textual framework.

### Data Control

Store all data locally. Securely export your entire account for backup or migration.

How It Works
------------

A robust, asynchronous Client-Daemon model ensures a responsive UI and persistent connections.

### Textual UI (Async)

(Running in async event loop)

│  
├── Local IPC (asyncio)  
│

### Async Server Daemon (server.py)

(Persistent Background Process)

*   Async command handlers
*   Async event broadcasting

│  
├── P2P connections  
│

### Async Network Layer (network.py)

*   asyncio P2P connections
*   Async message handling
*   Connection health monitoring

Get Started in 3 Steps
----------------------

1

### Create Identity

Run Jarvis and choose "Create Identity". Pick a username and a strong, memorable master password. Your unique UID will be generated.

⚠️ Your password CANNOT be recovered. Write it down!

2

### Add Contact

The easiest way is to ask your contact for their \*\*Link Code\*\* from their Settings screen. Press \`Ctrl+C\`, paste the code, and you're set.

3

### Verify Contact

\*\*This is the most important step.\*\* Call your contact or meet them in person. Read your \*\*fingerprints\*\* to each other. If they match, click "Mark as Verified".

This prevents Man-in-the-Middle (MITM) attacks.

Copyright (c) 2025 orpheus497

Built with Textual, Asyncio, and a passion for privacy.
