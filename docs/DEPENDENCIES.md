# Dependency Attributions

Jarvis relies on the following free and open-source software (FOSS) dependencies. We are grateful to all the creators and maintainers of these projects.

## Core UI Framework

### Textual
- **License**: MIT
- **Description**: Modern Python framework for building terminal user interfaces
- **Upstream**: https://github.com/Textualize/textual
- **Website**: https://textual.textualize.io/

### Rich
- **License**: MIT
- **Description**: Python library for rich text and beautiful formatting in the terminal
- **Upstream**: https://github.com/Textualize/rich
- **Website**: https://rich.readthedocs.io/

## Cryptography

### cryptography
- **License**: Apache-2.0 / BSD-3-Clause (dual license)
- **Description**: Cryptographic primitives and recipes for Python
- **Upstream**: https://github.com/pyca/cryptography
- **Website**: https://cryptography.io/

### argon2-cffi
- **License**: MIT
- **Description**: Argon2 password hashing algorithm implementation
- **Upstream**: https://github.com/hynek/argon2-cffi
- **Website**: https://argon2-cffi.readthedocs.io/

### liboqs-python
- **License**: MIT
- **Description**: Python wrapper for liboqs (post-quantum cryptography)
- **Upstream**: https://github.com/open-quantum-safe/liboqs-python
- **Website**: https://openquantumsafe.org/

## Utilities

### pyperclip
- **License**: BSD-3-Clause
- **Description**: Cross-platform clipboard access for Python
- **Upstream**: https://github.com/asweigart/pyperclip
- **Website**: https://pyperclip.readthedocs.io/

### tomli
- **License**: MIT
- **Description**: TOML parser for Python (for Python < 3.11)
- **Upstream**: https://github.com/hukkin/tomli
- **Website**: https://github.com/hukkin/tomli

### zstandard
- **License**: BSD-3-Clause
- **Description**: Python bindings for Zstandard compression
- **Upstream**: https://github.com/indygreg/python-zstandard
- **Website**: https://python-zstandard.readthedocs.io/

### validators
- **License**: MIT
- **Description**: Python data validation library
- **Upstream**: https://github.com/python-validators/validators
- **Website**: https://python-validators.github.io/validators/

### aiofiles
- **License**: Apache-2.0
- **Description**: Asynchronous file operations for Python
- **Upstream**: https://github.com/Tinche/aiofiles
- **Website**: https://github.com/Tinche/aiofiles

## Media and Display

### qrcode
- **License**: BSD-3-Clause
- **Description**: QR code generator for Python
- **Upstream**: https://github.com/lincolnloop/python-qrcode
- **Website**: https://github.com/lincolnloop/python-qrcode

### pyzbar
- **License**: MIT
- **Description**: Read one-dimensional barcodes and QR codes from Python
- **Upstream**: https://github.com/NaturalHistoryMuseum/pyzbar
- **Website**: https://github.com/NaturalHistoryMuseum/pyzbar
- **Note**: Python wrapper for ZBar barcode library

### Pillow
- **License**: HPND (Historical Permission Notice and Disclaimer) / PIL License
- **Description**: Python Imaging Library (PIL Fork)
- **Upstream**: https://github.com/python-pillow/Pillow
- **Website**: https://pillow.readthedocs.io/

## Audio (Voice Messages)

### sounddevice
- **License**: MIT
- **Description**: Python bindings for PortAudio
- **Upstream**: https://github.com/spatialaudio/python-sounddevice
- **Website**: https://python-sounddevice.readthedocs.io/

### soundfile
- **License**: BSD-3-Clause
- **Description**: Python library for reading and writing sound files
- **Upstream**: https://github.com/bastibe/python-soundfile
- **Website**: https://python-soundfile.readthedocs.io/

## Internet Connectivity

### miniupnpc
- **License**: BSD-3-Clause
- **Description**: UPnP IGD client library for automatic port mapping
- **Upstream**: https://github.com/miniupnp/miniupnp
- **Website**: http://miniupnp.free.fr/

### pystun3
- **License**: MIT
- **Description**: Python STUN client for NAT traversal and public IP discovery
- **Upstream**: https://github.com/talkiq/pystun3
- **Website**: https://github.com/talkiq/pystun3

### zeroconf
- **License**: LGPL-2.1
- **Description**: Multicast DNS service discovery (mDNS/DNS-SD) implementation
- **Upstream**: https://github.com/python-zeroconf/python-zeroconf
- **Website**: https://python-zeroconf.readthedocs.io/

## License Summary

All dependencies are free and open-source software (FOSS) with permissive licenses:

- **MIT**: textual, rich, argon2-cffi, liboqs-python, tomli, validators, pystun3, pyzbar, sounddevice
- **Apache-2.0**: cryptography (dual), aiofiles
- **BSD-3-Clause**: pyperclip, zstandard, qrcode, soundfile, miniupnpc, cryptography (dual)
- **LGPL-2.1**: zeroconf
- **HPND/PIL**: Pillow

## Standards and Protocols

Jarvis implements industry-standard cryptographic protocols and best practices:

### Cryptographic Standards

- **X25519** - Elliptic curve Diffie-Hellman key exchange (RFC 7748)
  - IETF standard: https://tools.ietf.org/html/rfc7748

- **AES-GCM** - Authenticated encryption with associated data (NIST SP 800-38D)
  - NIST standard: https://csrc.nist.gov/publications/detail/sp/800-38d/final

- **ChaCha20-Poly1305** - Authenticated encryption (RFC 8439)
  - IETF standard: https://tools.ietf.org/html/rfc8439

- **Argon2** - Memory-hard password hashing (RFC 9106)
  - IETF standard: https://tools.ietf.org/html/rfc9106

- **Double Ratchet Algorithm** - Forward secrecy protocol
  - Signal Protocol specification: https://signal.org/docs/specifications/doubleratchet/

### Networking Standards

- **UPnP IGD** - Internet Gateway Device Protocol for automatic port mapping
  - Specification: https://openconnectivity.org/developer/specifications/upnp-resources/upnp/

- **STUN** - Session Traversal Utilities for NAT (RFC 5389)
  - IETF standard: https://tools.ietf.org/html/rfc5389

- **mDNS/DNS-SD** - Multicast DNS Service Discovery (RFC 6762/6763)
  - IETF standards: https://tools.ietf.org/html/rfc6762 and https://tools.ietf.org/html/rfc6763

### Database and Storage

- **SQLite FTS5** - Full-text search engine
  - Documentation: https://www.sqlite.org/fts5.html

### Documentation Standards

- **Keep a Changelog** - Standardized changelog format
  - Specification: https://keepachangelog.com/

- **Semantic Versioning** - Version numbering convention
  - Specification: https://semver.org/

## Acknowledgements

This project would not be possible without the hard work and dedication of the open-source community. We extend our gratitude to all contributors of the dependencies listed above.

---

**Created by orpheus497**

---

## Contributing to Dependencies

If you would like to contribute to any of these projects, please visit their respective repositories and follow their contribution guidelines. Supporting the open-source ecosystem benefits everyone.
