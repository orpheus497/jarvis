"""
Jarvis - File Transfer Implementation

This module handles secure file transfer with chunking, encryption,
compression, checksums, and resume capability. Supports large files
with progress tracking and automatic retry.

Author: orpheus497
Version: 2.0.0
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .constants import (
    FILE_CHUNK_SIZE,
    FILE_TRANSFER_RETRY_ATTEMPTS,
    FILE_TRANSFER_RETRY_DELAY,
    FILE_TRANSFER_TIMEOUT,
    KEY_SIZE,
    MAX_FILE_SIZE,
    NONCE_SIZE,
)
from .errors import ErrorCode, FileTransferError

logger = logging.getLogger(__name__)


@dataclass
class FileMetadata:
    """Metadata for a file transfer.

    Attributes:
        filename: Name of the file
        size: Total file size in bytes
        checksum: SHA-256 checksum of the file
        chunk_size: Size of each chunk
        total_chunks: Total number of chunks
        transfer_id: Unique transfer identifier
    """

    filename: str
    size: int
    checksum: str
    chunk_size: int
    total_chunks: int
    transfer_id: str


@dataclass
class ChunkInfo:
    """Information about a file chunk.

    Attributes:
        chunk_number: Chunk sequence number (0-indexed)
        data: Chunk data (encrypted)
        checksum: SHA-256 checksum of decrypted chunk
    """

    chunk_number: int
    data: bytes
    checksum: str


class FileTransferSession:
    """Manages a file transfer session.

    Handles chunking, encryption, transmission, and reconstruction
    of files with progress tracking and resume capability.

    Attributes:
        transfer_id: Unique transfer identifier
        metadata: File metadata
        encryption_key: Key for encrypting chunks
        chunks_sent: Set of chunk numbers that have been sent
        chunks_received: Dictionary of received chunks
        progress_callback: Optional callback for progress updates
        start_time: Transfer start timestamp
    """

    def __init__(
        self,
        transfer_id: str,
        encryption_key: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ):
        """Initialize a file transfer session.

        Args:
            transfer_id: Unique transfer identifier
            encryption_key: Key for chunk encryption (32 bytes)
            progress_callback: Optional callback(current, total) for progress

        Raises:
            FileTransferError: If key is invalid
        """
        if len(encryption_key) != KEY_SIZE:
            raise FileTransferError(
                ErrorCode.E600_FILE_TRANSFER_ERROR, f"Encryption key must be {KEY_SIZE} bytes"
            )

        self.transfer_id = transfer_id
        self.encryption_key = encryption_key
        self.metadata: Optional[FileMetadata] = None
        self.chunks_sent: set = set()
        self.chunks_received: Dict[int, bytes] = {}
        self.progress_callback = progress_callback
        self.start_time = time.time()

        logger.info(f"Initialized file transfer session: {transfer_id}")

    def chunk_file(self, file_path: Path) -> FileMetadata:
        """Prepare a file for transfer by generating metadata.

        Args:
            file_path: Path to the file to transfer

        Returns:
            File metadata

        Raises:
            FileTransferError: If file is invalid or too large
        """
        if not file_path.exists():
            raise FileTransferError(ErrorCode.E003_FILE_NOT_FOUND, f"File not found: {file_path}")

        if not file_path.is_file():
            raise FileTransferError(ErrorCode.E002_INVALID_ARGUMENT, f"Not a file: {file_path}")

        file_size = file_path.stat().st_size

        if file_size > MAX_FILE_SIZE:
            raise FileTransferError(
                ErrorCode.E601_FILE_TOO_LARGE,
                f"File too large: {file_size} > {MAX_FILE_SIZE}",
                {"size": file_size, "max_size": MAX_FILE_SIZE},
            )

        # Calculate checksum
        checksum = self._calculate_file_checksum(file_path)

        # Calculate chunk information
        total_chunks = (file_size + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE

        self.metadata = FileMetadata(
            filename=file_path.name,
            size=file_size,
            checksum=checksum,
            chunk_size=FILE_CHUNK_SIZE,
            total_chunks=total_chunks,
            transfer_id=self.transfer_id,
        )

        logger.info(f"Chunked file: {file_path.name}, " f"size={file_size}, chunks={total_chunks}")

        return self.metadata

    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of a file.

        Args:
            file_path: Path to the file

        Returns:
            Hex-encoded checksum
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                data = f.read(FILE_CHUNK_SIZE)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()

    def encrypt_chunk(self, chunk_data: bytes, chunk_number: int) -> bytes:
        """Encrypt a file chunk.

        Args:
            chunk_data: Raw chunk data
            chunk_number: Chunk sequence number

        Returns:
            Encrypted chunk data (nonce + ciphertext)

        Raises:
            FileTransferError: If encryption fails
        """
        try:
            cipher = ChaCha20Poly1305(self.encryption_key)

            # Use chunk number as part of the nonce to ensure uniqueness
            nonce = hashlib.sha256(
                self.transfer_id.encode() + chunk_number.to_bytes(8, "big")
            ).digest()[:NONCE_SIZE]

            # Encrypt chunk
            ciphertext = cipher.encrypt(nonce, chunk_data, None)

            # Return nonce + ciphertext
            return nonce + ciphertext

        except Exception as e:
            raise FileTransferError(
                ErrorCode.E602_CHUNK_FAILED,
                f"Chunk encryption failed: {e}",
                {"chunk": chunk_number, "error": str(e)},
            )

    def decrypt_chunk(self, encrypted_data: bytes, chunk_number: int) -> bytes:
        """Decrypt a file chunk.

        Args:
            encrypted_data: Encrypted chunk (nonce + ciphertext)
            chunk_number: Chunk sequence number

        Returns:
            Decrypted chunk data

        Raises:
            FileTransferError: If decryption fails
        """
        try:
            if len(encrypted_data) < NONCE_SIZE:
                raise FileTransferError(ErrorCode.E606_INVALID_CHUNK, "Encrypted data too short")

            nonce = encrypted_data[:NONCE_SIZE]
            ciphertext = encrypted_data[NONCE_SIZE:]

            cipher = ChaCha20Poly1305(self.encryption_key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            return plaintext

        except Exception as e:
            raise FileTransferError(
                ErrorCode.E602_CHUNK_FAILED,
                f"Chunk decryption failed: {e}",
                {"chunk": chunk_number, "error": str(e)},
            )

    async def send_file(
        self, file_path: Path, send_callback: Callable[[ChunkInfo], asyncio.Future]
    ) -> bool:
        """Send a file by chunks.

        Args:
            file_path: Path to the file to send
            send_callback: Async callback to send each chunk

        Returns:
            True if transfer completed successfully

        Raises:
            FileTransferError: If transfer fails
        """
        # Generate metadata
        metadata = self.chunk_file(file_path)

        logger.info(f"Starting file transfer: {metadata.filename}")

        try:
            with open(file_path, "rb") as f:
                for chunk_num in range(metadata.total_chunks):
                    # Read chunk
                    chunk_data = f.read(FILE_CHUNK_SIZE)

                    if not chunk_data:
                        break

                    # Calculate chunk checksum
                    chunk_checksum = hashlib.sha256(chunk_data).hexdigest()

                    # Encrypt chunk
                    encrypted_chunk = self.encrypt_chunk(chunk_data, chunk_num)

                    # Create chunk info
                    chunk_info = ChunkInfo(
                        chunk_number=chunk_num, data=encrypted_chunk, checksum=chunk_checksum
                    )

                    # Send chunk with retry
                    retry_count = 0
                    while retry_count < FILE_TRANSFER_RETRY_ATTEMPTS:
                        try:
                            await asyncio.wait_for(
                                send_callback(chunk_info), timeout=FILE_TRANSFER_TIMEOUT
                            )
                            break
                        except asyncio.TimeoutError:
                            retry_count += 1
                            if retry_count >= FILE_TRANSFER_RETRY_ATTEMPTS:
                                raise FileTransferError(
                                    ErrorCode.E604_TRANSFER_TIMEOUT,
                                    f"Chunk {chunk_num} send timeout after retries",
                                )
                            logger.warning(f"Chunk {chunk_num} timeout, retry {retry_count}")
                            await asyncio.sleep(FILE_TRANSFER_RETRY_DELAY)

                    # Mark as sent
                    self.chunks_sent.add(chunk_num)

                    # Update progress
                    if self.progress_callback:
                        self.progress_callback(chunk_num + 1, metadata.total_chunks)

                    logger.debug(f"Sent chunk {chunk_num + 1}/{metadata.total_chunks}")

            elapsed = time.time() - self.start_time
            logger.info(f"File transfer completed: {metadata.filename} " f"in {elapsed:.2f}s")

            return True

        except FileTransferError:
            raise
        except Exception as e:
            raise FileTransferError(
                ErrorCode.E600_FILE_TRANSFER_ERROR, f"File transfer failed: {e}", {"error": str(e)}
            )

    def receive_chunk(self, chunk_info: ChunkInfo) -> None:
        """Receive and store a file chunk.

        Args:
            chunk_info: Information about the received chunk

        Raises:
            FileTransferError: If chunk is invalid
        """
        if self.metadata is None:
            raise FileTransferError(
                ErrorCode.E600_FILE_TRANSFER_ERROR, "No metadata set for receiving"
            )

        chunk_num = chunk_info.chunk_number

        # Validate chunk number
        if chunk_num >= self.metadata.total_chunks:
            raise FileTransferError(
                ErrorCode.E606_INVALID_CHUNK,
                f"Invalid chunk number: {chunk_num}",
                {"chunk": chunk_num, "total": self.metadata.total_chunks},
            )

        # Decrypt chunk
        decrypted_data = self.decrypt_chunk(chunk_info.data, chunk_num)

        # Verify checksum
        actual_checksum = hashlib.sha256(decrypted_data).hexdigest()
        if actual_checksum != chunk_info.checksum:
            raise FileTransferError(
                ErrorCode.E603_CHECKSUM_MISMATCH,
                f"Chunk {chunk_num} checksum mismatch",
                {"expected": chunk_info.checksum, "actual": actual_checksum},
            )

        # Store chunk
        self.chunks_received[chunk_num] = decrypted_data

        # Update progress
        if self.progress_callback:
            self.progress_callback(len(self.chunks_received), self.metadata.total_chunks)

        logger.debug(f"Received chunk {chunk_num + 1}/{self.metadata.total_chunks}")

    def is_complete(self) -> bool:
        """Check if all chunks have been received.

        Returns:
            True if transfer is complete
        """
        if self.metadata is None:
            return False

        return len(self.chunks_received) == self.metadata.total_chunks

    def get_missing_chunks(self) -> List[int]:
        """Get list of missing chunk numbers.

        Returns:
            List of chunk numbers not yet received
        """
        if self.metadata is None:
            return []

        all_chunks = set(range(self.metadata.total_chunks))
        received = set(self.chunks_received.keys())
        return sorted(all_chunks - received)

    def reconstruct_file(self, output_path: Path) -> None:
        """Reconstruct the file from received chunks.

        Args:
            output_path: Path where to save the reconstructed file

        Raises:
            FileTransferError: If reconstruction fails or checksum mismatch
        """
        if not self.is_complete():
            missing = self.get_missing_chunks()
            raise FileTransferError(
                ErrorCode.E600_FILE_TRANSFER_ERROR,
                f"Cannot reconstruct: missing {len(missing)} chunks",
                {"missing_chunks": missing[:10]},  # Show first 10
            )

        if self.metadata is None:
            raise FileTransferError(ErrorCode.E600_FILE_TRANSFER_ERROR, "No metadata available")

        logger.info(f"Reconstructing file: {output_path}")

        try:
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Write chunks in order
            with open(output_path, "wb") as f:
                for chunk_num in range(self.metadata.total_chunks):
                    chunk_data = self.chunks_received[chunk_num]
                    f.write(chunk_data)

            # Verify file checksum
            actual_checksum = self._calculate_file_checksum(output_path)
            if actual_checksum != self.metadata.checksum:
                # Delete corrupted file
                output_path.unlink()
                raise FileTransferError(
                    ErrorCode.E603_CHECKSUM_MISMATCH,
                    "Reconstructed file checksum mismatch",
                    {"expected": self.metadata.checksum, "actual": actual_checksum},
                )

            logger.info(
                f"File reconstructed successfully: {output_path} " f"({self.metadata.size} bytes)"
            )

        except FileTransferError:
            raise
        except Exception as e:
            raise FileTransferError(
                ErrorCode.E600_FILE_TRANSFER_ERROR,
                f"File reconstruction failed: {e}",
                {"error": str(e)},
            )

    def get_progress(self) -> Dict:
        """Get transfer progress information.

        Returns:
            Dictionary with progress details
        """
        if self.metadata is None:
            return {"status": "not_started"}

        chunks_done = len(self.chunks_received) or len(self.chunks_sent)
        total_chunks = self.metadata.total_chunks
        percentage = (chunks_done / total_chunks * 100) if total_chunks > 0 else 0

        elapsed = time.time() - self.start_time
        bytes_done = chunks_done * FILE_CHUNK_SIZE
        speed = bytes_done / elapsed if elapsed > 0 else 0

        return {
            "status": "complete" if self.is_complete() else "in_progress",
            "chunks_done": chunks_done,
            "total_chunks": total_chunks,
            "percentage": round(percentage, 2),
            "bytes_transferred": bytes_done,
            "total_bytes": self.metadata.size,
            "elapsed_seconds": round(elapsed, 2),
            "speed_bytes_per_sec": round(speed, 2),
            "filename": self.metadata.filename,
        }
