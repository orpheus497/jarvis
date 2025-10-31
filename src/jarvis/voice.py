"""
Jarvis - Voice Message Recording and Playback

This module provides voice message recording and playback functionality.
Requires optional dependencies: sounddevice and soundfile.

Install with: pip install -r requirements-optional.txt

Author: orpheus497
Version: 2.0.0
"""

import logging
import time
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Callable

import numpy as np

from .constants import (
    VOICE_MAX_DURATION,
    VOICE_SAMPLE_RATE,
    VOICE_CHANNELS,
    VOICE_CHUNK_DURATION,
)
from .errors import JarvisError, ErrorCode

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import sounddevice as sd
    SOUNDDEVICE_AVAILABLE = True
except ImportError:
    SOUNDDEVICE_AVAILABLE = False
    logger.warning("sounddevice not available - voice messages disabled")

try:
    import soundfile as sf
    SOUNDFILE_AVAILABLE = True
except ImportError:
    SOUNDFILE_AVAILABLE = False
    logger.warning("soundfile not available - voice messages disabled")

VOICE_AVAILABLE = SOUNDDEVICE_AVAILABLE and SOUNDFILE_AVAILABLE


class VoiceRecorder:
    """Records voice messages.

    Captures audio from the default input device and saves as
    compressed audio file. Supports duration limiting and
    real-time level monitoring.

    Attributes:
        sample_rate: Audio sample rate (Hz)
        channels: Number of audio channels (1=mono, 2=stereo)
        max_duration: Maximum recording duration (seconds)
        recording: Whether currently recording
        audio_data: Recorded audio samples
        start_time: Recording start timestamp
        level_callback: Optional callback for audio level updates
    """

    def __init__(
        self,
        sample_rate: int = VOICE_SAMPLE_RATE,
        channels: int = VOICE_CHANNELS,
        max_duration: int = VOICE_MAX_DURATION,
        level_callback: Optional[Callable[[float], None]] = None
    ):
        """Initialize voice recorder.

        Args:
            sample_rate: Sample rate in Hz
            channels: Number of channels (1 or 2)
            max_duration: Maximum recording duration in seconds
            level_callback: Optional callback for audio level updates

        Raises:
            JarvisError: If voice recording is not available
        """
        if not VOICE_AVAILABLE:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "Voice recording not available - install sounddevice and soundfile"
            )

        self.sample_rate = sample_rate
        self.channels = channels
        self.max_duration = max_duration
        self.recording = False
        self.audio_data: List[np.ndarray] = []
        self.start_time: Optional[float] = None
        self.level_callback = level_callback

        logger.info(
            f"Voice recorder initialized: "
            f"{sample_rate}Hz, {channels}ch, max {max_duration}s"
        )

    def record(self) -> None:
        """Start recording audio.

        Raises:
            JarvisError: If recording fails or already recording
        """
        if self.recording:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "Already recording"
            )

        logger.info("Starting voice recording")

        try:
            self.recording = True
            self.audio_data = []
            self.start_time = time.time()

            # Callback for audio input
            def callback(indata, frames, time_info, status):
                if status:
                    logger.warning(f"Recording status: {status}")

                # Store audio data
                self.audio_data.append(indata.copy())

                # Calculate audio level (RMS)
                if self.level_callback:
                    level = np.sqrt(np.mean(indata**2))
                    self.level_callback(float(level))

                # Check duration
                elapsed = time.time() - self.start_time
                if elapsed >= self.max_duration:
                    logger.info("Maximum recording duration reached")
                    raise sd.CallbackStop()

            # Start input stream
            with sd.InputStream(
                samplerate=self.sample_rate,
                channels=self.channels,
                callback=callback
            ):
                # Record until stopped or max duration reached
                while self.recording:
                    sd.sleep(100)

        except sd.CallbackStop:
            # Normal termination due to max duration
            pass
        except Exception as e:
            self.recording = False
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Recording failed: {e}",
                {"error": str(e)}
            )
        finally:
            self.recording = False

    def stop_recording(self) -> None:
        """Stop the current recording."""
        if not self.recording:
            return

        self.recording = False
        logger.info("Stopped voice recording")

    def get_duration(self) -> float:
        """Get duration of recorded audio.

        Returns:
            Duration in seconds
        """
        if not self.audio_data:
            return 0.0

        total_samples = sum(len(chunk) for chunk in self.audio_data)
        return total_samples / self.sample_rate

    def save(self, output_path: Path, format: str = 'WAV') -> None:
        """Save recorded audio to file.

        Args:
            output_path: Path to save audio file
            format: Audio format (WAV, FLAC, OGG, etc.)

        Raises:
            JarvisError: If no audio recorded or save fails
        """
        if not self.audio_data:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "No audio data to save"
            )

        try:
            # Concatenate all audio chunks
            audio = np.concatenate(self.audio_data, axis=0)

            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Save audio file
            sf.write(
                str(output_path),
                audio,
                self.sample_rate,
                format=format
            )

            duration = self.get_duration()
            logger.info(
                f"Saved voice message: {output_path} ({duration:.1f}s)"
            )

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Failed to save audio: {e}",
                {"error": str(e)}
            )

    def encode(self, format: str = 'WAV') -> bytes:
        """Encode recorded audio to bytes.

        Args:
            format: Audio format (WAV, FLAC, OGG, etc.)

        Returns:
            Encoded audio data

        Raises:
            JarvisError: If encoding fails
        """
        if not self.audio_data:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "No audio data to encode"
            )

        try:
            # Concatenate all audio chunks
            audio = np.concatenate(self.audio_data, axis=0)

            # Encode to BytesIO
            buffer = BytesIO()
            sf.write(buffer, audio, self.sample_rate, format=format)

            # Get bytes
            buffer.seek(0)
            encoded = buffer.read()

            logger.debug(f"Encoded audio: {len(encoded)} bytes")
            return encoded

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Failed to encode audio: {e}",
                {"error": str(e)}
            )


class VoicePlayer:
    """Plays voice messages.

    Plays audio files or audio data through the default output device.
    Supports playback control and waveform visualization.

    Attributes:
        playing: Whether currently playing
        current_stream: Active audio stream
    """

    def __init__(self):
        """Initialize voice player.

        Raises:
            JarvisError: If voice playback is not available
        """
        if not VOICE_AVAILABLE:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "Voice playback not available - install sounddevice and soundfile"
            )

        self.playing = False
        self.current_stream = None

        logger.info("Voice player initialized")

    def play(self, audio_path: Optional[Path] = None, audio_data: Optional[bytes] = None) -> None:
        """Play audio file or audio data.

        Args:
            audio_path: Path to audio file (optional)
            audio_data: Audio data bytes (optional)

        Raises:
            JarvisError: If playback fails
        """
        if self.playing:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "Already playing audio"
            )

        if not audio_path and not audio_data:
            raise JarvisError(
                ErrorCode.E002_INVALID_ARGUMENT,
                "Either audio_path or audio_data must be provided"
            )

        try:
            # Load audio
            if audio_path:
                audio, sample_rate = sf.read(str(audio_path))
            else:
                buffer = BytesIO(audio_data)
                audio, sample_rate = sf.read(buffer)

            logger.info(f"Playing audio: {len(audio)} samples @ {sample_rate}Hz")

            # Play audio
            self.playing = True
            sd.play(audio, sample_rate)
            sd.wait()  # Wait until playback finishes
            self.playing = False

            logger.info("Audio playback completed")

        except Exception as e:
            self.playing = False
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Playback failed: {e}",
                {"error": str(e)}
            )

    def stop(self) -> None:
        """Stop the current playback."""
        if not self.playing:
            return

        try:
            sd.stop()
            self.playing = False
            logger.info("Stopped audio playback")
        except Exception as e:
            logger.warning(f"Failed to stop playback: {e}")

    @staticmethod
    def get_waveform(
        audio_path: Optional[Path] = None,
        audio_data: Optional[bytes] = None,
        width: int = 100
    ) -> List[int]:
        """Get waveform visualization data.

        Args:
            audio_path: Path to audio file (optional)
            audio_data: Audio data bytes (optional)
            width: Number of waveform bars

        Returns:
            List of waveform levels (0-100)

        Raises:
            JarvisError: If waveform generation fails
        """
        if not VOICE_AVAILABLE:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "Voice features not available"
            )

        if not audio_path and not audio_data:
            raise JarvisError(
                ErrorCode.E002_INVALID_ARGUMENT,
                "Either audio_path or audio_data must be provided"
            )

        try:
            # Load audio
            if audio_path:
                audio, sample_rate = sf.read(str(audio_path))
            else:
                buffer = BytesIO(audio_data)
                audio, sample_rate = sf.read(buffer)

            # If stereo, convert to mono
            if len(audio.shape) > 1:
                audio = np.mean(audio, axis=1)

            # Calculate chunk size
            chunk_size = len(audio) // width

            if chunk_size == 0:
                chunk_size = 1

            # Calculate waveform levels
            waveform = []
            for i in range(width):
                start = i * chunk_size
                end = min(start + chunk_size, len(audio))
                chunk = audio[start:end]

                # Calculate RMS level
                level = np.sqrt(np.mean(chunk**2))

                # Normalize to 0-100
                normalized = int(min(level * 200, 100))
                waveform.append(normalized)

            return waveform

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Failed to generate waveform: {e}",
                {"error": str(e)}
            )


def is_voice_available() -> bool:
    """Check if voice message features are available.

    Returns:
        True if voice features are available
    """
    return VOICE_AVAILABLE


def get_input_devices() -> List[Dict]:
    """Get list of available input devices.

    Returns:
        List of device information dictionaries

    Raises:
        JarvisError: If voice features are not available
    """
    if not VOICE_AVAILABLE:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR,
            "Voice features not available"
        )

    try:
        devices = sd.query_devices()
        input_devices = []

        for i, device in enumerate(devices):
            if device['max_input_channels'] > 0:
                input_devices.append({
                    'index': i,
                    'name': device['name'],
                    'channels': device['max_input_channels'],
                    'sample_rate': device['default_samplerate'],
                })

        return input_devices

    except Exception as e:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR,
            f"Failed to query devices: {e}",
            {"error": str(e)}
        )
