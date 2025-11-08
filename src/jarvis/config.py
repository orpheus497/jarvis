"""
Jarvis - Configuration Management

This module handles loading, merging, and managing configuration from
TOML files and environment variables. Supports default values and
runtime configuration updates.

Author: orpheus497
Version: 2.3.0
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Python 3.11+ has tomllib built-in, older versions need tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from .constants import (
    BACKUP_RETENTION_DAYS,
    CONFIG_FILENAME,
    CONNECTION_TIMEOUT,
    DEFAULT_DATA_DIR,
    DEFAULT_HOST,
    DEFAULT_SERVER_PORT,
    HEARTBEAT_INTERVAL,
    MAX_MESSAGE_SIZE,
    RATE_LIMIT_MESSAGES_PER_MINUTE,
)
from .errors import ConfigError, ErrorCode

# Default configuration dictionary
DEFAULT_CONFIG: Dict[str, Any] = {
    "network": {
        "host": DEFAULT_HOST,
        "port": DEFAULT_SERVER_PORT,
        "timeout": CONNECTION_TIMEOUT,
        "heartbeat_interval": HEARTBEAT_INTERVAL,
    },
    "limits": {
        "max_message_size": MAX_MESSAGE_SIZE,
        "rate_limit_per_minute": RATE_LIMIT_MESSAGES_PER_MINUTE,
    },
    "ui": {
        "theme": "dark",
        "notifications": True,
        "sound_enabled": False,
    },
    "backup": {
        "enabled": True,
        "retention_days": BACKUP_RETENTION_DAYS,
        "auto_backup": False,
    },
    "notifications": {
        "desktop_notifications": False,
        "message_preview": True,
    },
    "logging": {
        "level": "INFO",
        "file_logging": True,
        "console_logging": True,
    },
    "features": {
        "double_ratchet": True,
        "file_transfer": True,
        "voice_messages": False,
        "qr_codes": False,
    },
}


class Config:
    """Configuration manager for Jarvis.

    Loads configuration from TOML files, merges with defaults,
    and applies environment variable overrides. Provides a simple
    interface for accessing and updating configuration values.

    Attributes:
        config_path: Path to the configuration file
        data: Configuration dictionary
    """

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration manager.

        Args:
            config_path: Path to configuration file (optional)
                If not provided, uses default location
        """
        if config_path is None:
            data_dir = Path(DEFAULT_DATA_DIR).expanduser()
            config_path = data_dir / CONFIG_FILENAME

        self.config_path = Path(config_path)
        self.data = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file and merge with defaults.

        Returns:
            Merged configuration dictionary

        Raises:
            ConfigError: If configuration loading or parsing fails
        """
        # Start with default configuration
        config = DEFAULT_CONFIG.copy()

        # Load from file if it exists
        if self.config_path.exists():
            try:
                if tomllib is None:
                    raise ConfigError(
                        ErrorCode.E701_CONFIG_LOAD_FAILED,
                        "TOML library not available. Install tomli for Python < 3.11",
                    )

                with open(self.config_path, "rb") as f:
                    file_config = tomllib.load(f)

                # Merge file config with defaults
                config = self._merge_config(config, file_config)

            except Exception as e:
                if isinstance(e, ConfigError):
                    raise
                raise ConfigError(
                    ErrorCode.E704_CONFIG_PARSE_ERROR,
                    f"Failed to parse configuration file: {e}",
                    {"path": str(self.config_path), "error": str(e)},
                )

        # Apply environment variable overrides
        config = self._apply_env_overrides(config)

        return config

    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge override config into base config.

        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary

        Returns:
            Merged configuration dictionary
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                result[key] = self._merge_config(result[key], value)
            else:
                # Override the value
                result[key] = value

        return result

    def _apply_env_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides to configuration.

        Environment variables follow the pattern: JARVIS_SECTION_KEY
        For example: JARVIS_NETWORK_PORT=5001

        Args:
            config: Base configuration dictionary

        Returns:
            Configuration with environment overrides applied
        """
        result = config.copy()

        # Check for environment variable overrides
        for section, settings in config.items():
            if not isinstance(settings, dict):
                continue

            for key in settings:
                env_var = f"JARVIS_{section.upper()}_{key.upper()}"
                env_value = os.environ.get(env_var)

                if env_value is not None:
                    # Convert environment variable to appropriate type
                    original_type = type(settings[key])
                    try:
                        if original_type == bool:
                            result[section][key] = env_value.lower() in ("true", "1", "yes")
                        elif original_type == int:
                            result[section][key] = int(env_value)
                        elif original_type == float:
                            result[section][key] = float(env_value)
                        else:
                            result[section][key] = env_value
                    except ValueError:
                        # Keep original value if conversion fails
                        pass

        return result

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            section: Configuration section name
            key: Configuration key name
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self.data.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value.

        Args:
            section: Configuration section name
            key: Configuration key name
            value: Value to set
        """
        if section not in self.data:
            self.data[section] = {}

        self.data[section][key] = value

    def save(self) -> None:
        """Save current configuration to file.

        Raises:
            ConfigError: If saving fails
        """
        try:
            # Ensure directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            # Write TOML file
            with open(self.config_path, "w") as f:
                self._write_toml(f, self.data)

        except Exception as e:
            raise ConfigError(
                ErrorCode.E702_CONFIG_SAVE_FAILED,
                f"Failed to save configuration: {e}",
                {"path": str(self.config_path), "error": str(e)},
            )

    def _write_toml(self, file, data: Dict[str, Any], indent: int = 0) -> None:
        """Write configuration data as TOML format.

        Args:
            file: File object to write to
            data: Configuration data to write
            indent: Current indentation level
        """
        for section, settings in data.items():
            if isinstance(settings, dict):
                file.write(f"[{section}]\n")
                for key, value in settings.items():
                    if isinstance(value, bool):
                        file.write(f"{key} = {str(value).lower()}\n")
                    elif isinstance(value, (int, float)):
                        file.write(f"{key} = {value}\n")
                    elif isinstance(value, str):
                        file.write(f'{key} = "{value}"\n')
                file.write("\n")

    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary.

        Returns:
            Configuration dictionary
        """
        return self.data.copy()

    @classmethod
    def create_example(cls, path: Path) -> None:
        """Create an example configuration file.

        Args:
            path: Path where to create the example config

        Raises:
            ConfigError: If file creation fails
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w") as f:
                f.write("# Jarvis Configuration File\n")
                f.write("# Generated example configuration\n\n")

                config = cls(config_path=path)
                config.data = DEFAULT_CONFIG
                config._write_toml(f, DEFAULT_CONFIG)

        except Exception as e:
            raise ConfigError(
                ErrorCode.E702_CONFIG_SAVE_FAILED,
                f"Failed to create example configuration: {e}",
                {"path": str(path), "error": str(e)},
            )
