"""
Jarvis - QR Code Generation for Contact Sharing

This module provides QR code generation for easy contact sharing.
Requires optional dependencies: qrcode and pillow.

Install with: pip install -r requirements-optional.txt

Author: orpheus497
Version: 2.0.0
"""

import base64
import json
import logging
from pathlib import Path
from typing import Dict, Optional

from .errors import ErrorCode, JarvisError

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import qrcode
    from qrcode.image.pure import PyPNGOrPILImage

    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False
    logger.warning("qrcode not available - QR code features disabled")

try:
    from PIL import Image

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("pillow not available - PNG export disabled")

try:
    from pyzbar import pyzbar

    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False
    logger.warning("pyzbar not available - QR code scanning disabled")


def generate_qr_code(
    data: str, error_correction: str = "M", box_size: int = 10, border: int = 4
) -> "qrcode.QRCode":
    """Generate a QR code from data.

    Args:
        data: Data to encode in QR code
        error_correction: Error correction level (L, M, Q, H)
        box_size: Size of each box in pixels
        border: Border size in boxes

    Returns:
        QR code object

    Raises:
        JarvisError: If QR code generation is not available or fails
    """
    if not QRCODE_AVAILABLE:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR,
            "QR code generation not available - install qrcode and pillow",
        )

    # Map error correction levels
    error_levels = {
        "L": qrcode.constants.ERROR_CORRECT_L,  # 7% correction
        "M": qrcode.constants.ERROR_CORRECT_M,  # 15% correction
        "Q": qrcode.constants.ERROR_CORRECT_Q,  # 25% correction
        "H": qrcode.constants.ERROR_CORRECT_H,  # 30% correction
    }

    error_level = error_levels.get(error_correction, qrcode.constants.ERROR_CORRECT_M)

    try:
        qr = qrcode.QRCode(
            version=1,  # Auto-adjust version
            error_correction=error_level,
            box_size=box_size,
            border=border,
        )

        qr.add_data(data)
        qr.make(fit=True)

        logger.debug(f"Generated QR code: {len(data)} bytes")
        return qr

    except Exception as e:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR, f"QR code generation failed: {e}", {"error": str(e)}
        )


def display_qr_terminal(qr: "qrcode.QRCode") -> str:
    """Display QR code as ASCII art for terminal.

    Args:
        qr: QR code object

    Returns:
        ASCII art representation of QR code
    """
    # Get QR code matrix
    matrix = qr.get_matrix()

    # Build ASCII art
    lines = []
    lines.append("█" * (len(matrix[0]) + 2))  # Top border

    for row in matrix:
        line = "█"  # Left border
        for cell in row:
            line += "  " if cell else "██"
        line += "█"  # Right border
        lines.append(line)

    lines.append("█" * (len(matrix[0]) + 2))  # Bottom border

    return "\n".join(lines)


def export_qr_png(
    qr: "qrcode.QRCode", output_path: Path, fill_color: str = "black", back_color: str = "white"
) -> None:
    """Export QR code as PNG image.

    Args:
        qr: QR code object
        output_path: Path to save PNG file
        fill_color: Foreground color
        back_color: Background color

    Raises:
        JarvisError: If PNG export is not available or fails
    """
    if not PIL_AVAILABLE:
        raise JarvisError(ErrorCode.E001_UNKNOWN_ERROR, "PNG export not available - install pillow")

    try:
        # Create image
        img = qr.make_image(fill_color=fill_color, back_color=back_color)

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save image
        img.save(str(output_path))

        logger.info(f"Exported QR code to: {output_path}")

    except Exception as e:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR, f"PNG export failed: {e}", {"error": str(e)}
        )


def encode_contact_data(
    username: str,
    public_key: bytes,
    address: Optional[str] = None,
    port: Optional[int] = None,
    display_name: Optional[str] = None,
) -> str:
    """Encode contact data for QR code sharing.

    Args:
        username: Contact username
        public_key: Contact's public key
        address: Optional IP address
        port: Optional port number
        display_name: Optional display name

    Returns:
        Encoded contact data string
    """
    # Create contact dictionary
    contact = {
        "version": "2.0",
        "type": "jarvis_contact",
        "username": username,
        "public_key": base64.b64encode(public_key).decode(),
    }

    if address:
        contact["address"] = address

    if port:
        contact["port"] = port

    if display_name:
        contact["display_name"] = display_name

    # Encode as JSON
    json_data = json.dumps(contact, separators=(",", ":"))

    logger.debug(f"Encoded contact data: {len(json_data)} bytes")
    return json_data


def decode_contact_data(encoded_data: str) -> Dict:
    """Decode contact data from QR code.

    Args:
        encoded_data: Encoded contact data string

    Returns:
        Dictionary with contact information

    Raises:
        JarvisError: If decoding fails or data is invalid
    """
    try:
        # Parse JSON
        contact = json.loads(encoded_data)

        # Validate required fields
        if contact.get("type") != "jarvis_contact":
            raise JarvisError(ErrorCode.E002_INVALID_ARGUMENT, "Invalid contact data: wrong type")

        if "username" not in contact or "public_key" not in contact:
            raise JarvisError(
                ErrorCode.E002_INVALID_ARGUMENT, "Invalid contact data: missing required fields"
            )

        # Decode public key
        contact["public_key"] = base64.b64decode(contact["public_key"])

        logger.debug(f"Decoded contact: {contact['username']}")
        return contact

    except json.JSONDecodeError as e:
        raise JarvisError(
            ErrorCode.E002_INVALID_ARGUMENT,
            f"Invalid contact data: JSON parse error: {e}",
            {"error": str(e)},
        )
    except JarvisError:
        raise
    except Exception as e:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR, f"Failed to decode contact data: {e}", {"error": str(e)}
        )


def create_contact_qr(
    username: str,
    public_key: bytes,
    address: Optional[str] = None,
    port: Optional[int] = None,
    display_name: Optional[str] = None,
    output_path: Optional[Path] = None,
    show_terminal: bool = True,
) -> str:
    """Create QR code for contact sharing.

    Args:
        username: Contact username
        public_key: Contact's public key
        address: Optional IP address
        port: Optional port number
        display_name: Optional display name
        output_path: Optional path to save PNG
        show_terminal: Whether to return terminal ASCII art

    Returns:
        ASCII art if show_terminal=True, otherwise empty string

    Raises:
        JarvisError: If QR code creation fails
    """
    # Encode contact data
    contact_data = encode_contact_data(username, public_key, address, port, display_name)

    # Generate QR code
    qr = generate_qr_code(contact_data, error_correction="M")

    # Export to PNG if requested
    if output_path:
        export_qr_png(qr, output_path)

    # Return ASCII art if requested
    if show_terminal:
        return display_qr_terminal(qr)

    return ""


def is_qr_available() -> bool:
    """Check if QR code features are available.

    Returns:
        True if QR code features are available
    """
    return QRCODE_AVAILABLE


def scan_qr_code(image_path: Path) -> str:
    """Scan and decode QR code from image file.

    Uses pyzbar library to decode QR codes from PNG, JPG, and other image formats.
    Supports multiple QR codes in a single image (returns first valid one).

    Args:
        image_path: Path to image containing QR code

    Returns:
        Decoded QR code data as string

    Raises:
        JarvisError: If scanning is not available, file not found, or decode fails
    """
    if not PYZBAR_AVAILABLE:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR,
            "QR code scanning not available - install pyzbar library",
        )

    if not PIL_AVAILABLE:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR,
            "QR code scanning requires pillow library for image loading",
        )

    # Validate image path
    if not image_path.exists():
        raise JarvisError(
            ErrorCode.E002_INVALID_ARGUMENT,
            f"Image file not found: {image_path}",
            {"path": str(image_path)},
        )

    try:
        # Load image using PIL
        image = Image.open(image_path)
        logger.debug(f"Loaded image: {image_path} ({image.size[0]}x{image.size[1]})")

        # Decode QR codes from image
        decoded_objects = pyzbar.decode(image)

        # Check if any QR codes were found
        if not decoded_objects:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                "No QR code found in image",
                {"path": str(image_path)},
            )

        # Extract data from first QR code
        qr_data = decoded_objects[0].data.decode("utf-8")
        logger.info(
            f"Successfully decoded QR code from {image_path.name}: {len(qr_data)} bytes"
        )

        # Log additional QR codes if present
        if len(decoded_objects) > 1:
            logger.info(
                f"Found {len(decoded_objects)} QR codes in image, using first one"
            )

        return qr_data

    except JarvisError:
        raise
    except UnicodeDecodeError as e:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR,
            f"QR code contains invalid text encoding: {e}",
            {"error": str(e), "path": str(image_path)},
        )
    except Exception as e:
        raise JarvisError(
            ErrorCode.E001_UNKNOWN_ERROR,
            f"Failed to scan QR code: {e}",
            {"error": str(e), "path": str(image_path)},
        )


# Example usage function
def create_example_qr(username: str = "example_user") -> None:
    """Create an example QR code for testing.

    Args:
        username: Username for example contact
    """
    if not is_qr_available():
        print("QR code features not available")
        return

    # Generate example public key (32 bytes)
    import secrets

    example_key = secrets.token_bytes(32)

    # Create QR code
    ascii_qr = create_contact_qr(
        username=username,
        public_key=example_key,
        address="192.168.1.100",
        port=5000,
        display_name="Example User",
        show_terminal=True,
    )

    print("\nExample Contact QR Code:")
    print(ascii_qr)
    print(f"\nScan this QR code to add '{username}' as a contact!")
