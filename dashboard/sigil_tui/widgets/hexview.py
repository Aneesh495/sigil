"""
hexview.py - Hex dump formatter widget with ASCII decoding margin
"""

from typing import List


def format_hex_lines(data: bytes, width: int = 16) -> List[str]:
    """Format raw bytes into standard side-by-side hex and ASCII dump lines."""
    if not data:
        return ["(empty payload)"]

    lines = []
    total_len = len(data)

    for offset in range(0, total_len, width):
        chunk = data[offset : offset + width]

        # Hex values
        hex_parts = []
        for i in range(width):
            if i < len(chunk):
                hex_parts.append(f"{chunk[i]:02x}")
            else:
                hex_parts.append("  ")
            if i == 7:
                hex_parts.append(" ")

        hex_str = " ".join(hex_parts)

        # ASCII characters
        ascii_chars = []
        for b in chunk:
            ascii_chars.append(chr(b) if 32 <= b <= 126 else ".")
        ascii_str = "".join(ascii_chars)

        lines.append(f"{offset:08x}  {hex_str:<49} |{ascii_str}|")

    return lines
