"""
sparkline.py - Unicode sparkline generator for terminal telemetry
"""

from typing import Sequence

SPARK_CHARS = (" ", "▂", "▃", "▄", "▅", "▆", "▇", "█")


def render_sparkline(values: Sequence[float], width: int = 30) -> str:
    """Render a sequence of numeric values into an 8-level Unicode sparkline."""
    if not values:
        return " " * width

    # Window to target width
    tail = list(values)[-width:]
    min_v = min(tail)
    max_v = max(tail)
    span = max_v - min_v

    chars = []
    for v in tail:
        if span == 0:
            idx = 3
        else:
            normalized = (v - min_v) / span
            idx = min(7, max(0, int(normalized * 7.99)))
        chars.append(SPARK_CHARS[idx])

    # Left-pad if fewer values than width
    line = "".join(chars)
    if len(line) < width:
        line = (" " * (width - len(line))) + line

    return line
