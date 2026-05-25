"""
Generate placeholder PNG icons for the CyberShield extension.
Run: python generate_icons.py
Requires: pip install Pillow
"""
import os
import struct
import zlib


def create_png(size, color_bg=(10, 10, 20), color_fg=(0, 212, 255)):
    """Create a simple shield icon as PNG bytes."""
    w, h = size, size
    pixels = []

    cx, cy = w / 2, h / 2
    r = w * 0.42

    for y in range(h):
        row = []
        for x in range(w):
            dx = x - cx
            dy = y - cy
            dist = (dx**2 + dy**2) ** 0.5

            # Shield shape
            in_circle = dist < r
            # Simple circle shield
            if in_circle:
                # Gradient glow
                t = 1 - (dist / r)
                intensity = int(t * 80)
                r_val = min(255, color_fg[0] + intensity)
                g_val = min(255, color_fg[1] + intensity)
                b_val = min(255, color_fg[2] + intensity)
                if dist < r * 0.6:
                    row.extend([255, 255, 255, 255])
                elif dist < r * 0.8:
                    row.extend([r_val, g_val, b_val, 255])
                else:
                    row.extend([color_bg[0] + intensity // 2, color_bg[1] + intensity // 2, color_bg[2] + intensity // 2, 255])
            else:
                # Transparent background
                row.extend([0, 0, 0, 0])
        pixels.append(row)

    # Build PNG
    raw = b""
    for row in pixels:
        raw += b"\x00" + bytes(row)

    compressed = zlib.compress(raw)
    chunks = []

    # IHDR
    ihdr_data = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)  # RGBA = type 6
    ihdr_data = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    chunks.append(make_chunk(b"IHDR", ihdr_data))
    chunks.append(make_chunk(b"IDAT", compressed))
    chunks.append(make_chunk(b"IEND", b""))

    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def make_chunk(name, data):
    c = zlib.crc32(name + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", c)


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "extension", "icons")
    os.makedirs(out_dir, exist_ok=True)

    sizes = [16, 32, 48, 128]
    for size in sizes:
        png = create_png(size)
        path = os.path.join(out_dir, f"icon{size}.png")
        with open(path, "wb") as f:
            f.write(png)
        print(f"Created {path}")

    print("Icons generated!")


if __name__ == "__main__":
    main()
