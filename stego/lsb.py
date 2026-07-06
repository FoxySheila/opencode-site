"""LSB steganography primitives — 3 bits per pixel RGB encoding."""
import struct
import hashlib
from PIL import Image


def lsb_encode(image: Image.Image, payload: bytes) -> Image.Image:
    """LSB-encode payload into RGB channels (3 bits/pixel)."""
    img = image.copy()
    pixels = img.load()
    w, h = img.size
    data = struct.pack("<I", len(payload)) + payload
    data += hashlib.sha256(payload).digest()[:4]
    bits = ''.join(format(b, '08b') for b in data)
    bit_idx = 0
    for y in range(h):
        for x in range(w):
            if bit_idx >= len(bits):
                break
            px = pixels[x, y]  # type: ignore[index]
            if not isinstance(px, tuple):
                px = (int(px), int(px), int(px)) if px is not None else (0, 0, 0)
            r, g, b = int(px[0]), int(px[1]), int(px[2])
            r = (r & 0xFE) | int(bits[bit_idx]); bit_idx += 1
            if bit_idx >= len(bits):
                pixels[x, y] = (r, g, b)  # type: ignore[index]
                break
            g = (g & 0xFE) | int(bits[bit_idx]); bit_idx += 1
            if bit_idx >= len(bits):
                pixels[x, y] = (r, g, b)  # type: ignore[index]
                break
            b = (b & 0xFE) | int(bits[bit_idx]); bit_idx += 1
            pixels[x, y] = (r, g, b)  # type: ignore[index]
        if bit_idx >= len(bits):
            break
    return img


def lsb_extract(img: Image.Image) -> bytes:
    """Extract LSB-encoded payload from RGB channels."""
    pixels = img.load()
    w, h = img.size
    bits: list[str] = []
    for y in range(h):
        for x in range(w):
            px = pixels[x, y]
            if not isinstance(px, tuple):
                px = (0, 0, 0) if px is None else (int(px), int(px), int(px))
            r, g, b = px[0], px[1], px[2]
            bits.append(str(r & 1))
            bits.append(str(g & 1))
            bits.append(str(b & 1))
    if len(bits) < 32:
        return b""
    len_bytes = bytes(int(''.join(bits[i*8:(i+1)*8]), 2) for i in range(4))
    payload_len = struct.unpack("<I", len_bytes)[0]
    total_bits = 32 + (payload_len + 4) * 8
    if len(bits) < total_bits:
        return b""
    payload_bytes = bytes(
        int(''.join(bits[32 + i*8 : 32 + (i+1)*8]), 2)
        for i in range(payload_len + 4)
    )
    payload_data = payload_bytes[:-4]
    checksum = payload_bytes[-4:]
    if hashlib.sha256(payload_data).digest()[:4] != checksum:
        return b""
    return payload_data


def lsb_extract_file(image_path: str) -> bytes:
    """Load image and extract LSB payload. Returns b'' on failure."""
    try:
        with Image.open(image_path) as img:
            return lsb_extract(img)
    except Exception:
        return b""
