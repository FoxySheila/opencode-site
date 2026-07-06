"""PNG steganography — embed/extract payloads invisibly in RGB pixels.
LSB encodes 3 bits per pixel with SHA256 integrity check.
Ported from Star Collapser's stego module (CRUN TLV format)."""
import struct
from PIL import Image

from .lsb import lsb_encode, lsb_extract

_UNIFIED_MAGIC = b"CRUN"

PAYLOAD_KEYS = [
    ".token", ".label", ".note", ".crypt", ".catalog", ".layout",
    ".seek_map", ".health", ".manifest", ".operator", ".hardware",
    ".recovery_script", ".info_text", ".cipher", ".bot", ".ledger",
    ".age_secret", ".sec", ".entropy", ".shadow", ".version",
    ".config", ".tape_index",
]


def embed_all_into_png(image_path: str, payloads: dict[str, bytes],
                       output_path: str) -> str:
    """LSB-encode ALL payloads into image pixels.
    
    Payloads dict can include any PAYLOAD_KEYS.
    Missing keys are skipped. Image auto-scales if payload exceeds capacity.
    Output PNG looks identical to input — no visible overlay.
    """
    img = Image.open(image_path).convert("RGB")

    entries = [(k, v) for k, v in payloads.items() if k in PAYLOAD_KEYS and v]
    blob = struct.pack("<I", len(entries))
    for name, data in entries:
        name_b = name.encode("utf-8")
        blob += struct.pack("<H", len(name_b)) + name_b
        if isinstance(data, str):
            data = data.encode("utf-8")
        blob += struct.pack("<I", len(data)) + data

    full = _UNIFIED_MAGIC + blob

    # Auto-scale if payload exceeds image capacity
    capacity = img.size[0] * img.size[1] * 3 // 8
    if len(full) > capacity:
        needed_px = (len(full) * 8 + 2) // 3
        scale = (needed_px / (img.size[0] * img.size[1])) ** 0.5
        new_w = int(img.size[0] * scale) + 1
        new_h = int(img.size[1] * scale) + 1
        lanczos = getattr(Image.Resampling, 'LANCZOS', None) or 1
        img = img.resize((new_w, new_h), lanczos)

    img_stego = lsb_encode(img, full)
    img_stego.save(output_path, format="PNG", compress_level=6)
    return output_path


def extract_all_from_png(image_path: str) -> dict[str, bytes]:
    """LSB-extract all payloads from a stego PNG.
    
    Returns dict of name → bytes. Raises ValueError if no payload found.
    """
    img = Image.open(image_path).convert("RGB")
    data = lsb_extract(img)
    if not data or not data.startswith(_UNIFIED_MAGIC):
        msg = f"No unified payload found in {image_path}"
        raise ValueError(msg)

    blob = data[len(_UNIFIED_MAGIC):]
    off = 0
    entry_count = struct.unpack_from("<I", blob, off)[0]
    off += 4
    result: dict[str, bytes] = {}
    for _ in range(entry_count):
        name_len = struct.unpack_from("<H", blob, off)[0]
        off += 2
        name = blob[off:off + name_len].decode("utf-8")
        off += name_len
        data_len = struct.unpack_from("<I", blob, off)[0]
        off += 4
        result[name] = blob[off:off + data_len]
        off += data_len
    return result
