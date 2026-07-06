#!/usr/bin/env python3
"""token_img.py — embed/extract access tokens invisibly in PNG images.
Uses LSB steganography (3 bits/pixel RGB, SHA256 integrity).
Ported from Star Collapser's CRUN TLV stego format.

Commands:
  embed <image> <token> [output.png]
    → Hide token in image, save output PNG
  extract <image>
    → Reveal token hidden in image
  generate --label NAME [--duration 7d] <image> [output.png]
    → Generate new token via token_manager.py + embed in one step
  batch <token_file> <image_dir/pattern> [output_dir/]
    → Batch embed tokens into multiple images
"""
import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time

from stego import embed_all_into_png, extract_all_from_png

_QUICHASH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "checksum", "quichash", "quichash")


# ── helpers ──

def _blake3(data: bytes) -> str:
    r = subprocess.run([_QUICHASH, "-a", "BLAKE3"], input=data,
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"quichash: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode(errors='replace').strip().split()[0]


def _parse_duration(s: str) -> int:
    """Parse duration string like '7d', '30d', '24h', '1m' → seconds."""
    s = s.strip().lower()
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s) * 86400  # default: days


def _generate_token(length: int = 32) -> str:
    """Generate a cryptographically random token (BLAKE3 via quichash)."""
    raw = secrets.token_bytes(length)
    return "opc_" + _blake3(raw)[:24]


def _format_expiry(expires_ts: float | None) -> str:
    if expires_ts is None:
        return "never"
    remaining = expires_ts - time.time()
    if remaining <= 0:
        return "expired"
    days = int(remaining // 86400)
    hours = int((remaining % 86400) // 3600)
    if days > 0:
        return f"{days}d {hours}h"
    return f"{hours}h"


# ── commands ──

def cmd_embed(args):
    src, token, dst = args.image, args.token, args.output
    if not dst:
        base, ext = os.path.splitext(src)
        dst = f"{base}_stego{ext or '.png'}"
    payloads = {".token": token.encode()}
    if args.label:
        payloads[".label"] = args.label.encode()
    if args.note:
        payloads[".note"] = args.note.encode()
    embed_all_into_png(src, payloads, dst)
    sz = os.path.getsize(dst)
    print(f"✓ Token embedded: {dst} ({sz:,} bytes)")
    return dst


def cmd_extract(args):
    result = extract_all_from_png(args.image)
    token = result.get(b".token" if isinstance(list(result.keys())[0] if result else b"", bytes) else ".token", b"").decode()
    # handle both str and bytes keys
    token = None
    for k, v in result.items():
        key = k if isinstance(k, str) else k.decode()
        if key == ".token":
            token = v.decode()
            break
    if args.verbose:
        print("=== Extracted payloads ===")
        for k, v in result.items():
            key = k if isinstance(k, str) else k.decode()
            val = v.decode(errors="replace")
            if key == ".token":
                print(f"  {key}: {val}")
            elif key == ".label":
                print(f"  {key}: {val}")
            elif key == ".note":
                print(f"  {key}: {val}")
            else:
                print(f"  {key}: {len(v)} bytes")
        return
    if token:
        print(token)
    else:
        print("No .token payload found in image")
        return 1


def cmd_generate(args):
    # Generate token metadata
    token = _generate_token()
    label = args.label or "unnamed"
    duration_s = _parse_duration(args.duration) if args.duration else 0
    expires = None
    if duration_s > 0:
        expires = time.time() + duration_s
    expires_str = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(expires)) if expires else "never"
    print(f"Token:     {token}")
    print(f"Label:     {label}")
    print(f"Expires:   {expires_str}")
    # Push to KV via token_manager.py if available
    tm = os.path.join(os.path.dirname(__file__), "token_manager.py")
    if os.path.isfile(tm):
        cmd = [sys.executable, tm, "generate", "--token", token, "--label", label]
        if expires:
            cmd += ["--expires", str(int(expires))]
        if args.max_uses:
            cmd += ["--max-uses", str(args.max_uses)]
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"⚠  token_manager.py failed (exit {e.returncode}) — token not stored in KV")
        except FileNotFoundError:
            print("⚠  token_manager.py not executable — token not stored in KV")
    else:
        print("⚠  token_manager.py not found — token not stored in KV")
    # Embed into image
    src, dst = args.image, args.output
    payloads = {".token": token.encode(), ".label": label.encode()}
    if expires:
        payloads[".expires"] = str(int(expires)).encode()
    embed_all_into_png(src, payloads, dst)
    sz = os.path.getsize(dst)
    print(f"✓ Image saved: {dst} ({sz:,} bytes)")
    return dst


def cmd_batch(args):
    # Read tokens file (one token per line, optionally with label)
    with open(args.token_file) as f:
        lines = [line.strip() for line in f if line.strip()]
    tokens = []
    for line in lines:
        parts = line.split(maxsplit=1)
        tokens.append((parts[0], parts[1] if len(parts) > 1 else ""))
    # Find matching images
    import glob
    images = sorted(glob.glob(args.image_pattern))
    if not images:
        print(f"No images matching: {args.image_pattern}")
        return 1
    if len(tokens) != len(images):
        print(f"⚠  {len(tokens)} tokens but {len(images)} images — will pair sequentially, excess ignored")
    out_dir = args.output_dir or "stego_output"
    os.makedirs(out_dir, exist_ok=True)
    pairs = min(len(tokens), len(images))
    for i in range(pairs):
        tok, label = tokens[i]
        src = images[i]
        base = os.path.splitext(os.path.basename(src))[0]
        dst = os.path.join(out_dir, f"{base}_stego.png")
        payloads = {".token": tok.encode()}
        if label:
            payloads[".label"] = label.encode()
        embed_all_into_png(src, payloads, dst)
        print(f"  [{i+1}/{pairs}] {base} → {dst}")
    print(f"✓ {pairs} images processed → {out_dir}/")


# ── main ──

def main():
    p = argparse.ArgumentParser(description="Stego token image tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    # embed
    pe = sub.add_parser("embed", help="Embed a token into an image")
    pe.add_argument("image", help="Source image path")
    pe.add_argument("token", help="Access token to embed")
    pe.add_argument("output", nargs="?", help="Output PNG path (default: source_stego.png)")
    pe.add_argument("--label", help="Optional label (who this is for)")
    pe.add_argument("--note", help="Optional note stored alongside token")

    # extract
    px = sub.add_parser("extract", help="Extract token from a stego image")
    px.add_argument("image", help="Stego image path")
    px.add_argument("-v", "--verbose", action="store_true", help="Show all embedded payloads")

    # generate
    pg = sub.add_parser("generate", help="Generate new token + embed in one step")
    pg.add_argument("image", help="Source image path")
    pg.add_argument("output", nargs="?", help="Output PNG path (default: source_stego.png)")
    pg.add_argument("--label", default="unnamed", help="Label for who this token is for")
    pg.add_argument("--duration", default="30d", help="Token validity (e.g. 7d, 24h, 30d, never)")
    pg.add_argument("--max-uses", type=int, default=0, help="Max uses (0=unlimited)")

    # batch
    pb = sub.add_parser("batch", help="Batch embed tokens into images")
    pb.add_argument("token_file", help="File with one token per line (optional: token label)")
    pb.add_argument("image_pattern", help="Glob pattern for images (e.g. 'photos/*.png')")
    pb.add_argument("output_dir", nargs="?", help="Output directory (default: stego_output/)")

    args = p.parse_args()

    if args.cmd == "embed":
        return cmd_embed(args)
    elif args.cmd == "extract":
        return cmd_extract(args)
    elif args.cmd == "generate":
        if not args.output:
            base, ext = os.path.splitext(args.image)
            args.output = f"{base}_stego{ext or '.png'}"
        return cmd_generate(args)
    elif args.cmd == "batch":
        return cmd_batch(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
