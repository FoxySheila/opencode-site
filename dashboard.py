#!/usr/bin/env python3
"""dashboard.py — token generation wizard.

Flow: browse for image → label → duration → max uses → generate+embed+store.

Usage:  python3 dashboard.py
"""
import hashlib
import http.cookiejar
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor

from stego import embed_all_into_png

_PROJECT_DIR = Path(__file__).parent
_BIN_DIR = _PROJECT_DIR / "bin"
_QUICHASH = _BIN_DIR / "checksum" / "quichash" / "quichash"
_AGE = _BIN_DIR / "age" / "age"

# ── Config ──

_CONFIG_PATH = Path.home() / ".config" / "opencode-site.json"

_DEFAULTS = {
    "pool_dir": str(_PROJECT_DIR / "pool"),
    "templates_dir": str(_PROJECT_DIR / "templates"),
    "stego_output_dir": str(_PROJECT_DIR / "stego_output"),
}

_config = None

def _load_config():
    global _config
    if _config is not None:
        return _config
    cfg = dict(_DEFAULTS)
    if _CONFIG_PATH.exists():
        try:
            with open(_CONFIG_PATH) as f:
                user = json.load(f)
            cfg.update({k: v for k, v in user.items() if k in _DEFAULTS})
        except (json.JSONDecodeError, OSError):
            pass
    _config = cfg
    return cfg

def _pool_dir():
    return Path(_load_config()["pool_dir"])

def _templates_dir():
    return Path(_load_config()["templates_dir"])

def _stego_dir():
    return Path(_load_config()["stego_output_dir"])


# ── ANSI helpers (blessed-style, no dep needed) ──

class C:
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    CLR = "\033[H\033[J"


def header(title: str):
    print(f"{C.CLR}{C.CYAN}═{'═' * 55}╗{C.RESET}")
    print(f"{C.CYAN}║  {C.BOLD}{title}{C.RESET}")
    print(f"{C.CYAN}╚{'═' * 55}╝{C.RESET}\n")


def prompt(text: str, default: str = "", suffix: str = "") -> str:
    d = f" [{default}]" if default else ""
    s = f" {suffix}" if suffix else ""
    raw = input(f"  {C.CYAN}>{C.RESET} {text}{C.DIM}{d}{s}{C.RESET}: ").strip()
    if not raw:
        return default
    return raw


def warn(msg: str):
    print(f"  {C.YELLOW}⚠  {msg}{C.RESET}")


def ok(msg: str):
    print(f"  {C.GREEN}✓ {msg}{C.RESET}")


def fail(msg: str):
    print(f"  {C.RED}✗ {msg}{C.RESET}")


# ── Crypto helpers ──

def _blake3(data: bytes) -> str:
    r = subprocess.run([str(_QUICHASH), "-a", "BLAKE3"], input=data,
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"quichash: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode(errors='replace').strip().split()[0]


def _age_encrypt(data: bytes) -> bytes:
    pubkey = (_PROJECT_DIR / "site.agepub").read_text().strip()
    r = subprocess.run([str(_AGE), "-e", "-r", pubkey], input=data,
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"age encrypt: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _generate_token() -> str:
    raw = secrets.token_bytes(32)
    return "opc_" + _blake3(raw)[:24]


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _ensure_dirs():
    _stego_dir().mkdir(parents=True, exist_ok=True)
    _templates_dir().mkdir(parents=True, exist_ok=True)
    _pool_dir().mkdir(parents=True, exist_ok=True)


# ── File browser ──

def _list_images(directory: Path) -> list[Path]:
    exts = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp', '.tiff'}
    if not directory.is_dir():
        return []
    return sorted(
        [f for f in directory.iterdir() if f.suffix.lower() in exts],
        key=lambda p: p.name.lower()
    )


def _browse_dir(directory: Path, label: str) -> Path | None:
    """Show files in a directory, let user pick one. Returns Path or None."""
    images = _list_images(directory)
    if not images:
        warn(f"No images found in {label}")
        input(f"  {C.DIM}Press Enter to continue{C.RESET}")
        return None

    print(f"\n  {C.BOLD}{label}{C.RESET}\n")
    for i, img in enumerate(images, 1):
        sz = _fmt_size(img.stat().st_size)
        print(f"    {C.CYAN}{i:2}){C.RESET}  {img.name}  {C.DIM}({sz}){C.RESET}")
    print()

    while True:
        raw = input(f"  {C.CYAN}>{C.RESET} Select image (1-{len(images)}, or {C.DIM}q{C.RESET} to cancel): ").strip()
        if raw.lower() == 'q':
            return None
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(images):
                return images[idx]
        except ValueError:
            pass


def browse_file() -> Path | None:
    """Pick image from pool or templates directory."""
    while True:
        header("Select an Image")
        print(f"  {C.BOLD}Choose a source:{C.RESET}\n")
        print(f"    {C.CYAN}1){C.RESET}  Pool  {C.DIM}({_pool_dir()}){C.RESET}")
        print(f"    {C.CYAN}2){C.RESET}  Templates  {C.DIM}({_templates_dir()}){C.RESET}")
        print(f"    {C.CYAN}q){C.RESET}  Quit\n")

        choice = input(f"  {C.CYAN}>{C.RESET} Choice: ").strip().lower()

        if choice == 'q':
            return None
        elif choice == '1':
            result = _browse_dir(_pool_dir(), f"══ pool/ ══")
            if result:
                return result
        elif choice == '2':
            result = _browse_dir(_templates_dir(), f"══ templates/ ══")
            if result:
                return result


# ── Duration picker ──

def pick_duration() -> int | None:
    """Returns seconds, or None for no expiry."""
    presets = [
        ("1 day", 86400),
        ("7 days", 604800),
        ("30 days", 2592000),
        ("90 days", 7776000),
        ("Custom", None),
        ("No expiry", None),
    ]
    print(f"\n  {C.BOLD}Duration:{C.RESET}\n")
    for i, (label, secs) in enumerate(presets, 1):
        tag = " (default)" if i == 3 else ""
        print(f"    {C.CYAN}{i}){C.RESET}  {label}{C.DIM}{tag}{C.RESET}")
    print()

    while True:
        raw = input(f"  {C.CYAN}>{C.RESET} Choice [3]: ").strip()
        if not raw:
            return 2592000  # default 30d
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(presets):
                label, secs = presets[idx]
                if label == "No expiry":
                    return None
                if label == "Custom":
                    val = input(f"  {C.CYAN}>{C.RESET} Duration (e.g. 14d, 48h, 90m): ").strip()
                    if val:
                        secs = _parse_duration(val)
                        if secs:
                            return secs
                        warn("Invalid format, try again")
                        continue
                    return 2592000
                if secs:
                    return secs
        except ValueError:
            pass


def _parse_duration(s: str) -> int | None:
    s = s.strip().lower()
    try:
        if s.endswith("d"):
            return int(s[:-1]) * 86400
        if s.endswith("h"):
            return int(s[:-1]) * 3600
        if s.endswith("m"):
            return int(s[:-1]) * 60
        if s.endswith("s"):
            return int(s[:-1])
        return int(s) * 86400
    except ValueError:
        return None


# ── Max uses prompt ──

def pick_max_uses() -> int:
    raw = input(f"  {C.CYAN}>{C.RESET} Max uses {C.DIM}[0 = unlimited]{C.RESET}: ").strip()
    if not raw:
        return 0
    try:
        n = int(raw)
        return max(0, n)
    except ValueError:
        return 0


# ── KV storage ──

def _kv_opener():
    """Return cookie-based opener if CF_COOKIE_FILE is set."""
    cf = os.environ.get("CF_COOKIE_FILE", "")
    if not cf or not os.path.isfile(cf):
        return None
    cj = http.cookiejar.MozillaCookieJar(cf)
    cj.load(ignore_expires=True, ignore_discard=True)
    return build_opener(HTTPCookieProcessor(cj))


def _kv_base() -> str:
    return "https://dash.cloudflare.com/api/v4" if os.environ.get("CF_COOKIE_FILE", "") else "https://api.cloudflare.com/client/v4"


def store_in_kv(api_token: str, account_id: str, ns_id: str,
                key: str, value: bytes, expiration: int | None) -> bool:
    path = f"{_kv_base()}/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}"
    if expiration:
        path += f"?expiration={expiration}"
    opener = _kv_opener()
    hdrs = {"Content-Type": "application/octet-stream"}
    if not opener:
        hdrs["Authorization"] = f"Bearer {api_token}"
    req = Request(path, data=value, headers=hdrs, method="PUT")
    try:
        opener_ctx = opener if opener else urlopen
        with opener_ctx.open(req) as r:
            resp = json.loads(r.read())
        return resp.get("success", False)
    except Exception as e:
        fail(f"KV write failed: {e}")
        return False


# ── Main wizard ──

def main():
    _load_config()
    _ensure_dirs()

    # ── 1. Browse for image ──
    image = browse_file()
    if not image:
        print(f"\n  {C.YELLOW}No image selected. Exiting.{C.RESET}")
        return

    # Copy to pool for future use
    pool_dst = _pool_dir() / image.name
    if image != pool_dst and not pool_dst.exists():
        try:
            shutil.copy2(str(image), str(pool_dst))
        except Exception:
            pass

    header("Token Details")

    # ── 2. Label ──
    label = prompt("Label (friend's name)", default="unnamed")
    print()

    # ── 3. Duration ──
    duration_s = pick_duration()
    expires_ts = int(time.time()) + duration_s if duration_s else None
    expires_display = (
        datetime.fromtimestamp(expires_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if expires_ts else "never"
    )
    print()

    # ── 4. Max uses ──
    max_uses = pick_max_uses()
    uses_display = "unlimited" if max_uses == 0 else str(max_uses)
    print()

    # ── 5. Generate ──
    header("Generating Token")

    print(f"  {C.DIM}Creating random token...{C.RESET}")
    token = _generate_token()
    ok(f"Token: {C.BOLD}{token}{C.RESET}")

    print(f"  {C.DIM}Age-encrypting metadata...{C.RESET}")
    now = int(time.time())
    meta = {
        "label": label,
        "created": now,
        "expires": expires_ts,
        "max_uses": max_uses,
        "use_count": 0,
    }
    try:
        encrypted = _age_encrypt(json.dumps(meta).encode())
        ok(f"Encrypted: {len(encrypted)} bytes")
    except Exception as e:
        fail(f"Age encrypt failed: {e}")
        return

    # ── 6. Store in KV ──
    api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    ns_id = os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
    cookie_file = os.environ.get("CF_COOKIE_FILE", "")

    key = f"tok_{_sha256(token)}"
    uses_key = f"{key}:u"

    kv_ok = False
    if api_token and account_id and ns_id:
        print(f"  {C.DIM}Storing in KV...{C.RESET}")

        # Main entry (age-encrypted blob, TTL = expiry)
        ok1 = store_in_kv(api_token, account_id, ns_id, key, encrypted, expires_ts)

        # Usage counter entry (plaintext, same TTL)
        uses_data = json.dumps({"n": 0, "m": max_uses}).encode()
        ok2 = store_in_kv(api_token, account_id, ns_id, uses_key, uses_data, expires_ts)

        if ok1 and ok2:
            kv_ok = True
            ok("Stored in KV")
        else:
            warn("KV storage incomplete — check token_manager.py push later")
    else:
        warn("CLOUDFLARE_API_TOKEN/ACCOUNT_ID/KV_NAMESPACE not set — skipped KV")
        warn("Use token_manager.py to push later")

    # ── 7. Embed into image ──
    safe_label = "".join(c if c.isalnum() else "_" for c in label)
    out_name = f"{safe_label}_{time.strftime('%Y%m%d_%H%M%S')}.png"
    out_path = str(_stego_dir() / out_name)

    print(f"  {C.DIM}Embedding token into {image.name}...{C.RESET}")
    payloads = {".token": token.encode(), ".label": label.encode()}
    try:
        embed_all_into_png(str(image), payloads, out_path)
        sz = os.path.getsize(out_path)
        ok(f"Stego image: {C.BOLD}{out_path}{C.RESET} ({_fmt_size(sz)})")
    except Exception as e:
        fail(f"Embed failed: {e}")
        out_path = None

    # ── 8. Summary ──
    print()
    header("Summary")
    print(f"  Token:     {C.BOLD}{token}{C.RESET}")
    print(f"  Label:     {label}")
    print(f"  Expires:   {expires_display}")
    print(f"  Max uses:  {uses_display}")
    print(f"  KV key:    {key}")
    if out_path:
        print(f"  Image:     {out_path}")
    print()
    print(f"  {C.GREEN}{C.BOLD}Share the stego image with your friend.{C.RESET}")
    print(f"  {C.DIM}They can extract the token from the image using:{C.RESET}")
    print(f"  {C.DIM}  python3 token_img.py extract <image>{C.RESET}")
    print()

    # Save token to a text file too
    tok_file = _stego_dir() / f"{safe_label}_{time.strftime('%Y%m%d_%H%M%S')}.token"
    tok_file.write_text(f"Token: {token}\nLabel: {label}\nExpires: {expires_display}\nMax uses: {uses_display}\n")
    print(f"  {C.DIM}Token info saved: {tok_file}{C.RESET}")
    print()


def show_config():
    cfg = _load_config()
    print(f"\n  {C.DIM}Config: {_CONFIG_PATH}{C.RESET}")
    for k, v in cfg.items():
        print(f"    {k}: {v}")
    print()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Generate tokens with stego images")
    p.add_argument("--config", action="store_true", help="Show current config and exit")
    p.add_argument("--pool", help="Override pool directory for this session")
    p.add_argument("--templates", help="Override templates directory for this session")
    p.add_argument("--stego-output", help="Override stego output directory for this session")
    a = p.parse_args()
    if a.config:
        show_config()
        sys.exit(0)
    if a.pool:
        _load_config()["pool_dir"] = a.pool
    if a.templates:
        _load_config()["templates_dir"] = a.templates
    if a.stego_output:
        _load_config()["stego_output_dir"] = a.stego_output
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}Cancelled.{C.RESET}")
        sys.exit(0)
