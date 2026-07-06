#!/usr/bin/env python3
"""token_manager.py — manage access tokens in Cloudflare Workers KV.
Tokens: BLAKE3 hashed (via quichash binary), age-encrypted at rest.
Uses the Cloudflare API directly (no wrangler needed for token ops).
Requires: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID env vars, or
          --api-token and --account-id flags.

Commands:
  generate     Create a new token, age-encrypt it, store in KV
  list         List all stored tokens (decrypts age payloads)
  revoke       Delete a token from KV
  cleanup      Remove expired tokens (KV TTL does this, but for safety)
  push         Push a list of tokens from a file
"""
import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import http.cookiejar
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
from urllib.error import HTTPError


# ── Paths ──

_BIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
_QUICHASH = os.path.join(_BIN_DIR, "checksum", "quichash", "quichash")
_AGE = os.path.join(_BIN_DIR, "age", "age")
_AGE_KEYGEN = os.path.join(_BIN_DIR, "age", "age-keygen")
_SITE_AGEKEY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site.agekey")
_SITE_AGEPUB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site.agepub")

# ── Config ──

API_BASE = "https://api.cloudflare.com/client/v4"
DASH_BASE = "https://dash.cloudflare.com/api/v4"
DEFAULT_DURATION = 30 * 86400  # 30 days

_CF_COOKIE_FILE = None  # set via --cookie-file or CF_COOKIE_FILE env


def _cf_opener():
    """Return an opener with cookie-based auth if cookie file is set."""
    if not _CF_COOKIE_FILE or not os.path.isfile(_CF_COOKIE_FILE):
        return None
    cj = http.cookiejar.MozillaCookieJar(_CF_COOKIE_FILE)
    cj.load(ignore_expires=True, ignore_discard=True)
    return build_opener(HTTPCookieProcessor(cj))


def _cf_url(path, params=None):
    """Build URL using cookie auth base if available, else standard API base."""
    base = DASH_BASE if _CF_COOKIE_FILE else API_BASE
    url = f"{base}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        url += f"?{qs}"
    return url


def _get_env():
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    ns_id = os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
    return token, account, ns_id


def _headers(headers=None):
    h = {"Content-Type": "application/json"}
    if _CF_COOKIE_FILE:
        h["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        h["Referer"] = "https://dash.cloudflare.com/"
    if headers:
        h.update(headers)
    return h


def _cf_req(method, path, data=None, binary=False):
    """Make a CF API request using cookie auth or token auth."""
    opener = _cf_opener()
    url = _cf_url(path)
    hdrs = _headers({"Content-Type": "application/octet-stream"} if binary else None)
    body = data if isinstance(data, (bytes, type(None))) else json.dumps(data).encode()
    req = Request(url, data=body, headers=hdrs, method=method)
    opener_ctx = opener if opener else urlopen
    with opener_ctx.open(req) as r:
        return json.loads(r.read())


def _cf_get(token, path):
    return _cf_req("GET", path)


def _cf_put(token, path, data):
    return _cf_req("PUT", path, data)


def _cf_post(token, path, data):
    return _cf_req("POST", path, data)


def _cf_delete(token, path):
    return _cf_req("DELETE", path)


def _cf_put_kv(api_token, account_id, ns_id, key, value, expiration=None):
    """Store a value in KV with optional TTL (expiration = Unix timestamp)."""
    path = f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}"
    params = {}
    if expiration:
        params["expiration"] = str(int(expiration))
    body = value if isinstance(value, bytes) else json.dumps(value).encode()
    url = _cf_url(path, params or None)
    opener = _cf_opener()
    hdrs = _headers({"Content-Type": "application/octet-stream"})
    req = Request(url, data=body, headers=hdrs, method="PUT")
    opener_ctx = opener if opener else urlopen
    with opener_ctx.open(req) as r:
        return json.loads(r.read())


def _cf_get_kv_raw(api_token, account_id, ns_id, key):
    """Read a raw value from KV as bytes."""
    path = f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}"
    url = _cf_url(path)
    opener = _cf_opener()
    hdrs = _headers({"Accept": "application/octet-stream"})
    if not opener:
        hdrs["Authorization"] = f"Bearer {api_token}"
    req = Request(url, headers=hdrs, method="GET")
    opener_ctx = opener if opener else urlopen
    with opener_ctx.open(req) as r:
        return r.read()


# ── BLAKE3 via quichash ──

def _blake3(data: bytes) -> str:
    """Hash data with BLAKE3 via quichash binary. Returns hex string."""
    if not os.path.isfile(_QUICHASH):
        raise RuntimeError(f"quichash not found at {_QUICHASH}")
    r = subprocess.run([_QUICHASH, "-a", "BLAKE3"], input=data,
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"quichash failed: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode(errors='replace').strip().split()[0]


# ── Age encryption ──

def _age_pubkey() -> str:
    """Get the site's age public key."""
    if os.path.isfile(_SITE_AGEPUB):
        with open(_SITE_AGEPUB) as f:
            return f.read().strip()
    raise RuntimeError(f"site.agepub not found at {_SITE_AGEPUB}")


def _age_encrypt(data: bytes) -> bytes:
    """Encrypt data with the site's age public key."""
    pubkey = _age_pubkey()
    r = subprocess.run([_AGE, "-e", "-r", pubkey], input=data,
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"age encrypt failed: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout


def _age_decrypt(data: bytes) -> bytes:
    """Decrypt data with the site's age private key."""
    if not os.path.isfile(_SITE_AGEKEY):
        raise RuntimeError(f"site.agekey not found at {_SITE_AGEKEY}")
    r = subprocess.run([_AGE, "-d", "-i", _SITE_AGEKEY], input=data,
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"age decrypt failed: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout


# ── Helpers ──

def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _generate_token():
    raw = secrets.token_bytes(32)
    b3 = _blake3(raw)
    return "opc_" + b3[:24]


def _parse_duration(s):
    s = s.strip().lower()
    if s in ("never", "0", "none"):
        return 0
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s) * 86400


def _fmt_ts(ts):
    if ts is None:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))


def _resolve_age():
    if not os.path.isfile(_SITE_AGEKEY):
        print("No site.agekey found. Run: ./bin/age/age-keygen -o site.agekey")
        sys.exit(1)
    if not os.path.isfile(_SITE_AGEPUB):
        print("No site.agepub found. Run: ./bin/age/age-keygen -y site.agekey > site.agepub")
        sys.exit(1)


# ── Commands ──

def cmd_generate(args):
    _resolve_age()
    api_token, account_id, ns_id = _resolve_args(args)
    token = args.token or _generate_token()
    label = args.label or "unnamed"
    now = int(time.time())
    dur = _parse_duration(args.duration)
    expires = args.expires or (None if dur == 0 else now + dur)
    max_uses = args.max_uses
    meta = {
        "label": label,
        "created": now,
        "expires": expires,
        "max_uses": max_uses,
        "use_count": 0,
    }
    encrypted = _age_encrypt(json.dumps(meta).encode())
    key = f"tok_{_token_hash(token)}"
    uses_key = f"{key}:u"
    _cf_put_kv(api_token, account_id, ns_id, key, encrypted, expiration=expires if expires else None)
    # Usage counter entry (plaintext, same TTL)
    uses_data = json.dumps({"n": 0, "m": max_uses}).encode()
    _cf_put_kv(api_token, account_id, ns_id, uses_key, uses_data, expiration=expires if expires else None)
    print(f"Token:     {token}")
    print(f"Label:     {label}")
    print(f"Created:   {_fmt_ts(now)}")
    print(f"Expires:   {_fmt_ts(expires)}")
    print(f"Max uses:  {'unlimited' if max_uses == 0 else max_uses}")
    print(f"KV Key:    {key}")
    print(f"Encrypted: {len(encrypted)} bytes (age)")
    return token


def cmd_list(args):
    _resolve_age()
    api_token, account_id, ns_id = _resolve_args(args)
    cursor = None
    tokens = []
    while True:
        path = f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/keys"
        if cursor:
            path += f"?cursor={cursor}"
        resp = _cf_get(api_token, path)
        if not resp.get("success"):
            print("Error listing KV keys:", resp.get("errors"))
            return 1
        for key_info in resp.get("result", []):
            key = key_info["name"]
            if key.startswith("tok_") and not key.endswith(":u"):
                try:
                    raw = _cf_get_kv_raw(api_token, account_id, ns_id, key)
                    decrypted = _age_decrypt(raw)
                    val_data = json.loads(decrypted)
                    tokens.append((key, val_data))
                except Exception as e:
                    tokens.append((key, {"label": f"<decrypt error: {e}>", "created": 0, "expires": 0}))
        cursor = resp.get("result_info", {}).get("cursor")
        if not cursor:
            break
    if not tokens:
        print("No tokens found.")
        return
    now = time.time()
    print(f"{'Key':<48} {'Label':<18} {'Uses':<10} {'Created':<16} {'Expires':<16} {'Status':<10}")
    print("-" * 125)
    for key, val in tokens:
        label = val.get("label", "")
        created = _fmt_ts(val.get("created"))
        expires = _fmt_ts(val.get("expires"))
        expires_ts = val.get("expires")
        max_uses = val.get("max_uses", 0)
        use_count = val.get("use_count", 0)
        uses_str = f"{use_count}/{max_uses}" if max_uses else "unlimited"
        if expires_ts and now > expires_ts:
            status = "EXPIRED"
        else:
            status = "active"
        print(f"{key:<48} {label:<18} {uses_str:<10} {created:<16} {expires:<16} {status:<10}")
    print(f"\nTotal: {len(tokens)} tokens")


def cmd_revoke(args):
    api_token, account_id, ns_id = _resolve_args(args)
    token = args.token
    key = args.key
    if not key:
        key = f"tok_{_token_hash(token)}"
    uses_key = f"{key}:u"
    try:
        _cf_delete(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}")
        # Also delete usage counter
        try:
            _cf_delete(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{uses_key}")
        except HTTPError:
            pass
        print(f"✓ Token revoked: {key}")
    except HTTPError as e:
        if e.code == 404:
            print(f"Token not found: {key}")
            return 1
        raise


def cmd_cleanup(args):
    api_token, account_id, ns_id = _resolve_args(args)
    now = time.time()
    cursor = None
    removed = 0
    while True:
        path = f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/keys"
        if cursor:
            path += f"?cursor={cursor}"
        resp = _cf_get(api_token, path)
        if not resp.get("success"):
            print("Error listing KV keys:", resp.get("errors"))
            return 1
        for key_info in resp.get("result", []):
            key = key_info["name"]
            if key.startswith("tok_") and not key.endswith(":u"):
                try:
                    raw = _cf_get_kv_raw(api_token, account_id, ns_id, key)
                    decrypted = _age_decrypt(raw)
                    val_data = json.loads(decrypted)
                    expires = val_data.get("expires")
                    if expires and now > expires:
                        _cf_delete(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}")
                        try:
                            _cf_delete(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}:u")
                        except HTTPError:
                            pass
                        print(f"  Removed: {key} ({val_data.get('label', '')})")
                        removed += 1
                except Exception:
                    pass
        cursor = resp.get("result_info", {}).get("cursor")
        if not cursor:
            break
    print(f"✓ Cleanup done. {removed} expired tokens removed.")


def cmd_push(args):
    _resolve_age()
    api_token, account_id, ns_id = _resolve_args(args)
    now = int(time.time())
    default_duration = _parse_duration(args.duration)
    default_max_uses = args.max_uses
    added = 0
    with open(args.file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=2)
            token = parts[0]
            label = parts[1] if len(parts) > 1 else ""
            max_uses = int(parts[2]) if len(parts) > 2 else default_max_uses
            meta = {
                "label": label,
                "created": now,
                "expires": now + default_duration,
                "max_uses": max_uses,
                "use_count": 0,
            }
            encrypted = _age_encrypt(json.dumps(meta).encode())
            key = f"tok_{_token_hash(token)}"
            uses_key = f"{key}:u"
            _cf_put_kv(api_token, account_id, ns_id, key, encrypted,
                       expiration=now + default_duration)
            uses_data = json.dumps({"n": 0, "m": max_uses}).encode()
            _cf_put_kv(api_token, account_id, ns_id, uses_key, uses_data,
                       expiration=now + default_duration)
            uses_str = f"max={max_uses}" if max_uses else "unlimited"
            print(f"  + {key} ({label or token[:16]}...) {uses_str}")
            added += 1
    print(f"✓ {added} tokens pushed to KV.")


def _resolve_args(args):
    global _CF_COOKIE_FILE
    _CF_COOKIE_FILE = args.cookie_file or os.environ.get("CF_COOKIE_FILE", "")
    api_token = args.api_token or os.environ.get("CLOUDFLARE_API_TOKEN", "")
    account_id = args.account_id or os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    ns_id = args.namespace or os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
    if not api_token and not _CF_COOKIE_FILE:
        print("Error: need CLOUDFLARE_API_TOKEN (or --api-token), or --cookie-file / CF_COOKIE_FILE", file=sys.stderr)
        sys.exit(1)
    if not account_id:
        print("Error: CLOUDFLARE_ACCOUNT_ID required (env or --account-id)", file=sys.stderr)
        sys.exit(1)
    if not ns_id:
        print("Error: KV namespace ID required (env CLOUDFLARE_KV_NAMESPACE or --namespace)", file=sys.stderr)
        sys.exit(1)
    return api_token, account_id, ns_id


# ── Main ──

def main():
    p = argparse.ArgumentParser(description="Manage access tokens in Cloudflare Workers KV")
    p.add_argument("--api-token", help="Cloudflare API token (or CLOUDFLARE_API_TOKEN env)")
    p.add_argument("--account-id", help="Cloudflare account ID (or CLOUDFLARE_ACCOUNT_ID env)")
    p.add_argument("--namespace", "-n", help="KV namespace ID (or CLOUDFLARE_KV_NAMESPACE env)")
    p.add_argument("--cookie-file", help="Cloudflare session cookie file (Netscape format, or CF_COOKIE_FILE env)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pg = sub.add_parser("generate", help="Create a new token")
    pg.add_argument("--token", help="Token value (auto-generated if omitted)")
    pg.add_argument("--label", "-l", default="unnamed", help="Label for the token")
    pg.add_argument("--duration", "-d", default="30d", help="Validity duration (e.g. 7d, 24h, 30d)")
    pg.add_argument("--expires", type=int, help="Expiry Unix timestamp (overrides --duration)")
    pg.add_argument("--max-uses", type=int, default=0, help="Max number of uses (0 = unlimited)")

    pl = sub.add_parser("list", help="List all tokens")

    pr = sub.add_parser("revoke", help="Revoke/delete a token")
    pr.add_argument("--token", help="Token value (or --key)")
    pr.add_argument("--key", help="KV key (tok_<hash>)")

    pc = sub.add_parser("cleanup", help="Remove expired tokens")

    pp = sub.add_parser("push", help="Push tokens from a file")
    pp.add_argument("file", help="File with one token per line (token [label])")
    pp.add_argument("--duration", "-d", default="30d", help="Default duration")
    pp.add_argument("--max-uses", type=int, default=0, help="Default max uses (0=unlimited)")

    args = p.parse_args()
    if args.cmd == "generate":
        return cmd_generate(args)
    elif args.cmd == "list":
        return cmd_list(args)
    elif args.cmd == "revoke":
        return cmd_revoke(args)
    elif args.cmd == "cleanup":
        return cmd_cleanup(args)
    elif args.cmd == "push":
        return cmd_push(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
