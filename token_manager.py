#!/usr/bin/env python3
"""token_manager.py — manage access tokens in Cloudflare Workers KV.

Uses the Cloudflare API directly (no wrangler needed for token ops).
Requires: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID env vars, or
          --api-token and --account-id flags.

Commands:
  generate     Create a new token and store it in KV
  list         List all stored tokens
  revoke       Delete a token from KV
  cleanup      Remove expired tokens
  push         Push a list of tokens from a file
"""
import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError


# ── Config ──

API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_DURATION = 30 * 86400  # 30 days


def _get_env():
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    ns_id = os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
    return token, account, ns_id


def _headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _cf_get(token, path):
    req = Request(f"{API_BASE}{path}", headers=_headers(token))
    with urlopen(req) as r:
        return json.loads(r.read())


def _cf_put(token, path, data):
    body = json.dumps(data).encode()
    req = Request(f"{API_BASE}{path}", data=body, headers=_headers(token), method="PUT")
    with urlopen(req) as r:
        return json.loads(r.read())


def _cf_post(token, path, data):
    body = json.dumps(data).encode()
    req = Request(f"{API_BASE}{path}", data=body, headers=_headers(token), method="POST")
    with urlopen(req) as r:
        return json.loads(r.read())


def _cf_delete(token, path):
    req = Request(f"{API_BASE}{path}", headers=_headers(token), method="DELETE")
    with urlopen(req) as r:
        return json.loads(r.read())


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _generate_token(length=32):
    raw = secrets.token_bytes(length)
    return "opc_" + hashlib.blake2s(raw, digest_size=20).hexdigest()[:24]


def _parse_duration(s):
    s = s.strip().lower()
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


# ── Commands ──

def cmd_generate(args):
    api_token, account_id, ns_id = _resolve_args(args)
    token = args.token or _generate_token()
    label = args.label or "unnamed"
    now = int(time.time())
    expires = args.expires or (now + _parse_duration(args.duration))
    entry = {
        "label": label,
        "created": now,
        "expires": expires,
        "last_used": None,
    }
    key = f"tok_{_token_hash(token)}"
    _cf_put(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}", json.dumps(entry))
    print(f"Token:     {token}")
    print(f"Label:     {label}")
    print(f"Created:   {_fmt_ts(now)}")
    print(f"Expires:   {_fmt_ts(expires)}")
    print(f"KV Key:    {key}")
    return token


def cmd_list(args):
    api_token, account_id, ns_id = _resolve_args(args)
    # KV list API is paginated
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
            if key.startswith("tok_"):
                # Fetch value
                val_path = f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}"
                try:
                    val_req = Request(f"{API_BASE}{val_path}", headers=_headers(api_token))
                    with urlopen(val_req) as vr:
                        val_data = json.loads(vr.read())
                    tokens.append((key, val_data))
                except Exception as e:
                    print(f"  {key}: error reading: {e}", file=sys.stderr)
        cursor = resp.get("result_info", {}).get("cursor")
        if not cursor:
            break
    if not tokens:
        print("No tokens found.")
        return
    now = time.time()
    print(f"{'Key':<48} {'Label':<20} {'Created':<18} {'Expires':<18} {'Status':<10}")
    print("-" * 120)
    for key, val in tokens:
        label = val.get("label", "")
        created = _fmt_ts(val.get("created"))
        expires = _fmt_ts(val.get("expires"))
        expires_ts = val.get("expires")
        if expires_ts and now > expires_ts:
            status = "EXPIRED"
        else:
            status = "active"
        print(f"{key:<48} {label:<20} {created:<18} {expires:<18} {status:<10}")
    print(f"\nTotal: {len(tokens)} tokens")


def cmd_revoke(args):
    api_token, account_id, ns_id = _resolve_args(args)
    token = args.token
    key = args.key
    if not key:
        key = f"tok_{_token_hash(token)}"
    try:
        _cf_delete(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}")
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
            if key.startswith("tok_"):
                val_path = f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}"
                try:
                    val_req = Request(f"{API_BASE}{val_path}", headers=_headers(api_token))
                    with urlopen(val_req) as vr:
                        val_data = json.loads(vr.read())
                    expires = val_data.get("expires")
                    if expires and now > expires:
                        _cf_delete(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}")
                        print(f"  Removed: {key} ({val_data.get('label', '')})")
                        removed += 1
                except Exception:
                    pass
        cursor = resp.get("result_info", {}).get("cursor")
        if not cursor:
            break
    print(f"✓ Cleanup done. {removed} expired tokens removed.")


def cmd_push(args):
    """Push tokens from a file (one per line, format: token label)."""
    api_token, account_id, ns_id = _resolve_args(args)
    now = int(time.time())
    default_duration = _parse_duration(args.duration)
    added = 0
    with open(args.file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            token = parts[0]
            label = parts[1] if len(parts) > 1 else ""
            entry = {
                "label": label,
                "created": now,
                "expires": now + default_duration,
                "last_used": None,
            }
            key = f"tok_{_token_hash(token)}"
            _cf_put(api_token, f"/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}", json.dumps(entry))
            print(f"  + {key} ({label or token[:16]}...)")
            added += 1
    print(f"✓ {added} tokens pushed to KV.")


def _resolve_args(args):
    api_token = args.api_token or os.environ.get("CLOUDFLARE_API_TOKEN", "")
    account_id = args.account_id or os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    ns_id = args.namespace or os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
    if not api_token:
        print("Error: CLOUDFLARE_API_TOKEN required (env or --api-token)", file=sys.stderr)
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
    sub = p.add_subparsers(dest="cmd", required=True)

    pg = sub.add_parser("generate", help="Create a new token")
    pg.add_argument("--token", help="Token value (auto-generated if omitted)")
    pg.add_argument("--label", "-l", default="unnamed", help="Label for the token")
    pg.add_argument("--duration", "-d", default="30d", help="Validity duration (e.g. 7d, 24h, 30d)")
    pg.add_argument("--expires", type=int, help="Expiry Unix timestamp (overrides --duration)")

    pl = sub.add_parser("list", help="List all tokens")

    pr = sub.add_parser("revoke", help="Revoke/delete a token")
    pr.add_argument("--token", help="Token value (or --key)")
    pr.add_argument("--key", help="KV key (tok_<hash>)")

    pc = sub.add_parser("cleanup", help="Remove expired tokens")

    pp = sub.add_parser("push", help="Push tokens from a file")
    pp.add_argument("file", help="File with one token per line (token [label])")
    pp.add_argument("--duration", "-d", default="30d", help="Default duration")

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
