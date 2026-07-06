# OpenCode — Private Access Site

Token-gated landing page for [OpenCode](https://opencode.ai).
Access tokens hidden in images via LSB steganography.
Powered by Cloudflare Workers + KV.

## Architecture

```
Friend → opencode-site.<your-subdomain>.workers.dev
           └─> Cloudflare Worker
                 ├─> No valid session → login page (token required)
                 └─> Valid session → opencode info page
```

- **dashboard.py** — TUI dashboard: browse images, manage tokens, generate+embed
- **worker.js** — Cloudflare Worker: auth gate + HTML inline
- **token_manager.py** — CLI to create/revoke tokens in KV
- **token_img.py** — embed/extract tokens in images via steganography
- **stego/** — Star Collapser's LSB steganography engine (3 bits/pixel RGB)
- **pool/** — Drop source images here (the dashboard loads from this folder)
- **templates/** — Bundled default images
- **stego_output/** — Generated stego PNGs land here (auto-created)

## Quick Start: Dashboard

```bash
# Activate venv (needs textual, blessed)
source ~/.local/venvs/crystal/bin/activate

# Set Cloudflare credentials (for KV operations)
export CLOUDFLARE_API_TOKEN="your-token"
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
export CLOUDFLARE_KV_NAMESPACE="your-kv-namespace-id"

# Launch TUI
python3 dashboard.py
```

The dashboard lets you:
- Browse template images in `templates/` or browse the filesystem
- See all tokens with their status
- Generate a token + embed it into an image in one click
- Revoke tokens
- Open the stego output folder

## Setup

### 1. Deploy Cloudflare Worker

```bash
npm install -g wrangler
wrangler login
wrangler kv namespace create opencode-tokens
# → copy the returned namespace ID
```

Edit `wrangler.toml`: paste the KV namespace ID.

```bash
# Generate a random SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Set secrets
wrangler secret put SESSION_SECRET

# Deploy
wrangler deploy
```

### 2. Configure token_manager.py

```bash
export CLOUDFLARE_API_TOKEN="your-api-token"
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
export CLOUDFLARE_KV_NAMESPACE="your-kv-namespace-id"
```

### 3. Generate your first token

```bash
# Generate token + store in KV
python3 token_manager.py generate --label admin

# Embed it into an image
python3 token_img.py embed logo.png <token> admin_stego.png
```

### 4. Give access to friends

```bash
# One-step: generate token + embed into image
python3 token_img.py generate --label alice --duration 30d photo.png alice_stego.png

# Send alice_stego.png to Alice
# Alice runs: python3 token_img.py extract alice_stego.png
# Alice visits the workers.dev URL, enters the token
```

## Usage

### token_img.py

```bash
# Embed an existing token
python3 token_img.py embed input.png tok_abc123 output.png

# Extract token from an image
python3 token_img.py extract stego.png

# Show all embedded payloads
python3 token_img.py extract stego.png --verbose

# Generate + embed in one step
python3 token_img.py generate --label bob --duration 7d photo.png bob_stego.png

# Batch embed
python3 token_img.py batch tokens.txt "photos/*.png" stego_output/
```

### token_manager.py

```bash
# Create a token
python3 token_manager.py generate --label alice --duration 30d

# List all tokens
python3 token_manager.py list

# Revoke a token
python3 token_manager.py revoke --token tok_abc123

# Clean up expired tokens
python3 token_manager.py cleanup

# Push tokens from a file
python3 token_manager.py push tokens.txt --duration 7d
```

## Files

| File | Purpose |
|------|---------|
| `dashboard.py` | TUI dashboard: browse images, manage tokens, generate+embed |
| `worker.js` | Cloudflare Worker (auth + site content) |
| `token_manager.py` | CLI: CRUD tokens in Cloudflare Workers KV |
| `token_img.py` | CLI: embed/extract/generate tokens in images via LSB stego |
| `stego/__init__.py` | Embed/extract payloads via LSB (TLV/CRUN format) |
| `stego/lsb.py` | LSB primitives (3 bits/pixel RGB, SHA256 integrity) |
| `templates/` | Drop source images here for the dashboard |
| `bin/checksum/quichash/quichash` | BLAKE3 hashing (bundled from Star Collapser) |
| `bin/age/age` | Age encryption (bundled from Star Collapser) |
| `site.agepub` | Site's age public key (for encrypting KV values) |
| `site.agekey` | ⚠ Private key — **do not commit**, keep secure |

## Credits

Stego engine ported from [Star Collapser](https://github.com/anomalyco/starcollapser).
BLAKE3 via quichash, encryption via age.
