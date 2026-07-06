#!/usr/bin/env bash
set -euo pipefail

# ── deploy.sh — Full setup: GitHub repo, Cloudflare KV, Worker deploy ──
# Usage: bash deploy.sh
# Prerequisites:
#   1. Create repo at https://github.com/new → name: opencode-site
#   2. Set these env vars or edit the values below:
#      CLOUDFLARE_API_TOKEN
#      CLOUDFLARE_ACCOUNT_ID
#      GITHUB_TOKEN (classic PAT with repo scope)

echo "=== OpenCode Site Deploy ==="

CF_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CF_ACCOUNT="${CLOUDFLARE_ACCOUNT_ID:-}"
GH_TOKEN="${GITHUB_TOKEN:-}"
GH_USER="FoxySheila"
REPO="opencode-site"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Check prerequisites ──
if ! command -v wrangler &>/dev/null; then
    echo "Installing wrangler..."
    npm install -g wrangler
fi

if ! command -v git &>/dev/null; then
    echo "Error: git not installed"
    exit 1
fi

# ── 1. GitHub: create repo + push ──
if [ -n "$GH_TOKEN" ]; then
    echo ""
    echo "--- GitHub: Creating repo ---"
    RESP=$(curl -s -H "Authorization: token $GH_TOKEN" \
                -H "Accept: application/vnd.github.v3+json" \
                https://api.github.com/user/repos \
                -d "{\"name\":\"$REPO\",\"description\":\"Token-gated opencode landing page\",\"private\":false}" 2>&1)
    if echo "$RESP" | grep -q '"full_name"'; then
        echo "✓ Repo created"
    elif echo "$RESP" | grep -q "already exists"; then
        echo "ℹ Repo already exists"
    else
        echo "⚠ Could not create repo: $RESP"
        echo "  Create it manually at https://github.com/new → name: opencode-site"
    fi
else
    echo ""
    echo "--- GitHub ---"
    echo "Create repo at: https://github.com/new"
    echo "  Repository name: opencode-site"
    echo "  Description: Token-gated opencode landing page"
    echo "  Visibility: Public"
    echo "  Do NOT initialize with README"
    echo ""
    read -p "Press Enter after creating the repo..."
fi

# Push code
echo ""
echo "--- GitHub: Pushing code ---"
cd "$PROJECT_DIR"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$GH_USER/$REPO.git"
git push -u origin master 2>&1 || echo "⚠ Push failed — you may need to: git push -u origin master"

# Enable GitHub Pages
if [ -n "$GH_TOKEN" ]; then
    echo ""
    echo "--- GitHub: Enabling Pages ---"
    # Pages requires the site/ directory, but our site is served by the Worker
    # We just enable it for the repo metadata
    curl -s -X POST -H "Authorization: token $GH_TOKEN" \
         -H "Accept: application/vnd.github.v3+json" \
         "https://api.github.com/repos/$GH_USER/$REPO/pages" \
         -d '{"source":{"branch":"master","path":"/"}}' 2>&1 | head -1
fi

# ── 2. Cloudflare KV ──
echo ""
echo "--- Cloudflare: Creating KV namespace ---"
if [ -n "$CF_TOKEN" ] && [ -n "$CF_ACCOUNT" ]; then
    KV_RESP=$(curl -s -X POST \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT/storage/kv/namespaces" \
        -d '{"title":"opencode-tokens"}')
    KV_ID=$(echo "$KV_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('id',''))" 2>/dev/null || echo "")
    if [ -n "$KV_ID" ]; then
        echo "✓ KV namespace created: $KV_ID"
        # Update wrangler.toml
        sed -i "s/id = \"\"/id = \"$KV_ID\"/" wrangler.toml
        echo "  Updated wrangler.toml"
    else
        echo "⚠ Could not create KV namespace: $KV_RESP"
        echo "  Create manually: wrangler kv namespace create opencode-tokens"
        echo "  Then update id in wrangler.toml"
    fi
else
    echo "Run: wrangler kv namespace create opencode-tokens"
    echo "Then paste the returned ID into wrangler.toml"
    read -p "Press Enter after setting up KV namespace..."
fi

# ── 3. Set SESSION_SECRET ──
echo ""
echo "--- Cloudflare: Setting SESSION_SECRET ---"
SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" 2>/dev/null || openssl rand -hex 32)
wrangler secret put SESSION_SECRET <<< "$SECRET" 2>&1 || {
    echo "Manual: wrangler secret put SESSION_SECRET"
    echo "  Value: $SECRET"
}

# ── 4. Deploy Worker ──
echo ""
echo "--- Cloudflare: Deploying Worker ---"
wrangler deploy 2>&1 || echo "⚠ Deploy failed — run: wrangler deploy"

echo ""
echo "=== Done! ==="
echo ""
echo "Next steps:"
echo "  1. Set env vars for token_manager.py:"
echo "     export CLOUDFLARE_API_TOKEN=your_token"
echo "     export CLOUDFLARE_ACCOUNT_ID=$CF_ACCOUNT"
echo "     export CLOUDFLARE_KV_NAMESPACE=$KV_ID"
echo ""
echo "  2. Generate your first token and embed it:"
echo "     python3 token_manager.py generate --label admin"
echo "     python3 token_img.py embed some_image.png <token> admin_stego.png"
echo ""
echo "  3. Share the URL + stego image with friends"
