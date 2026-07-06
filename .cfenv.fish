# OpenCode token manager env vars — Fish
# Usage:  source .cfenv.fish
set -x CLOUDFLARE_ACCOUNT_ID a6f30d8d5e0e04ee20747d91d62c232e
set -x CLOUDFLARE_KV_NAMESPACE 8753c35dccdb4222b88b115d745bd4d5
set -x CF_COOKIE_FILE /home/deadfoxy/Desktop/cookies-cloudflare-com.txt
set -x OCPATH /run/media/deadfoxy/5c368964-d580-4e28-b555-d28616198ca21/opencode-site

alias tokgen='source ~/.local/venvs/crystal/bin/activate.fish; source "$OCPATH/.cfenv.fish"; python3 "$OCPATH/token_manager.py" --cookie-file "$CF_COOKIE_FILE"'
alias dashgen='source ~/.local/venvs/crystal/bin/activate.fish; source "$OCPATH/.cfenv.fish"; python3 "$OCPATH/dashboard.py"'
