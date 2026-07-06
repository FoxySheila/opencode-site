#!/usr/bin/env python3
"""dashboard.py — TUI dashboard for token management and stego image embedding.
Requires: textual, rich (pip install textual rich)

Usage:  python3 dashboard.py
Keys:   Tab/arrows to navigate, Enter to select, q to quit
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import ClassVar

from rich.syntax import Syntax
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.css.query import NoMatches
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, DataTable, Header, Footer, Input, Label,
    ListItem, ListView, RichLog, Select, Static,
)
from textual.widgets.data_table import RowDoesNotExist

from stego import embed_all_into_png, extract_all_from_png

_PROJECT_DIR = Path(__file__).parent
_TEMPLATES_DIR = _PROJECT_DIR / "templates"
_IMAGES_DIR = _PROJECT_DIR / "images"
_STEGO_DIR = _PROJECT_DIR / "stego_output"
_BIN_DIR = _PROJECT_DIR / "bin"

# ── Helpers ──

def _blake3(data: bytes) -> str:
    qc = _BIN_DIR / "checksum" / "quichash" / "quichash"
    r = subprocess.run([str(qc), "-a", "BLAKE3"], input=data, capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"quichash: {r.stderr.decode()[:200]}")
    return r.stdout.decode().strip().split()[0]


def _age_encrypt(data: bytes) -> bytes:
    age = _BIN_DIR / "age" / "age"
    pubkey = _PROJECT_DIR / "site.agepub"
    if not pubkey.exists():
        raise RuntimeError("site.agepub not found")
    with open(pubkey) as f:
        recipient = f.read().strip()
    r = subprocess.run([str(age), "-e", "-r", recipient], input=data, capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"age encrypt: {r.stderr.decode()[:200]}")
    return r.stdout


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_ts(ts):
    if not ts:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))


def _fmt_duration(seconds: int) -> str:
    if seconds < 3600:
        return f"{seconds//60}m"
    if seconds < 86400:
        return f"{seconds//3600}h"
    return f"{seconds//86400}d"


# ── Screens ──

class GenerateScreen(ModalScreen):
    """Modal dialog to generate a new token and optionally embed it."""

    DEFAULT_CSS = """
    GenerateScreen {
        align: center middle;
    }
    #gen-box {
        width: 60;
        height: auto;
        padding: 2 3;
        background: $surface;
        border: thick $primary;
    }
    #gen-box > * {
        margin-bottom: 1;
    }
    #gen-box Input {
        width: 100%;
    }
    #gen-box Select {
        width: 100%;
    }
    .gen-buttons {
        width: 100%;
        height: 3;
        align: center middle;
    }
    .gen-buttons Button {
        margin: 0 1;
    }
    #gen-status {
        height: 3;
    }
    """

    def __init__(self, selected_image: str | None = None):
        super().__init__()
        self._selected_image = selected_image
        self._result_token = None

    def compose(self):
        with Vertical(id="gen-box"):
            yield Label("[bold]Generate New Token[/]")
            yield Label("Label (friend's name):")
            yield Input(id="gen-label", placeholder="alice", value="")
            yield Label("Duration:")
            yield Select(
                id="gen-duration",
                options=[
                    ("1 day", "1d"),
                    ("7 days", "7d"),
                    ("14 days", "14d"),
                    ("30 days (default)", "30d"),
                    ("60 days", "60d"),
                    ("90 days", "90d"),
                    ("No expiry", "never"),
                ],
                value="30d",
                prompt="Select duration",
            )
            if self._selected_image:
                yield Label(f"Image: [italic]{Path(self._selected_image).name}[/]")
                yield Label(f"       {Path(self._selected_image).parent}")
            else:
                yield Label("[yellow]No image selected — token only, no stego[/]")
            yield RichLog(id="gen-status", highlight=True, markup=True)
            with Horizontal(classes="gen-buttons"):
                yield Button("Generate & Embed", id="gen-go", variant="primary")
                yield Button("Cancel", id="gen-cancel", variant="default")

    @on(Button.Pressed, "#gen-go")
    async def on_generate(self):
        log = self.query_one("#gen-status", RichLog)
        log.clear()
        label = self.query_one("#gen-label", Input).value.strip() or "unnamed"
        duration = self.query_one("#gen-duration", Select).value
        if duration == "never":
            duration = None
        else:
            dur_map = {"1d": 86400, "7d": 604800, "14d": 1209600, "30d": 2592000,
                       "60d": 5184000, "90d": 7776000}
            duration = dur_map.get(duration, 2592000)

        log.write("[cyan]Generating token...[/]")
        try:
            import secrets
            raw = secrets.token_bytes(32)
            token = "opc_" + _blake3(raw)[:24]
            log.write(f"[green]Token:[/] {token}")
        except Exception as e:
            log.write(f"[red]Error: {e}[/]")
            return

        log.write("[cyan]Age-encrypting metadata...[/]")
        now = int(time.time())
        expires = now + duration if duration else None
        meta = {"label": label, "created": now, "expires": expires, "last_used": None}
        try:
            encrypted = _age_encrypt(json.dumps(meta).encode())
            log.write(f"[green]Encrypted:[/] {len(encrypted)} bytes")
        except Exception as e:
            log.write(f"[red]Age encrypt failed: {e}[/]")
            return

        log.write("[cyan]Storing in KV...[/]")
        import hashlib
        from urllib.request import Request, urlopen
        api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
        account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
        ns_id = os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
        if api_token and account_id and ns_id:
            key = f"tok_{hashlib.sha256(token.encode()).hexdigest()}"
            path = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}"
            if expires:
                path += f"?expiration={expires}"
            req = Request(path, data=encrypted, headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/octet-stream",
            }, method="PUT")
            try:
                with urlopen(req) as r:
                    resp = json.loads(r.read())
                if resp.get("success"):
                    log.write(f"[green]✓ Stored in KV[/]")
                else:
                    log.write(f"[red]KV error: {resp.get('errors')}[/]")
            except Exception as e:
                log.write(f"[red]KV write failed: {e}[/]")
        else:
            log.write("[yellow]CLOUDFLARE_API_TOKEN/ACCOUNT_ID/KV_NAMESPACE not set — skipped KV[/]")
            log.write("[yellow]Token still usable via token_manager.py push later[/]")

        # Embed into image if selected
        if self._selected_image and os.path.isfile(self._selected_image):
            log.write(f"[cyan]Embedding into {Path(self._selected_image).name}...[/]")
            out_dir = _STEGO_DIR
            out_dir.mkdir(parents=True, exist_ok=True)
            safe_label = "".join(c if c.isalnum() else "_" for c in label)
            out_name = f"{safe_label}_{time.strftime('%Y%m%d_%H%M%S')}.png"
            out_path = str(out_dir / out_name)
            try:
                payloads = {".token": token.encode(), ".label": label.encode()}
                embed_all_into_png(self._selected_image, payloads, out_path)
                sz = os.path.getsize(out_path)
                log.write(f"[green]✓ Saved:[/] {out_path} ({_fmt_size(sz)})")
            except Exception as e:
                log.write(f"[red]Embed failed: {e}[/]")
        else:
            out_path = None

        log.write("")
        log.write(f"[bold green]Success![/] Token: [bold]{token}[/]")
        if out_path:
            log.write(f"Stego image: [bold]{out_path}[/]")
        self._result_token = (token, out_path)

    @on(Button.Pressed, "#gen-cancel")
    def on_cancel(self):
        self.dismiss(None)

    def on_mount(self):
        self.query_one("#gen-label", Input).focus()


class BrowseScreen(ModalScreen):
    """Modal screen to browse the filesystem for images."""

    DEFAULT_CSS = """
    BrowseScreen {
        align: center middle;
    }
    #browse-box {
        width: 70;
        height: 70%;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    #browse-path {
        width: 100%;
        height: 3;
    }
    #browse-list {
        width: 100%;
        height: 1fr;
    }
    .browse-buttons {
        width: 100%;
        height: 3;
        align: center middle;
    }
    .browse-buttons Button {
        margin: 0 1;
    }
    """

    def __init__(self, start_dir: str = ""):
        super().__init__()
        self._start_dir = start_dir or str(_TEMPLATES_DIR)
        self._selected = None

    def compose(self):
        with Vertical(id="browse-box"):
            yield Label("[bold]Browse for Image[/]")
            yield Input(id="browse-path", value=self._start_dir, placeholder="Directory path")
            yield ListView(id="browse-list")
            with Horizontal(classes="browse-buttons"):
                yield Button("Select", id="browse-select", variant="primary")
                yield Button("Go Up", id="browse-up")
                yield Button("Cancel", id="browse-cancel", variant="default")

    def on_mount(self):
        self._load_dir(self._start_dir)

    @on(Input.Submitted, "#browse-path")
    def on_path_submit(self):
        self._load_dir(self.query_one("#browse-path", Input).value)

    @on(Button.Pressed, "#browse-up")
    def on_go_up(self):
        current = Path(self.query_one("#browse-path", Input).value)
        parent = str(current.parent) if current.parent != current else "/"
        self.query_one("#browse-path", Input).value = parent
        self._load_dir(parent)

    @on(Button.Pressed, "#browse-select")
    def on_select(self):
        lv = self.query_one("#browse-list", ListView)
        if lv.index is not None and lv.index >= 0:
            item = lv.children[lv.index]
            if hasattr(item, '_path') and item._path:
                path = item._path
                ext = os.path.splitext(path)[1].lower()
                if ext in ('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'):
                    self._selected = path
                    self.dismiss(path)
                    return
                if os.path.isdir(path):
                    self.query_one("#browse-path", Input).value = path
                    self._load_dir(path)
                    return

    def _load_dir(self, dir_path):
        lv = self.query_one("#browse-list", ListView)
        lv.clear()
        try:
            entries = sorted(Path(dir_path).iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            self.query_one("#browse-path", Input).value = str(Path(dir_path).parent)
            return
        self.query_one("#browse-path", Input).value = str(dir_path)
        img_exts = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp', '.tiff'}
        for e in entries:
            ext = e.suffix.lower()
            if e.is_dir():
                item = ListItem(Label(f"📁  {e.name}/"), _path=str(e))
                lv.append(item)
            elif ext in img_exts:
                sz = _fmt_size(e.stat().st_size)
                item = ListItem(Label(f"🖼  {e.name}  ({sz})"), _path=str(e))
                lv.append(item)

    @on(Button.Pressed, "#browse-cancel")
    def on_cancel(self):
        self.dismiss(None)


# ── Main App ──

class TokenApp(App):
    """OpenCode Token Manager Dashboard."""

    CSS = """
    Screen {
        background: $surface;
    }
    #main-layout {
        height: 100%;
        padding: 0 1;
    }
    #top-bar {
        height: 3;
        dock: top;
        background: $primary-background;
    }
    #top-bar > * {
        height: 100%;
    }
    #token-section {
        height: 40%;
        border: solid $primary;
        margin-bottom: 1;
    }
    #token-section Header {
        background: $primary-background;
        text-style: bold;
    }
    #token-table {
        height: 1fr;
    }
    #token-actions {
        height: 4;
        align: center middle;
    }
    #token-actions Button {
        margin: 0 1;
    }
    #image-section {
        height: 1fr;
        border: solid $primary;
        margin-bottom: 1;
    }
    #image-section Header {
        background: $primary-background;
        text-style: bold;
    }
    #image-area {
        height: 1fr;
    }
    #image-list {
        width: 40%;
        height: 100%;
    }
    #image-preview {
        width: 60%;
        height: 100%;
        padding: 0 1;
    }
    #image-actions {
        height: 4;
        dock: bottom;
        align: center middle;
    }
    #image-actions Button {
        margin: 0 1;
    }
    #status-bar {
        height: 2;
        dock: bottom;
        background: $boost;
        padding: 0 1;
    }
    #stego-dir-hint {
        height: 3;
        padding: 0 1;
        background: $surface;
        border: dashed $primary;
    }
    """

    BINDINGS: ClassVar = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh", "Refresh"),
        Binding("g", "generate", "Generate"),
    ]

    def __init__(self):
        super().__init__()
        self._tokens = []
        self._images = []
        self._selected_image = None
        _STEGO_DIR.mkdir(parents=True, exist_ok=True)
        _TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    def compose(self):
        yield Header(show_clock=True)
        with Vertical(id="main-layout"):
            # Token section
            with Vertical(id="token-section"):
                yield Label("Access Tokens", id="token-header")
                yield DataTable(id="token-table", cursor_type="row")
                with Horizontal(id="token-actions"):
                    yield Button(" Generate Token ", id="btn-gen", variant="primary")
                    yield Button(" Revoke ", id="btn-revoke", variant="error")
                    yield Button(" Refresh ", id="btn-refresh")

            # Image section
            with Vertical(id="image-section"):
                yield Label("Template Images", id="image-header")
                with Horizontal(id="image-area"):
                    yield ListView(id="image-list")
                    with Vertical(id="image-preview"):
                        yield Label("[dim]Select an image to preview[/]", id="preview-label")
                        yield Label("", id="preview-details")
                with Horizontal(id="image-actions"):
                    yield Button(" Browse... ", id="btn-browse")
                    yield Button(" Generate & Embed ", id="btn-genembed", variant="primary")
                    yield Button(" Open Output Folder ", id="btn-open-out")

            yield Static(
                f"Stego output: [bold]{_STEGO_DIR}[/]",
                id="stego-dir-hint",
            )

        yield RichLog(id="status-bar", highlight=True, markup=True, max_lines=3)

    def on_mount(self):
        table = self.query_one("#token-table", DataTable)
        table.add_columns("Label", "Created", "Expires", "Status", "KV Key")
        self.refresh_tokens()
        self.refresh_images()

    # ── Token actions ──

    @work(thread=True)
    def refresh_tokens(self):
        self.call_from_thread(self._do_refresh_tokens)

    def _do_refresh_tokens(self):
        log = self.query_one("#status-bar", RichLog)
        log.write("[dim]Refreshing tokens...[/]")
        api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
        account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
        ns_id = os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
        if not (api_token and account_id and ns_id):
            log.write("[yellow]Set CLOUDFLARE_API_TOKEN, ACCOUNT_ID, KV_NAMESPACE to see tokens[/]")
            return

        import urllib.request
        import hashlib

        table = self.query_one("#token-table", DataTable)
        table.clear()
        now = time.time()
        cursor = None
        count = 0

        while True:
            path = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}/keys"
            if cursor:
                path += f"?cursor={cursor}"
            req = urllib.request.Request(path, headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            })
            try:
                with urllib.request.urlopen(req) as r:
                    resp = json.loads(r.read())
            except Exception as e:
                log.write(f"[red]KV list error: {e}[/]")
                break
            if not resp.get("success"):
                break

            for key_info in resp.get("result", []):
                key = key_info["name"]
                if not key.startswith("tok_"):
                    continue
                val_path = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{key}"
                val_req = urllib.request.Request(val_path, headers={
                    "Authorization": f"Bearer {api_token}",
                })
                try:
                    with urllib.request.urlopen(val_req) as vr:
                        raw = vr.read()
                    # Decrypt with age
                    age = _BIN_DIR / "age" / "age"
                    agekey = _PROJECT_DIR / "site.agekey"
                    if agekey.exists():
                        r2 = subprocess.run([str(age), "-d", "-i", str(agekey)],
                                            input=raw, capture_output=True, timeout=30)
                        if r2.returncode == 0:
                            val_data = json.loads(r2.stdout)
                        else:
                            val_data = {"label": f"<age decrypt error>", "created": 0, "expires": 0}
                    else:
                        val_data = {"label": "<site.agekey missing>", "created": 0, "expires": 0}
                except Exception:
                    val_data = {"label": "<read error>", "created": 0, "expires": 0}

                label = val_data.get("label", "")
                created = _fmt_ts(val_data.get("created"))
                expires = val_data.get("expires")
                expires_str = _fmt_ts(expires)
                status = "✓" if (not expires or now < expires) else "✗ EXPIRED"
                table.add_row(label, created, expires_str, status, key[:20]+"...")
                count += 1

            cursor = resp.get("result_info", {}).get("cursor")
            if not cursor:
                break

        log.write(f"[green]✓[/] [bold]{count}[/] tokens loaded")

    @on(Button.Pressed, "#btn-refresh")
    def on_refresh(self):
        self.refresh_tokens()
        self.refresh_images()

    @on(Button.Pressed, "#btn-gen")
    def on_generate(self):
        self.push_screen(GenerateScreen(self._selected_image),
                         callback=self._on_generate_done)

    def _on_generate_done(self, result):
        if result:
            self.refresh_tokens()
            self.refresh_images()

    @on(Button.Pressed, "#btn-revoke")
    def on_revoke(self):
        table = self.query_one("#token-table", DataTable)
        if table.cursor_row is None:
            self.query_one("#status-bar", RichLog).write("[yellow]Select a token first[/]")
            return
        try:
            row_key = table.get_row_at(table.cursor_row)
        except RowDoesNotExist:
            return
        # KV key is last column (truncated to 20 chars)
        full_key_display = row_key[-1] if row_key else ""
        if not full_key_display:
            return
        # We need the full key — store it from the refresh
        self._revoke_token(full_key_display)

    @work(thread=True)
    def _revoke_token(self, key_display):
        api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
        account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
        ns_id = os.environ.get("CLOUDFLARE_KV_NAMESPACE", "")
        if not (api_token and account_id and ns_id):
            return
        log = self.query_one("#status-bar", RichLog)
        # We need the full key, so list and match
        import urllib.request, urllib.error
        cursor = None
        found = None
        while True:
            path = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}/keys"
            if cursor:
                path += f"?cursor={cursor}"
            req = urllib.request.Request(path, headers={"Authorization": f"Bearer {api_token}"})
            try:
                with urllib.request.urlopen(req) as r:
                    resp = json.loads(r.read())
            except Exception:
                break
            for ki in resp.get("result", []):
                if ki["name"].startswith("tok_") and ki["name"][:len(key_display)] == key_display:
                    found = ki["name"]
                    break
            if found:
                break
            cursor = resp.get("result_info", {}).get("cursor")
            if not cursor:
                break
        if not found:
            log.write(f"[red]Could not find full key for {key_display}[/]")
            return
        del_path = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values/{found}"
        del_req = urllib.request.Request(del_path, headers={"Authorization": f"Bearer {api_token}"}, method="DELETE")
        try:
            with urllib.request.urlopen(del_req):
                log.write(f"[green]✓ Revoked: {found[:24]}...[/]")
        except Exception as e:
            log.write(f"[red]Revoke failed: {e}[/]")
        self.refresh_tokens()

    # ── Image actions ──

    def refresh_images(self):
        lv = self.query_one("#image-list", ListView)
        lv.clear()
        self._images = []
        sources = [_TEMPLATES_DIR]
        if _IMAGES_DIR.exists():
            sources.append(_IMAGES_DIR)
        img_exts = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'}
        seen = set()
        for src_dir in sources:
            if not src_dir.exists():
                continue
            for f in sorted(src_dir.iterdir(), key=lambda p: p.name.lower()):
                if f.suffix.lower() in img_exts and f.name not in seen:
                    seen.add(f.name)
                    self._images.append(str(f))
                    sz = _fmt_size(f.stat().st_size)
                    item = ListItem(Label(f"  {f.name}  ({sz})"), _path=str(f))
                    lv.append(item)
        if not self._images:
            lv.append(ListItem(Label("  [dim](drop images in templates/ folder)[/]", _path="")))

    @on(ListView.Selected, "#image-list")
    def on_image_selected(self, event):
        item = event.item
        path = getattr(item, '_path', "")
        if path and os.path.isfile(path):
            self._selected_image = path
            name = Path(path).name
            sz = os.path.getsize(path)
            preview = self.query_one("#preview-label", Label)
            details = self.query_one("#preview-details", Label)
            preview.update(f"[bold]{name}[/]")
            try:
                from PIL import Image
                with Image.open(path) as img:
                    w, h = img.size
                    details.update(
                        f"Size: {w}×{h} px\n"
                        f"File: {_fmt_size(sz)}\n"
                        f"Path: {path}\n"
                        f"Capacity: ~{_fmt_size(w * h * 3 // 8)} payload"
                    )
            except Exception:
                details.update(f"File: {_fmt_size(sz)}\nPath: {path}\n")
        else:
            self._selected_image = None

    @on(Button.Pressed, "#btn-genembed")
    def on_genembed(self):
        if not self._selected_image:
            self.query_one("#status-bar", RichLog).write("[yellow]Select a template image first[/]")
            return
        self.push_screen(GenerateScreen(self._selected_image),
                         callback=self._on_generate_done)

    @on(Button.Pressed, "#btn-browse")
    def on_browse(self):
        start = self._selected_image or str(_TEMPLATES_DIR)
        self.push_screen(BrowseScreen(start), callback=self._on_browse_done)

    def _on_browse_done(self, result):
        if result:
            self._selected_image = result
            # Add to templates for future use
            dst = _TEMPLATES_DIR / Path(result).name
            if not dst.exists():
                try:
                    shutil.copy2(result, dst)
                except Exception:
                    pass
            self.refresh_images()
            # Select it
            lv = self.query_one("#image-list", ListView)
            for i, child in enumerate(lv.children):
                if getattr(child, '_path', '') == result:
                    lv.index = i
                    break
            name = Path(result).name
            preview = self.query_one("#preview-label", Label)
            details = self.query_one("#preview-details", Label)
            preview.update(f"[bold]{name}[/]")
            try:
                from PIL import Image
                with Image.open(result) as img:
                    w, h = img.size
                    details.update(
                        f"Size: {w}×{h} px\n"
                        f"File: {_fmt_size(os.path.getsize(result))}\n"
                        f"Path: {result}\n"
                        f"Capacity: ~{_fmt_size(w * h * 3 // 8)} payload"
                    )
            except Exception:
                details.update(f"File: {_fmt_size(os.path.getsize(result))}\nPath: {result}\n")

    @on(Button.Pressed, "#btn-open-out")
    def on_open_output(self):
        path = str(_STEGO_DIR.resolve())
        try:
            import subprocess
            subprocess.Popen(["xdg-open", path])
        except Exception:
            self.query_one("#status-bar", RichLog).write(f"[dim]Output: {path}[/]")

    # ── Action bindings ──

    def action_generate(self):
        self.on_generate()

    def action_refresh(self):
        self.on_refresh()


# ── Entry ──

if __name__ == "__main__":
    app = TokenApp()
    app.run()
