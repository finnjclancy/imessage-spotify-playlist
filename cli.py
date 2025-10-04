#!/usr/bin/env python3

import argparse
import base64
import hashlib
import http.server
import os
import re
import sqlite3
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, parse_qs, quote

import requests
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    _console = Console()
except Exception:
    RICH_AVAILABLE = False
    _console = None  # type: ignore


SPOTIFY_HOSTS = (
    "open.spotify.com",
    "spoti.fi",
    "spotify.link",
    "spotify.app.link",
)

# very forgiving url matcher for use on both plain text and decoded blobs
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _apple_time_to_datetime(seconds_or_ns: int) -> datetime:
    """
    Convert iMessage 'date' (which can be in Apple epoch, sometimes nanoseconds) to UTC datetime.
    Apple epoch starts at 2001-01-01, which is 978307200 seconds after Unix epoch.
    """
    # Newer macOS uses nanoseconds; older used seconds. Heuristic: big numbers are ns.
    if seconds_or_ns is None:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if seconds_or_ns > 10_000_000_000:  # treat as nanoseconds since Apple epoch
        seconds = seconds_or_ns / 1_000_000_000
    else:
        seconds = float(seconds_or_ns)
    unix_seconds = seconds + 978_307_200
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)


def open_db(db_path: str) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError as e:
        if "unable to open database file" in str(e):
            print(f"error: unable to open database file at '{db_path}'")
            print("\nthis tool needs access to your imessage database. try one of these solutions:")
            print("1. use the default path: --db ~/Library/Messages/chat.db")
            print("2. copy the database: cp ~/Library/Messages/chat.db ./chat.db")
            print("3. specify the correct path: --db /path/to/your/chat.db")
            print("\nnote: you may need to grant full disk access to terminal in system preferences > security & privacy")
        raise


def list_chats(conn: sqlite3.Connection, limit: int = 100) -> List[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute(
        """
        select rowid as chat_id,
               guid,
               coalesce(display_name, chat_identifier) as name
        from chat
        order by rowid desc
        limit ?
        """,
        (limit,),
    )
    return cur.fetchall()


def _normalized_chat_name(row: sqlite3.Row) -> str:
    return (row["name"] or "").strip()


def find_chats_by_name(conn: sqlite3.Connection, name_query: str) -> List[sqlite3.Row]:
    """Find chats where display_name or chat_identifier match name.
    Prefer exact case-insensitive matches, else substring matches. Newest first.
    """
    cur = conn.cursor()
    # exact matches first
    cur.execute(
        """
        select rowid as chat_id,
               guid,
               coalesce(display_name, chat_identifier) as name
        from chat
        where lower(coalesce(display_name, chat_identifier)) = lower(?)
        order by rowid desc
        """,
        (name_query,),
    )
    exact = cur.fetchall()
    if exact:
        return exact

    # fallback to contains
    cur.execute(
        """
        select rowid as chat_id,
               guid,
               coalesce(display_name, chat_identifier) as name
        from chat
        where lower(coalesce(display_name, chat_identifier)) like lower(?)
        order by rowid desc
        """,
        (f"%{name_query}%",),
    )
    return cur.fetchall()


def list_participants(conn: sqlite3.Connection, chat_id: int) -> List[str]:
    cur = conn.cursor()
    # Prefer chat_handle_join if present; otherwise derive from messages
    try:
        cur.execute(
            """
            select h.id
            from chat_handle_join chj
            join handle h on h.rowid = chj.handle_id
            where chj.chat_id = ?
            order by h.id
            """,
            (chat_id,),
        )
        rows = [r[0] for r in cur.fetchall()]
        if rows:
            return rows
    except sqlite3.OperationalError:
        pass

    cur.execute(
        """
        select distinct h.id
        from chat_message_join cmj
        join message m on m.rowid = cmj.message_id
        join handle h on h.rowid = m.handle_id
        where cmj.chat_id = ? and h.id is not null
        order by h.id
        """,
        (chat_id,),
    )
    return [r[0] for r in cur.fetchall()]


@dataclass
class FoundUrl:
    message_id: int
    timestamp: datetime
    sender: str
    raw_url: str
    expanded_url: Optional[str]
    track_id: Optional[str]


def _extract_urls_from_text(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return [m.group(0) for m in URL_RE.finditer(text)]


def _extract_urls_from_blob(blob: Optional[bytes]) -> List[str]:
    if not blob:
        return []
    try:
        decoded = blob.decode("utf-8", errors="ignore")
    except Exception:
        return []
    return [m.group(0) for m in URL_RE.finditer(decoded)]


def _is_spotify_host(url: str) -> bool:
    try:
        host = url.split("://", 1)[1].split("/", 1)[0].lower()
    except Exception:
        return False
    return any(host.endswith(h) for h in SPOTIFY_HOSTS)


def _expand_url(url: str, timeout: float = 6.0) -> str:
    try:
        # HEAD first; some link shorteners require GET for redirect, so fallback
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        final = r.url
        if final and final != url:
            return final
        # fallback GET (no body download if possible)
        r = requests.get(url, allow_redirects=True, timeout=timeout)
        return r.url or url
    except Exception:
        return url


def _extract_track_id(spotify_url: str) -> Optional[str]:
    """
    Strictly extract a spotify track id (22 base62 chars) from a URL.
    Drops malformed/rich-text artifact matches (e.g., *WHttpURL or truncated ids).
    """
    try:
        parsed = urlparse(spotify_url)
        path = parsed.path or ""
        m = re.search(r"/track/([A-Za-z0-9]{22})(?:[/?#]|$)", path)
        if not m:
            return None
        return m.group(1)
    except Exception:
        return None


def iter_chat_messages(conn: sqlite3.Connection, chat_id: int) -> Iterable[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute(
        """
        select m.rowid as message_id,
               m.date as apple_date,
               m.text as body,
               m.attributedBody as attr_body,
               h.id as sender
        from message m
        join chat_message_join cmj on cmj.message_id = m.rowid
        left join handle h on h.rowid = m.handle_id
        where cmj.chat_id = ?
        order by m.date asc, m.rowid asc
        """,
        (chat_id,),
    )
    for row in cur:
        yield row


def extract_spotify_links(conn: sqlite3.Connection, chat_id: int, expand_short_links: bool = True) -> List[FoundUrl]:
    found: List[FoundUrl] = []
    for row in iter_chat_messages(conn, chat_id):
        ts = _apple_time_to_datetime(row["apple_date"])  # UTC
        sender = row["sender"] or "me"

        urls: List[str] = []
        urls.extend(_extract_urls_from_text(row["body"]))
        urls.extend(_extract_urls_from_blob(row["attr_body"]))

        for url in urls:
            if not _is_spotify_host(url):
                continue
            expanded = _expand_url(url) if (expand_short_links and not url.startswith("http://open.spotify.com") and not url.startswith("https://open.spotify.com")) else url
            track_id = _extract_track_id(expanded)
            found.append(
                FoundUrl(
                    message_id=row["message_id"],
                    timestamp=ts,
                    sender=sender,
                    raw_url=url,
                    expanded_url=expanded,
                    track_id=track_id,
                )
            )

    return found


def dedupe_keep_first_by_track(found: Sequence[FoundUrl]) -> List[FoundUrl]:
    seen = set()
    result: List[FoundUrl] = []
    for item in found:
        if not item.track_id:
            continue  # ignore non-track links
        if item.track_id in seen:
            continue
        seen.add(item.track_id)
        result.append(item)
    return result


def cmd_list_chats(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    try:
        chats = list_chats(conn, limit=args.limit)
        # Build rows with participants and optional filtering
        rows = []
        for c in chats:
            participants = list_participants(conn, c["chat_id"])
            # filter by participants if provided (must include all)
            if getattr(args, "filter_participant", None):
                want = set(args.filter_participant)
                if not want.issubset(set(participants)):
                    continue
            raw_group_name = (c["name"] or "").strip()
            display_name = raw_group_name if raw_group_name else "(unnamed)"
            rows.append({
                "chat_id": str(c["chat_id"]),
                "group_name": display_name,
                "participants": ", ".join(participants) if participants else "(none)",
            })

        if RICH_AVAILABLE:
            table = Table(title="recent chats")
            table.add_column("group id", justify="right")
            table.add_column("group name")
            table.add_column("participants")
            for r in rows:
                table.add_row(r["chat_id"], r["group_name"], r["participants"])
            _console.print(table)
        else:
            print("group id\tgroup name\tparticipants")
            print("--------\t----------\t------------")
            for r in rows:
                print(f"{r['chat_id']}\t{r['group_name']}\t{r['participants']}")
        return 0
    finally:
        conn.close()


def _resolve_chat_id(conn: sqlite3.Connection, chat_id: Optional[int], chat_name: Optional[str]) -> Tuple[int, str, List[str]]:
    if chat_id is not None:
        participants = list_participants(conn, chat_id)
        return chat_id, "", participants
    if not chat_name:
        raise ValueError("either chat-id or chat-name is required")
    matches = find_chats_by_name(conn, chat_name)
    if not matches:
        raise ValueError(f"no chats matched name: {chat_name}")
    chosen = matches[0]
    cid = int(chosen["chat_id"]) 
    name = _normalized_chat_name(chosen)
    participants = list_participants(conn, cid)
    return cid, name, participants


def cmd_dry_run(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    try:
        chat_id, chat_name, participants = _resolve_chat_id(conn, args.chat_id, args.chat_name)
        header = f"chat: {chat_name} (id {chat_id})" if chat_name else f"chat id: {chat_id}"
        parts = ", ".join(participants) if participants else "(none)"
        if RICH_AVAILABLE:
            _console.print(Panel.fit(f"{header}\nparticipants: {parts}", title="selection"))
        else:
            print(header)
            print(f"participants: {parts}")
        found = extract_spotify_links(conn, chat_id=chat_id, expand_short_links=True)
        # only tracks; keep first occurrence; already in chronological order because query orders by date asc
        tracks = dedupe_keep_first_by_track(found)

        if RICH_AVAILABLE:
            table = Table(title=f"tracks (oldest → newest)  total={len(tracks)}")
            table.add_column("date/time")
            table.add_column("sender")
            table.add_column("track id")
            table.add_column("link")
            for item in tracks:
                ts_local = item.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                who = item.sender
                short = f"https://open.spotify.com/track/{item.track_id}" if item.track_id else (item.expanded_url or item.raw_url)
                table.add_row(ts_local, who, item.track_id or "-", short)
            _console.print(table)
        else:
            print(f"total spotify links found: {len(found)}")
            print(f"total track links (deduped, oldest→newest): {len(tracks)}")
            print()
            for item in tracks:
                ts_local = item.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                who = item.sender
                url = item.expanded_url or item.raw_url
                print(f"{ts_local}\t{who}\t{item.track_id}\t{url}")
        return 0
    finally:
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="imessage → spotify extractor (dry-run)")
    p.add_argument(
        "--version",
        action="version",
        version="imsg2spot 0.1.3",
        help="show version and exit",
    )
    p.add_argument(
        "--db",
        default=os.path.expanduser("~/Library/Messages/chat.db"),
        help="path to chat.db (default: ~/Library/Messages/chat.db)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list-chats", help="list recent chats with participants")
    p_list.add_argument("--limit", type=int, default=50, help="number of chats to list (default: 50)")
    p_list.add_argument("--filter-participant", action="append", default=[], help="only show chats that include this handle (repeatable)")
    p_list.set_defaults(func=cmd_list_chats)

    p_dry = sub.add_parser("dry-run", help="extract spotify track links and print in order")
    g1 = p_dry.add_mutually_exclusive_group(required=True)
    g1.add_argument("--chat-id", type=int, help="chat rowid to scan (e.g., 27)")
    g1.add_argument("--chat-name", type=str, help="chat display name (case-insensitive)")
    p_dry.set_defaults(func=cmd_dry_run)

    p_make = sub.add_parser("make-playlist", help="create/update public playlist with extracted tracks")
    g2 = p_make.add_mutually_exclusive_group(required=True)
    g2.add_argument("--chat-id", type=int, help="chat rowid to scan (e.g., 27)")
    g2.add_argument("--chat-name", type=str, help="chat display name (case-insensitive)")
    p_make.add_argument("--name", default="FEDs", help="playlist name (default: FEDs)")
    p_make.add_argument("--public", action="store_true", default=True, help="make playlist public (default: true)")
    p_make.set_defaults(func=cmd_make_playlist)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

# -----------------------
# OAuth + Playlist code
# -----------------------


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _gen_pkce_verifier_challenge() -> Tuple[str, str]:
    verifier_bytes = os.urandom(64)
    verifier = _b64url_no_pad(verifier_bytes)
    challenge = _b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class OAuthCodeHandler(http.server.BaseHTTPRequestHandler):
    code: Optional[str] = None
    state: Optional[str] = None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        params = parse_qs(parsed.query)
        OAuthCodeHandler.code = params.get("code", [None])[0]
        OAuthCodeHandler.state = params.get("state", [None])[0]
        body = b"<html><body><h3>ok, you can return to the app.</h3></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def _start_local_server(port: int) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", port), OAuthCodeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _oauth_pkce_get_token(client_id: str, redirect_uri: str, scope: str) -> dict:
    auth_base = "https://accounts.spotify.com/authorize"
    token_url = "https://accounts.spotify.com/api/token"

    verifier, challenge = _gen_pkce_verifier_challenge()
    state = _b64url_no_pad(os.urandom(16))

    parsed = urlparse(redirect_uri)
    port = parsed.port or 8000

    server = _start_local_server(port)

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
    }
    query = "&".join(f"{k}={quote(v)}" for k, v in params.items())
    url = f"{auth_base}?{query}"

    webbrowser.open(url)

    for _ in range(600):
        if OAuthCodeHandler.code:
            break
        time.sleep(0.1)

    server.shutdown()

    if not OAuthCodeHandler.code:
        raise RuntimeError("authorization timed out")

    code = OAuthCodeHandler.code

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
    }
    r = requests.post(token_url, data=data, timeout=15)
    r.raise_for_status()
    return r.json()


def _auth_session(access_token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})
    return s


def _get_current_user_id(sess: requests.Session) -> str:
    r = sess.get("https://api.spotify.com/v1/me", timeout=15)
    r.raise_for_status()
    return r.json()["id"]


def _find_playlist_by_name(sess: requests.Session, name: str) -> Optional[str]:
    limit = 50
    offset = 0
    while True:
        r = sess.get("https://api.spotify.com/v1/me/playlists", params={"limit": limit, "offset": offset}, timeout=15)
        r.raise_for_status()
        data = r.json()
        for item in data.get("items", []):
            if (item.get("name") or "") == name:
                return item.get("id")
        if data.get("next"):
            offset += limit
        else:
            break
    return None


def _create_playlist(sess: requests.Session, user_id: str, name: str, public: bool) -> str:
    payload = {"name": name, "public": public, "description": "songs shared in imessage"}
    r = sess.post(f"https://api.spotify.com/v1/users/{user_id}/playlists", json=payload, timeout=15)
    r.raise_for_status()
    return r.json()["id"]


def _replace_playlist_items(sess: requests.Session, playlist_id: str, uris: List[str]) -> None:
    first = uris[:100]
    rest = uris[100:]
    r = sess.put(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", json={"uris": first}, timeout=30)
    r.raise_for_status()
    idx = 0
    while idx < len(rest):
        chunk = rest[idx : idx + 100]
        r = sess.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", json={"uris": chunk}, timeout=30)
        r.raise_for_status()
        idx += 100


DEFAULT_CLIENT_ID = "e9b01b313bdb459ca8c53189b3ed59ce"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8000/callback"


def cmd_make_playlist(args: argparse.Namespace) -> int:
    # optional config import; fall back to env or defaults
    cfg = None
    try:
        import config as cfg  # type: ignore
    except Exception:
        cfg = None

    client_id = os.getenv("SPOTIFY_CLIENT_ID") or (getattr(cfg, "client_id", None) if cfg else None) or DEFAULT_CLIENT_ID
    redirect_uri = os.getenv("SPOTIFY_REDIRECT_URI") or (getattr(cfg, "redirect_uri", None) if cfg else None) or DEFAULT_REDIRECT_URI

    if not client_id or not redirect_uri:
        print("missing client configuration; set SPOTIFY_CLIENT_ID and SPOTIFY_REDIRECT_URI or create config.py")
        return 1

    conn = open_db(args.db)
    try:
        chat_id, chat_name, participants = _resolve_chat_id(conn, args.chat_id, args.chat_name)
        header = f"chat: {chat_name} (id {chat_id})" if chat_name else f"chat id: {chat_id}"
        parts = ", ".join(participants) if participants else "(none)"
        if RICH_AVAILABLE:
            _console.print(Panel.fit(f"{header}\nparticipants: {parts}\nplaylist: {args.name} (public)", title="summary"))
        else:
            print(header)
            print(f"participants: {parts}")

        found = extract_spotify_links(conn, chat_id=chat_id, expand_short_links=True)
        tracks = dedupe_keep_first_by_track(found)
        track_ids = [t.track_id for t in tracks if t.track_id]
    finally:
        conn.close()

    if not track_ids:
        print("no tracks found")
        return 1

    token = _oauth_pkce_get_token(client_id=client_id, redirect_uri=redirect_uri, scope="playlist-modify-public")
    access_token = token["access_token"]

    sess = _auth_session(access_token)
    user_id = _get_current_user_id(sess)
    playlist_name = args.name
    playlist_id = _find_playlist_by_name(sess, playlist_name)
    if not playlist_id:
        playlist_id = _create_playlist(sess, user_id, playlist_name, public=bool(args.public))

    uris = [f"spotify:track:{tid}" for tid in track_ids]
    _replace_playlist_items(sess, playlist_id, uris)

    print(f"playlist '{playlist_name}' updated with {len(uris)} tracks (oldest→newest)")
    print(f"https://open.spotify.com/playlist/{playlist_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


