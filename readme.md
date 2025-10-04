## overview

turn imessage spotify links from a group chat into a spotify playlist. it runs locally on your mac, keeps only songs, de‑dupes, and orders oldest → newest.

## install

```bash
pip install imsg2spot
```

requirements (super short): macos with messages history, python 3.9+.

mac permissions (first‑time only):
1. open system settings
2. privacy & security
3. full disk access
4. turn on "terminal" (or the shell/ide you’ll use)

then quit and reopen the terminal.

## commands

### list-chats
- overview
  - shows recent chats so you can identify the right group
  - `--limit N`: how many chats to show (default 50)
  - `--filter-participant HANDLE`: only show chats that include this handle; repeatable
    - HANDLE can be a phone in e164 (e.g., `+00000000000`) or an apple id email
- example
```bash
imsg2spot list-chats --limit 50
# narrow by member(s)
imsg2spot list-chats --limit 200 \
  --filter-participant "+00000000000" \
  --filter-participant "+10000000000"
```

### dry-run
- overview
  - preview what will be added (no spotify changes)
  - pick exactly one chat selector:
    - `--chat-name NAME` (case-insensitive)
    - `--chat-id ID` (from list-chats)
  - optional: `--db PATH` if you’re using a copied db
- example
```bash
# by name
imsg2spot dry-run --chat-name "group name"
# or by id
imsg2spot dry-run --chat-id 20
```

### make-playlist
- overview
  - creates/updates your playlist on spotify (opens browser to authorize)
  - same chat selector as dry-run: choose `--chat-name NAME` or `--chat-id ID`
  - `--name PLAYLIST_NAME`: playlist title
  - `--public`: makes the playlist public (omit for private)
  - optional: `SPOTIFY_REDIRECT_URI` to change the local port if 8000 is busy
- example
```bash
# by name
imsg2spot make-playlist --chat-name "group name" --name "my playlist" --public
# or by id
imsg2spot make-playlist --chat-id 20 --name "my playlist" --public
```

### copying your live messages db (optional but safer)
```bash
mkdir -p db
sqlite3 ~/Library/Messages/chat.db ".backup 'db/chat.db'"
```
use `--db db/chat.db` if you copied it to a different path.

that’s it. if anything looks off, run dry‑run first. if port 8000 is busy, set `SPOTIFY_REDIRECT_URI=http://127.0.0.1:8888/callback` and re‑run.
