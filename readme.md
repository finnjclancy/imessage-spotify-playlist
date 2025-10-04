## what this does

turns spotify links shared in an imessage group into a spotify playlist.

- reads your local imessage database (mac only), finds spotify links in a specific chat
- expands short links, keeps only real tracks (no podcasts/shows/albums)
- de-dupes and orders oldest → newest
- creates/updates a public playlist on your spotify

## quick start

1) prerequisites
- macos (messages app history on this machine)
- python 3.9+
- full disk access for your terminal (system settings → privacy & security → full disk access)
- spotify developer app with redirect: `http://127.0.0.1:8000/callback`

2) install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) config
create a `config.py` (do not commit this) with:
```python
client_id = "your_spotify_client_id"
redirect_uri = "http://127.0.0.1:8000/callback"
```

4) prepare the messages database
either copy your db into `db/chat.db`, or run this safe backup (recommended):
```bash
mkdir -p db
sqlite3 ~/Library/Messages/chat.db ".backup 'db/chat.db'"
```

5) find your chat and dry-run
```bash
python cli.py list-chats --limit 20
python cli.py dry-run --chat-id <rowid>
```
you’ll see lines like: `yyyy-mm-dd hh:mm:ss  sender  track_id  url`. order is oldest → newest.

6) make the playlist
```bash
python cli.py make-playlist --chat-id <rowid> --name "FEDs" --public
```
this opens a browser for spotify auth (pkce). when it finishes, it prints your playlist url.

## notes
- only real tracks are included (`/track/<22-char-id>`). podcasts (`/episode`), shows, artists, albums, and playlists are ignored.
- de-dupe keeps the first time a track was shared.
- re-running won’t double-add; it replaces content with the current ordered list.

## privacy
- this runs locally. it only reads your imessage db file.
- don’t commit personal data. add these to `.gitignore` (already suggested):
  - `config.py`
  - `db/chat.db*`

## troubleshooting
- “this redirect uri is not secure” in spotify dashboard: it’s fine for `127.0.0.1`.
- port 8000 in use: change your `redirect_uri` to a free port (e.g., `http://127.0.0.1:8888/callback`) and update it in the spotify dashboard.
- no output on dry-run: many links are “rich” in imessage; the cli parses those automatically. if you still see zero tracks, check you picked the right chat id.
- messages locked: quit the messages app and use the sqlite `.backup` command shown above.

## getting older messages (e.g., a parent from 2019)
two easy paths:

1) they run the tool on their mac
- on their mac, enable full disk access for their terminal, quit messages, then:
```bash
mkdir -p db
sqlite3 ~/Library/Messages/chat.db ".backup 'db/chat.db'"
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python cli.py list-chats --limit 50
python cli.py dry-run --chat-id <rowid>
python cli.py make-playlist --chat-id <rowid> --name "FEDs" --public
```
they’ll create their own playlist from their full history.

2) they send you a safe copy of their db
- on their mac: `sqlite3 ~/Library/Messages/chat.db ".backup '/tmp/chat.db'"`
- they send you `/tmp/chat.db` (airdrop/drive)
- you place it here as `db/dad_chat.db`, then:
```bash
python cli.py --db db/dad_chat.db list-chats --limit 50
python cli.py --db db/dad_chat.db dry-run --chat-id <rowid>
python cli.py --db db/dad_chat.db make-playlist --chat-id <rowid> --name "FEDs" --public
```

tip: chat rowids are db-specific. always run `list-chats` on the exact db you’re using to get the correct `<rowid>`.

## license
mit. do what you want, be kind.

go to spotify
make a new app
use