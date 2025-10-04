## what this does

turns spotify links shared in an imessage group into a spotify playlist.

- reads your local imessage database (mac only), finds spotify links in a specific chat
- expands short links, keeps only real tracks (no podcasts/shows/albums)
- de-dupes and orders oldest → newest
- creates/updates a public playlist on your spotify

## one-liner (no spotify setup needed)

my spotify app/client_id is baked in using a loopback redirect + pkce, so you don’t need to make your own app.

```bash
python cli.py make-playlist --chat-name "F is F" --name "FEDs" --public
```

that opens your browser to authorize, then builds the playlist in order (oldest → newest).

notes:
- if you prefer chat id, use: `--chat-id 27`
- if you keep messages open, quit it first so the db copy isn’t locked

## quick start

1) prerequisites
- macos (messages app history on this machine)
- python 3.9+
- full disk access for your terminal (system settings → privacy & security → full disk access)

2) install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) prepare the messages database
copy your db into `db/chat.db` (safe backup):
```bash
mkdir -p db
sqlite3 ~/Library/Messages/chat.db ".backup 'db/chat.db'"
```

4) find your chat and dry-run
```bash
python cli.py list-chats --limit 20
python cli.py dry-run --chat-name "F is F"
```

## notes
- only real tracks are included (`/track/<22-char-id>`). podcasts (`/episode`), shows, artists, albums, and playlists are ignored.
- de-dupe keeps the first time a track was shared.
- re-running won’t double-add; it replaces content with the current ordered list.

## privacy
- this runs locally. it only reads your imessage db file.
- don’t commit personal data. `.gitignore` already includes `db/chat.db*` and `config.py`.

## troubleshooting
- “this redirect uri is not secure” in spotify dashboard: we use loopback `127.0.0.1` which is fine.
- port 8000 in use: set `SPOTIFY_REDIRECT_URI` to another port (e.g., `http://127.0.0.1:8888/callback`) and re-run.
- no output on dry-run: many links are “rich” in imessage; the cli parses those automatically. if you still see zero tracks, check you picked the right chat.
- messages locked: quit the messages app and use the sqlite `.backup` command shown above.

## getting older messages (e.g., a parent from 2019)
1) they run the tool on their mac (same steps), or
2) they send you a safe copy of their db:
```bash
sqlite3 ~/Library/Messages/chat.db ".backup '/tmp/chat.db'"
```
place it as `db/dad_chat.db`, then run with `--db db/dad_chat.db`.

## license
mit. do what you want, be kind.
