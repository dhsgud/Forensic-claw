"""Read a completed Chromium download's final URL from a specific History database."""

import sqlite3
from contextlib import closing
from pathlib import Path


def final_download_url(history: Path, download_id: int) -> str | None:
    """Return the final recorded URL for a completed download in this database."""
    with closing(sqlite3.connect(history.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute(
            """SELECT url.url
               FROM downloads AS download
               JOIN downloads_url_chains AS url ON url.id = download.id
               WHERE download.id = ? AND download.state = 1
               ORDER BY url.chain_index DESC
               LIMIT 1""",
            (download_id,),
        ).fetchone()
    return row[0] if row else None
