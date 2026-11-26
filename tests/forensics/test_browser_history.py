import sqlite3
from contextlib import closing

from forensic_claw.forensics.browser_history import final_download_url


def test_direct_lookup_returns_final_url_for_the_requested_download(tmp_path):
    history = tmp_path / "History"
    with closing(sqlite3.connect(history)) as db:
        db.executescript("""
            CREATE TABLE downloads (id INTEGER PRIMARY KEY, state INTEGER);
            CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
            INSERT INTO downloads VALUES (7, 1), (8, 1);
            INSERT INTO downloads_url_chains VALUES
                (7, 0, 'https://example.test/start'),
                (7, 2, 'https://example.test/final'),
                (8, 0, 'https://example.test/unrelated');
        """)
        db.commit()
    assert final_download_url(history, 7) == "https://example.test/final"
    assert final_download_url(history, 9) is None
