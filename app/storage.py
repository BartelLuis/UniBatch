"""Small transactional SQLite store; one application worker, bounded background jobs."""
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.guard = threading.RLock()
        self.execute('PRAGMA journal_mode=WAL')
        self.execute('PRAGMA foreign_keys=ON')
        self.execute('PRAGMA busy_timeout=30000')
        try:
            Path(path).chmod(0o600)
        except OSError:
            pass

    def query(self, sql, args=()):
        with self.guard:
            return [dict(row) for row in self.connection.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def execute(self, sql, args=()):
        with self.guard:
            return self.connection.execute(sql, args).lastrowid

    @contextmanager
    def transaction(self):
        with self.guard:
            own = not self.connection.in_transaction
            if own:
                self.connection.execute('BEGIN IMMEDIATE')
            try:
                yield self
                if own:
                    self.connection.execute('COMMIT')
            except BaseException:
                if own:
                    self.connection.execute('ROLLBACK')
                raise

    def close(self):
        with self.guard:
            self.connection.close()
