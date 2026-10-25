"""Локальная история на SQLite: подтверждение только после COMMIT."""

import fcntl
import hashlib
import json
import os
import sqlite3
import stat


class Store:
    def __init__(self, path, binary):
        self.lock = None
        self.db = None
        self.persistent = path is not None
        try:
            fresh = path is None
            if path is not None:
                if path.is_symlink():
                    raise ValueError("Хранилище не должно быть символической ссылкой")
                fd = os.open(
                    str(path) + ".lock",
                    os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                    0o600,
                )
                self.lock = os.fdopen(fd, "a")
                if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 1:
                    raise ValueError("Нужен обычный файл блокировки без ссылок")
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    if (
                        not stat.S_ISREG(path.lstat().st_mode)
                        or path.lstat().st_nlink != 1
                    ):
                        raise ValueError("Нужен обычный файл хранилища") from None
                else:
                    os.close(fd)
                    fresh = True
            self.db = sqlite3.connect(
                ":memory:" if path is None else str(path),
                timeout=0,
                isolation_level=None,
            )
            self.db.execute("PRAGMA synchronous=FULL")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            if fresh:
                self.db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE history(seq INTEGER PRIMARY KEY,payload TEXT NOT NULL,wire TEXT NOT NULL,report TEXT NOT NULL);
                    PRAGMA user_version=2;
                """)
                self.db.execute(
                    "INSERT INTO metadata VALUES('core_sha256',?)", (digest,)
                )
                self.db.execute("COMMIT")
            else:
                if self.db.execute("PRAGMA user_version").fetchone() != (2,):
                    raise ValueError("Неподдерживаемый формат хранилища")
                if self.db.execute(
                    "SELECT value FROM metadata WHERE name='core_sha256'"
                ).fetchone() != (digest,):
                    raise ValueError(
                        "Для хранилища нужен исходный проверенный бинарник"
                    )
            self.db.execute("PRAGMA max_page_count=4096")
            if self.db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("Повреждённое хранилище")
        except BaseException:
            self.close()
            raise

    def rows(self):
        rows = self.db.execute(
            "SELECT seq,payload,wire,report FROM history ORDER BY seq"
        ).fetchall()
        if len(rows) > 1000:
            raise ValueError("Превышен предел истории")
        if [r[0] for r in rows] != list(range(1, len(rows) + 1)):
            raise ValueError("Нарушена последовательность истории")
        return rows

    def append(self, record, wire, report):
        payload = json.dumps(record, ensure_ascii=False, sort_keys=True)
        rendered = json.dumps(report, ensure_ascii=False, sort_keys=True)
        if max(len(s.encode()) for s in (payload, wire, rendered)) > 65536:
            raise ValueError("Превышен размер сохраняемой записи")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            count = self.db.execute("SELECT COUNT(*) FROM history").fetchone()[0]
            if count >= 1000:
                raise ValueError("Превышен предел истории")
            self.db.execute(
                "INSERT INTO history VALUES(?,?,?,?)",
                (count + 1, payload, wire, rendered),
            )
            self.db.execute("COMMIT")
            return count + 1
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None
