import sqlite3
from typing import List, Optional
from modules.password_entry import PasswordEntry
from pathlib import Path

class DatabaseManager:
    def __init__(self, db_path: str = "data/database.db"):
        self.db_path = Path(db_path)
        self._connection: Optional[sqlite3.Connection] = None

        self._create_table_if_not_exists()

    def _connect(self):
        if self._connection is None:
            self._connection = sqlite3.connect(str(self.db_path))
        return self._connection

    def _create_table_if_not_exists(self):
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            notes TEXT,
            last_updated TEXT NOT NULL
        )
                       ''')

        conn.commit()

    def add_entry(self, entry: PasswordEntry) -> int:
        """
        Adaugam o parola noua in baza de date
        Returneaza id ul parolei adaugate
        """

        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO passwords (service, username, password_encrypted, notes, last_updated)
            VALUES (?, ?, ?, ?, ?)
        ''', entry.to_tuple_db())

        conn.commit()
        return cursor.lastrowid