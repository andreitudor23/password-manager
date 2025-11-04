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

    def get_all_entries(self) -> List[PasswordEntry]:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM passwords ORDER BY service ASC")
        rows = cursor.fetchall()

        return [PasswordEntry.from_db_row(row) for row in rows]

    def delete_entry(self, entry_id: int) -> bool:
        """
        Șterge o intrare după ID. Returnează True dacă a fost ștearsă.
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        conn.commit()

        return cursor.rowcount > 0

    def clear_all_entries(self):
        """
        Șterge toate intrările din tabela passwords și resetează autoincrement-ul.
        """
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords")
        # Resetăm sqlite_sequence (doar dacă tabela are AUTOINCREMENT)
        cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'passwords'")
        conn.commit()

    def reset_database(self):
        """
        Șterge tabela passwords și o recreează (reset complet).
        """
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS passwords")
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS passwords
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           service
                           TEXT
                           NOT
                           NULL,
                           username
                           TEXT
                           NOT
                           NULL,
                           password_encrypted
                           TEXT
                           NOT
                           NULL,
                           notes
                           TEXT,
                           last_updated
                           TEXT
                           NOT
                           NULL
                       )
                       """)
        conn.commit()

    def update_entry_password(self, entry_id: int, new_encrypted_password: str):
        """
        Actualizează parola criptată a unei intrări.
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
                       UPDATE passwords
                       SET password_encrypted = ?,
                           last_updated       = datetime('now')
                       WHERE id = ?
                       """, (new_encrypted_password, entry_id))

        conn.commit()

    def find_by_service(self, service_query: str) -> List[PasswordEntry]:
        """
        Caută intrări care conțin textul service_query (case-insensitive).
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
                       SELECT *
                       FROM passwords
                       WHERE LOWER(service) LIKE ?
                       """, (f"%{service_query.lower()}%",))

        rows = cursor.fetchall()
        return [PasswordEntry.from_db_row(row) for row in rows]

    def get_entry_by_id(self, entry_id: int) -> Optional[PasswordEntry]:
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        return PasswordEntry.from_db_row(row) if row else None

    def close(self):
        """
        Închide conexiunea la baza de date.
        """
        if self._connection:
            self._connection.close()
            self._connection = None