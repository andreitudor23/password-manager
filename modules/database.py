import sqlite3
import hashlib
from typing import List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from modules.password_entry import PasswordEntry


@dataclass
class User:
    id: int
    username: str
    role: str
    password_hash: str


class DatabaseManager:
    def __init__(self, db_path: str = "data/database.db"):
        self.db_path = Path(db_path)
        self._connection: Optional[sqlite3.Connection] = None

        self._create_table_if_not_exists()

    def _connect(self):
        if self._connection is None:
            self._connection = sqlite3.connect(str(self.db_path))
            # activăm cheile străine (când există)
            self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection

    def _create_table_if_not_exists(self):
        """
        Creează tabelele users și passwords dacă nu există.
        Dacă tabela passwords este veche (fără user_id), adăugăm coloana.
        """
        conn = self._connect()
        cursor = conn.cursor()

        # 1) tabela de utilizatori
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('master', 'user')),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)

        # 2) tabela de parole (noua schemă are user_id)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                notes TEXT,
                last_updated TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # 3) dacă avem o bază veche fără coloana user_id, o adăugăm
        cursor.execute("PRAGMA table_info(passwords)")
        columns = [row[1] for row in cursor.fetchall()]  # row[1] = numele coloanei
        if "user_id" not in columns:
            cursor.execute("ALTER TABLE passwords ADD COLUMN user_id INTEGER")

        conn.commit()

    # -------------------------------------------------------------------------
    # USERI
    # -------------------------------------------------------------------------
    def _hash_user_password(self, password: str) -> str:
        """Hash simplu cu SHA-256 pentru parolele userilor (nu master password)."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def create_user(self, username: str, password: str, role: str = "user") -> int:
        """
        Creează un utilizator nou (implicit rol 'user').
        Returnează id-ul userului creat.
        """
        conn = self._connect()
        cursor = conn.cursor()

        password_hash = self._hash_user_password(password)
        cursor.execute("""
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        """, (username, password_hash, role))
        conn.commit()
        return cursor.lastrowid

    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Returnează User pentru username dat, sau None dacă nu există.
        """
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, role, password_hash
            FROM users
            WHERE username = ?
        """, (username,))
        row = cursor.fetchone()
        if not row:
            return None
        user_id, uname, role, pwhash = row
        return User(id=user_id, username=uname, role=role, password_hash=pwhash)

    def verify_user_credentials(self, username: str, password: str) -> Optional[User]:
        """
        Verifică username + parolă. Dacă sunt corecte, returnează User, altfel None.
        """
        user = self.get_user_by_username(username)
        if not user:
            return None
        if user.password_hash != self._hash_user_password(password):
            return None
        return user

    def get_all_users(self) -> List[User]:
        """
        Returnează toți utilizatorii existenți.
        """
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role, password_hash FROM users ORDER BY username ASC")
        rows = cursor.fetchall()
        return [User(id=r[0], username=r[1], role=r[2], password_hash=r[3]) for r in rows]

    # -------------------------------------------------------------------------
    # PAROLE
    # -------------------------------------------------------------------------
    def add_entry(self, entry: PasswordEntry, user_id: Optional[int] = None) -> int:
        """
        Adăugăm o parolă nouă în baza de date.
        Returnează id-ul parolei adăugate.
        user_id:
            - None = (temporar) fără user asociat
            - altfel = id-ul userului căruia îi aparține parola
        """
        conn = self._connect()
        cursor = conn.cursor()

        # entry.to_tuple_db() -> (service, username, password_encrypted, notes, last_updated)
        data = entry.to_tuple_db()
        cursor.execute("""
            INSERT INTO passwords (service, username, password_encrypted, notes, last_updated, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (*data, user_id))

        conn.commit()
        return cursor.lastrowid

    def get_all_entries(self) -> List[PasswordEntry]:
        """
        Returnează toate intrările (indiferent de user).
        NOTĂ: selectăm explicit coloanele, ca să nu stricăm PasswordEntry.from_db_row
        chiar dacă tabela are și coloana user_id.
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            ORDER BY service ASC
        """)
        rows = cursor.fetchall()

        return [PasswordEntry.from_db_row(row) for row in rows]

    def get_entries_for_user(self, user_id: int) -> List[PasswordEntry]:
        """
        Returnează intrările care aparțin unui anumit user.
        """
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            WHERE user_id = ?
            ORDER BY service ASC
        """, (user_id,))
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
        cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'passwords'")
        conn.commit()

    def reset_database(self):
        """
        Șterge tabela passwords și o recreează (reset complet doar pentru parole).
        NOTĂ: nu ștergem tabela users aici, ca să nu pierdem utilizatorii.
        Dacă vrei reset complet (și users), poți extinde această metodă.
        """
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS passwords")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                notes TEXT,
                last_updated TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
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
        Caută intrări care conțin textul service_query (case-insensitive) pentru TOȚI userii.
        Va fi folosit în principal de master.
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            WHERE LOWER(service) LIKE ?
        """, (f"%{service_query.lower()}%",))

        rows = cursor.fetchall()
        return [PasswordEntry.from_db_row(row) for row in rows]

    def find_by_service_for_user(self, service_query: str, user_id: int) -> List[PasswordEntry]:
        """
        Caută intrări pentru UN anumit user, după service.
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            WHERE user_id = ?
              AND LOWER(service) LIKE ?
        """, (user_id, f"%{service_query.lower()}%",))

        rows = cursor.fetchall()
        return [PasswordEntry.from_db_row(row) for row in rows]

    def get_entry_by_id(self, entry_id: int) -> Optional[PasswordEntry]:
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            WHERE id = ?
        """, (entry_id,))
        row = cursor.fetchone()
        return PasswordEntry.from_db_row(row) if row else None

    def close(self):
        """
        Închide conexiunea la baza de date.
        """
        if self._connection:
            self._connection.close()
            self._connection = None