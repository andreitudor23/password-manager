import sqlite3
import hashlib
from typing import List, Optional
from dataclasses import dataclass
from pathlib import Path

from modules.password_entry import PasswordEntry
from modules.encryption import EncryptionManager


@dataclass
class User:
    id: int
    username: str
    role: str
    password_hash: str
    user_key_for_master: Optional[bytes] = None
    user_key_for_user: Optional[bytes] = None


class DatabaseManager:
    def __init__(self, db_path: str = "data/database.db"):
        self.db_path = Path(db_path)
        self._connection: Optional[sqlite3.Connection] = None
        self._create_table_if_not_exists()

    # ------------------------------------------------------------------
    # CONNECTION
    # ------------------------------------------------------------------
    def _connect(self):
        if self._connection is None:
            self._connection = sqlite3.connect(str(self.db_path))
            self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection

    # ------------------------------------------------------------------
    # DB CREATION / MIGRATION
    # ------------------------------------------------------------------
    def _create_table_if_not_exists(self):
        conn = self._connect()
        cursor = conn.cursor()

        # USERS
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('master', 'user')),
                user_key_for_master BLOB,
                user_key_for_user   BLOB,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)

        cursor.execute("PRAGMA table_info(users)")
        cols = [row[1] for row in cursor.fetchall()]
        if "user_key_for_master" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN user_key_for_master BLOB")
        if "user_key_for_user" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN user_key_for_user BLOB")

        # PASSWORDS
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                notes TEXT,
                last_updated TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        cursor.execute("PRAGMA table_info(passwords)")
        cols = [row[1] for row in cursor.fetchall()]
        if "user_id" not in cols:
            cursor.execute("ALTER TABLE passwords ADD COLUMN user_id INTEGER")

        conn.commit()

    # ------------------------------------------------------------------
    # USER HELPERS
    # ------------------------------------------------------------------
    def _hash_user_password(self, password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "user",
        master_fernet_key: Optional[bytes] = None,
    ) -> int:

        conn = self._connect()
        cursor = conn.cursor()

        password_hash = self._hash_user_password(password)

        user_key_for_master = None
        user_key_for_user = None

        if master_fernet_key is not None:
            # 1. Generăm cheia reală a userului
            dek_user = EncryptionManager.generate_user_key()

            # 2. Derivăm cheia fernet din parola userului
            user_enc = EncryptionManager(master_password=password)
            user_fernet_key = user_enc.key

            # 3. Criptăm DEK_user pentru master + pentru user
            user_key_for_master = EncryptionManager.encrypt_key(dek_user, master_fernet_key)
            user_key_for_user = EncryptionManager.encrypt_key(dek_user, user_fernet_key)

        cursor.execute("""
            INSERT INTO users(username, password_hash, role, user_key_for_master, user_key_for_user)
            VALUES(?, ?, ?, ?, ?)
        """, (username, password_hash, role, user_key_for_master, user_key_for_user))

        conn.commit()
        return cursor.lastrowid

    def get_user_by_username(self, username: str) -> Optional[User]:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, role, password_hash, user_key_for_master, user_key_for_user
            FROM users
            WHERE username = ?
        """, (username,))
        row = cursor.fetchone()

        if not row:
            return None

        return User(*row)

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """!!! Necesară pentru decriptarea per-user în main_gui !!!"""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, role, password_hash, user_key_for_master, user_key_for_user
            FROM users
            WHERE id = ?
        """, (user_id,))
        row = cursor.fetchone()

        return User(*row) if row else None

    def verify_user_credentials(self, username: str, password: str) -> Optional[User]:
        user = self.get_user_by_username(username)
        if not user:
            return None
        if user.password_hash != self._hash_user_password(password):
            return None
        return user

    def get_all_users(self) -> List[User]:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, username, role, password_hash, user_key_for_master, user_key_for_user
            FROM users
            ORDER BY username ASC
        """)
        return [User(*row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # DEK (Data Encryption Key) RETRIEVAL
    # ------------------------------------------------------------------
    def get_user_dek_via_master(self, user: User, master_fernet_key: bytes) -> Optional[bytes]:
        if not user.user_key_for_master:
            return None
        return EncryptionManager.decrypt_key(user.user_key_for_master, master_fernet_key)

    def get_user_dek_via_user_password(self, user: User, user_password: str) -> Optional[bytes]:
        if not user.user_key_for_user:
            return None
        user_enc = EncryptionManager(master_password=user_password)
        return EncryptionManager.decrypt_key(user.user_key_for_user, user_enc.key)

    # ------------------------------------------------------------------
    # PASSWORD ENTRIES
    # ------------------------------------------------------------------
    def add_entry(self, entry: PasswordEntry, user_id: Optional[int] = None) -> int:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO passwords(service, username, password_encrypted, notes, last_updated, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (*entry.to_tuple_db(), user_id))

        conn.commit()
        return cursor.lastrowid

    def get_all_entries(self) -> List[PasswordEntry]:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            ORDER BY service ASC
        """)
        return [PasswordEntry.from_db_row(r) for r in cursor.fetchall()]

    def get_entries_for_user(self, user_id: int) -> List[PasswordEntry]:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            WHERE user_id = ?
            ORDER BY service ASC
        """, (user_id,))
        return [PasswordEntry.from_db_row(r) for r in cursor.fetchall()]

    def get_entry_owner_id(self, entry_id: int) -> Optional[int]:
        """!!! Necesară pentru master ca să știe cu ce cheie să decripteze !!!"""
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("SELECT user_id FROM passwords WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        return row[0] if row else None

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

    def update_entry_password(self, entry_id: int, new_encrypted_password: str):
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE passwords
            SET password_encrypted = ?, last_updated = datetime('now')
            WHERE id = ?
        """, (new_encrypted_password, entry_id))

        conn.commit()

    def delete_entry(self, entry_id: int) -> bool:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        conn.commit()
        return cursor.rowcount > 0

    def find_by_service(self, query: str) -> List[PasswordEntry]:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            WHERE LOWER(service) LIKE ?
        """, (f"%{query.lower()}%",))
        return [PasswordEntry.from_db_row(r) for r in cursor.fetchall()]

    def find_by_service_for_user(self, query: str, user_id: int) -> List[PasswordEntry]:
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, service, username, password_encrypted, notes, last_updated
            FROM passwords
            WHERE user_id = ? AND LOWER(service) LIKE ?
        """, (user_id, f"%{query.lower()}%",))
        return [PasswordEntry.from_db_row(r) for r in cursor.fetchall()]

    # ------------------------------------------------------------------
    # MAINTENANCE
    # ------------------------------------------------------------------
    def clear_all_entries(self):
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM passwords")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='passwords'")
        conn.commit()

    def reset_database(self):
        """
        Șterge complet baza de date:
        - tabela passwords
        - tabela users
        și le recreează de la zero.
        """
        conn = self._connect()
        cursor = conn.cursor()

        cursor.execute("DROP TABLE IF EXISTS passwords")
        cursor.execute("DROP TABLE IF EXISTS users")
        conn.commit()

        # recreăm schema fresh
        self._create_table_if_not_exists()

    def close(self):
        if self._connection:
            self._connection.close()
            self._connection = None