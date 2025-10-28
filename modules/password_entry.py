from datetime import datetime
from typing import Optional

class PasswordEntry:

    def __init__(
        self,
        service: str,
        username: str,
        password_encrypted: str,
        notes: str = "",
        entry_id: Optional[int] = None,
        last_updated: Optional[str] = None
    ):
        self.id = entry_id
        self.service = service
        self.username = username
        self.password_encrypted = password_encrypted
        self.notes = notes
        self.last_updated = last_updated or datetime.now().isoformat(timespec="seconds")

    def to_tuple_db(self):
        return (
            self.service,
            self.username,
            self.password_encrypted,
            self.notes,
            self.last_updated,
        )

    @staticmethod
    def from_db_row(row: tuple) -> "PasswordEntry":
        return PasswordEntry(
            entry_id=row[0],
            service=row[1],
            username=row[2],
            password_encrypted=row[3],
            notes=row[4],
            last_updated=row[5],
        )

    def __str__(self):

        preview = self.password_encrypted[:10] + "..." #afisam doar primele 10 caractere

        return (
            f"[ID: {self.id}] {self.service}\n"
            f"Username: {self.username}\n"
            f"Password(encrypted): {preview}\n"
            f"Notes: {self.notes}\n"
            f"Last Updated: {self.last_updated}\n"
        )