from datetime import datetime
from typing import Optional


class PasswordEntry:
    """
    Aceasta clasa reprezinta o intrare a unei parole in baza de date.
    """

    def __init__(
        self,
        service: str,              # Serviciul pentru care este parola
        username: str,             # user / email cu care te loghezi
        password_encrypted: str,   # parola deja criptata
        notes: str = "",           # comentarii extra
        entry_id: Optional[int] = None,      # id-ul din baza de date (None daca nu a fost salvata anterior)
        last_updated: Optional[str] = None,  # ultima data cand a fost updatata parola
    ):
        self.id = entry_id
        self.service = service
        self.username = username
        self.password_encrypted = password_encrypted
        self.notes = notes
        self.last_updated = last_updated or datetime.now().isoformat(timespec="seconds")

    def to_tuple_db(self):
        """
        Returneaza datele intr-un format care este usor de introdus in baza de date SQLite.
        Self.id-ul este autoincrementat de la SQL.
        """
        return (
            self.service,
            self.username,
            self.password_encrypted,
            self.notes,
            self.last_updated,
        )

    @staticmethod
    def from_db_row(row: tuple) -> "PasswordEntry":
        """
        Creeaza un obiect PasswordEntry pornind de la un rand scos din Database.
        """
        return PasswordEntry(
            entry_id=row[0],
            service=row[1],
            username=row[2],
            password_encrypted=row[3],
            notes=row[4],
            last_updated=row[5],
        )

    def __str__(self):
        """
        Modul in care se afiseaza intrarea atunci cand facem un print.
        Parola nu va fi afisata in clar si nici intreaga forma criptata.
        """
        preview = self.password_encrypted[:10] + "..."  # afisam doar primele 10 caractere

        return (
            f"[ID: {self.id}] {self.service}\n"
            f"Username: {self.username}\n"
            f"Password(encrypted): {preview}\n"
            f"Notes: {self.notes}\n"
            f"Last Updated: {self.last_updated}\n"
        )