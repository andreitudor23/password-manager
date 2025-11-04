import os
import json
import hashlib
from getpass import getpass, GetPassWarning
from modules.encryption import EncryptionManager

try:
    # maschează cu ***** și merge în IDE-uri
    from pwinput import pwinput as hidden_input
except Exception:
    hidden_input = None


def ask_secret(prompt: str) -> str:
    # preferă pwinput dacă e instalat
    if hidden_input is not None:
        return hidden_input(prompt)
    # fallback la getpass și ascunde warningul enervant
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", GetPassWarning)
        return getpass(prompt)

class AuthManager:
    def __init__(self, auth_file_path: str = "data/auth.json"):
        self.auth_file_path = auth_file_path
        self.master_hash = None

        if os.path.exists(self.auth_file_path):
            try:
                with open(self.auth_file_path, "r") as f:
                    data = json.load(f)
                # ✅ folosește .get() CORECT
                self.master_hash = data.get("master_hash")
                # opțional: validare basic
                if not isinstance(self.master_hash, str) or len(self.master_hash) < 10:
                    self.master_hash = None  # forțează re-setup dacă fișierul e ciudat
            except (JSONDecodeError, OSError):
                # fișier gol/corupt → îl ignorăm; va rula setup la nevoie
                self.master_hash = None


    def _hash_password(self, password: str) -> str:
        """
        Genereaza hash SHA-256 al parolei master
        :param password:
        :return:
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def setup_master_password(self):
        """
        Creeaza o parola master la prima rulare
        """
        print("Configurare master password: ")

        while True:
            pw1 = ask_secret("Introdu o parola master: ")
            pw2 = ask_secret("Confirma parola master: ")

            if pw1 != pw2:
                print("Parolele nu coincid. Incearca din nou")
                continue

            self.master_hash = self._hash_password(pw1)
            os.makedirs(os.path.dirname(self.auth_file_path), exist_ok=True)
            with open(self.auth_file_path, "w") as f:
                json.dump({"master_hash": self.master_hash}, f, indent=4)

            print("Parola master a fost configurata cu succes")
            return pw1

    def verify_master_password(self) -> str:
        """
        Verifica parola master introdusa de utilizator.
        Returneaza parola in clar daca e corecta pentru a o folosi la criptare
        :return:
        """

        if not self.master_hash:
            return self.setup_master_password()

        for _ in range(3):
            pw = ask_secret("Introdu parola master: ")
            if self._hash_password(pw) == self.master_hash:
                print("Autentificare reusita")
                return pw
            else:
                print("Parola incorecta")

        print("Prea multe incercari gresite. Acces Blocat")
        exit(1)

    def reset_master_password(self):
        """
        Șterge fișierul auth.json (dacă există) și resetează starea internă astfel încât
        la următoarea rulare aplicația va cere configurarea unui nou master password.
        """
        try:
            if os.path.exists(self.auth_file_path):
                os.remove(self.auth_file_path)
            self.master_hash = None
            print("✅ Master password a fost resetat (fișierul auth sters).")
        except Exception as e:
            print(f"⚠️ Eroare la resetarea master password: {e}")

    def has_master(self) -> bool:
        """Îți spune dacă există deja master password inițializat (auth.json valid)."""
        return isinstance(self.master_hash, str) and len(self.master_hash) > 0

    def check_password(self, password: str) -> bool:
        """Verifică o parolă dată față de hash-ul salvat. Nu citește din input, doar compară."""
        if not self.has_master():
            return False
        return self._hash_password(password) == self.master_hash

    def set_new_master(self, password: str):
        """
        Setează un master password NOU și îl salvează în data/auth.json.
        Folosit de GUI la prima rulare (în loc să citească din getpass).
        """
        self.master_hash = self._hash_password(password)
        os.makedirs(os.path.dirname(self.auth_file_path), exist_ok=True)
        with open(self.auth_file_path, "w") as f:
            json.dump({"master_hash": self.master_hash}, f, indent=4)