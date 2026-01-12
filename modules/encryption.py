from cryptography.fernet import Fernet
import base64
import hashlib
import os


class EncryptionManager:
    """
    Manager general de criptare.
    Poate funcționa în două moduri:

    1) Cu master password  -> derivează cheia Fernet din parola master.
    2) Cu o cheie brută (DEK_user) -> folosește direct cheia Fernet pentru user.
    """

    def __init__(self, master_password: str = None, raw_key: bytes = None):
        """
        Dacă master_password este furnizat → derivăm cheia din parola master.
        Dacă raw_key este furnizat → îl folosim direct ca DEK (Data Encryption Key).
        EXACT unul dintre cele două trebuie trimis.
        """

        if (master_password is None) == (raw_key is None):
            raise ValueError("Trebuie fie master_password, fie raw_key, dar nu ambele.")

        # MOD 1: master password → derivă cheie Fernet
        if master_password is not None:
            key = hashlib.sha256(master_password.encode()).digest()  # 32 bytes
            fkey = base64.urlsafe_b64encode(key)
            self.key = fkey
            self.fernet = Fernet(self.key)

        # MOD 2: avem o cheie raw (DEK_user) deja formată
        else:
            if len(raw_key) != 32:
                raise ValueError("DEK_user trebuie să fie exact 32 bytes!")
            self.key = base64.urlsafe_b64encode(raw_key)
            self.fernet = Fernet(self.key)

    # ---------------------------------------------------------
    # 🚀 Helper static pentru a genera un DEK (user key)
    # ---------------------------------------------------------
    @staticmethod
    def generate_user_key() -> bytes:
        """
        Creează o cheie random de 32 bytes care va fi DEK_user.
        Această cheie nu este derivată din parolă — este complet aleatorie.
        """
        return os.urandom(32)

    # ---------------------------------------------------------
    # 🔐 Criptare / Decriptare
    # ---------------------------------------------------------
    def encrypt(self, plain_text: str) -> str:
        encrypted = self.fernet.encrypt(plain_text.encode())
        return encrypted.decode()

    def decrypt(self, encrypted_text: str) -> str:
        decrypted = self.fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()

    # ---------------------------------------------------------
    # 🔒 Funcții utile pentru a cripta/decripta DEK_user cu alte chei
    # ---------------------------------------------------------
    @staticmethod
    def encrypt_key(raw_key: bytes, fernet_key: bytes) -> bytes:
        """
        Criptează DEK_user folosind o cheie Fernet (ex: cheia master derivată).
        Returnează bytes criptati.
        """
        f = Fernet(fernet_key)
        return f.encrypt(raw_key)

    @staticmethod
    def decrypt_key(encrypted_key: bytes, fernet_key: bytes) -> bytes:
        """
        Decriptează DEK_user și întoarce cei 32 bytes originali.
        """
        f = Fernet(fernet_key)
        return f.decrypt(encrypted_key)