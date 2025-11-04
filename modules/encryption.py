from cryptography.fernet import Fernet
import base64
import hashlib

class EncryptionManager:
    """
    Gestioneaza criptarea si decriptarea parolelor
    Criptarea se face cu o cheie derivata din master password
    """

    def __init__(self, master_password: str):
        """
        Primeste master passwd de la utilizator si deriva cheia Fernet.
        Folosim SHA-256 pentru a genera o cheie de 32 bytes din parola master
        """
        key = hashlib.sha256(master_password.encode()).digest()
        self.key = base64.urlsafe_b64encode(key)
        self.fernet = Fernet(self.key)

    def encrypt(self, plain_text: str) -> str:
        """
        Cripteaza textul trimis si il returneaza codificat
        """
        encrypted = self.fernet.encrypt(plain_text.encode())
        return encrypted.decode()

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decripteaza textul criptat si returneaza forma originala
        """
        decrypted = self.fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()

