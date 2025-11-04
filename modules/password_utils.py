import math
import random
import string

def generate_password(length: int = 16, upper=True, lower=True, digits=True, symbols=True) -> str:
    """
    Generează o parolă aleatoare din seturile selectate.
    """
    pools = []
    if upper:   pools.append(string.ascii_uppercase)
    if lower:   pools.append(string.ascii_lowercase)
    if digits:  pools.append(string.digits)
    if symbols: pools.append("!@#$%^&*()-_=+[]{};:,.?/")

    if not pools:
        raise ValueError("Alege cel puțin un tip de caractere.")

    # garantăm cel puțin un char din fiecare pool selectată
    password_chars = [random.choice(pool) for pool in pools]

    all_chars = "".join(pools)
    password_chars += [random.choice(all_chars) for _ in range(max(0, length - len(password_chars)))]
    random.shuffle(password_chars)
    return "".join(password_chars[:length])

def strength_score(pwd: str) -> tuple[int, str]:
    """
    Estimează tăria parolei (scor 0..4) pe baza entropiei aproximative.
    Nu e perfect ca zxcvbn, dar e lightweight și suficient pentru proiect.
    """
    charset = 0
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_symb  = any(not c.isalnum() for c in pwd)

    if has_upper: charset += 26
    if has_lower: charset += 26
    if has_digit: charset += 10
    if has_symb:  charset += 32  # aproximativ pentru setul folosit

    if charset == 0:
        return 0, "Foarte slabă"

    entropy = len(pwd) * math.log2(charset)

    # Praguri simple (după bunul simț; ajustabile)
    if entropy < 28:
        return 0, "Foarte slabă"
    if entropy < 36:
        return 1, "Slabă"
    if entropy < 60:
        return 2, "Mediu"
    if entropy < 80:
        return 3, "Puternică"
    return 4, "Foarte puternică"
