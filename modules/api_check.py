import hashlib
import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

def pwned_count(password: str) -> int:
    """
    Verifică dacă parola apare în breach-uri publice.
    Întoarce de câte ori a apărut (0 = e ok din punctul ăsta de vedere).
    Implementare k-anonymity: trimitem DOAR prefixul SHA1 (primele 5 caractere).
    """

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    resp = requests.get(HIBP_RANGE_URL.format(prefix), timeout=8)
    resp.raise_for_status()

    # răspunsul are multe linii "SUFFIX:COUNT"
    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        sfx, cnt = parts[0].strip(), parts[1].strip()
        if sfx == suffix:
            try:
                return int(cnt)
            except ValueError:
                return 0
    return 0
