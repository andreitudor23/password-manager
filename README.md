# 🔐 Password Manager — Aplicație completă de gestionare a parolelor

Acest proiect este un **Password Manager avansat**, construit în Python, care oferă un sistem complet de stocare, administrare și securizare a parolelor. Aplicația este gândită pentru utilizare reală și combină mai multe tehnologii:

- criptare avansată cu chei individuale per utilizator (DEK)
- un sistem MASTER cu drepturi administrative totale
- utilizatori normali, izolați între ei
- verificarea parolelor prin API-ul *Have I Been Pwned*
- autentificare biometrică (FaceID) pentru master
- interfață grafică (GUI) intuitivă realizată cu Tkinter

Proiectul demonstrează lucrul cu:
- criptografie simetrică (Fernet)
- baze de date SQLite cu migrare automată
- recunoaștere facială OpenCV
- arhitectură multi-user
- generare + evaluare parole
- gestionarea sigură a datelor sensibile

Aplicația este modulară, scalabilă și ușor de extins, datorită structurii bine organizate a codului și separării responsabilităților.

---

## Funcționalități principale

### Sistem MASTER + utilizatori multipli
- MASTER poate vedea, edita și administra **toate parolele tuturor userilor**
- fiecare utilizator are propria parolă de login
- fiecare utilizator poate accesa **doar propriile parole**
- tabele separate în baza de date pentru useri și parole

### Criptare
- fiecare user are o cheie unică (`DEK_user`)
- parolele sunt criptate individual, nu cu o cheie globală
- cheia master poate decripta orice `DEK_user`
- schimbarea parolei unui user nu duce la re-criptarea tuturor parolelor lui

### Autentificare biometrică (FaceID)
- master își poate înregistra fața
- login-ul de master poate necesita atât parolă, cât și verificare facială
- sistem bazat pe OpenCV: Haar Cascade + LBPH

### Generare și evaluare parole
- generator configurabil (lungime, simboluri, litere, cifre etc.)
- evaluare tărie în timp real (Foarte slabă → Foarte puternică)
- bazat pe entropie

### Integrare Have I Been Pwned
- verifică dacă parola a apărut în breach-uri online
- implementare corectă **k-anonymity** → parola nu părăsește dispozitivul

### Resetare completă a aplicației
- șterge toți userii
- șterge toate parolele
- șterge FaceID-ul
- șterge parola master
- revine la starea „prima pornire”

### Interfață grafică completă
- login master / login user
- listă de parole filtrabilă
- buton „Reveal password” cu auto-expirare
- afișarea puterii parolelor cu culori (roșu / portocaliu / verde)
- acțiuni diferite pentru master și user

---

## `gui/main_gui.py`

Fișierul main_gui.py conține interfața grafică principală a aplicației de password manager. Aici se leagă partea de UI cu toate modulele „de logică” din proiect:
	
    • autentificare (master + useri)
	• criptare și decriptare parole
	• acces la baza de date
	• verificare parole în HaveIBeenPwned
	• autentificare facială (FaceID)

### Rol general:

	• Pornește aplicația GUI (App).

	• Oferă două moduri de lucru:
	   - MASTER – admin, are acces la toți userii și toate parolele
	   - USER – utilizator normal, vede și modifică doar parolele lui
	• Creează fereastra principală cu:
	   -  toolbar (butoane de acțiune)
	   - tabel cu parole
	   - status bar

	• Controlează fluxurile de:
	   - login master
	   - login user
	   - reset aplicație
	   - afișare / adăugare / editare / ștergere parole

⸻

### Module folosite

main_gui.py se bazează pe:

	• modules.auth.AuthManager – gestionează parola master (hash + fișier auth.json)
	• modules.encryption.EncryptionManager – criptare / decriptare parole și chei DEK per user
	• modules.database.DatabaseManager – interacțiune cu baza de date (users + passwords)
	• modules.password_entry.PasswordEntry – reprezentarea unei intrări de parolă
	• modules.api_check.pwned_count – verifică dacă o parolă apare în breșe (HIBP)
	• modules.face_auth.FaceAuthManager – enrolare + verificare facială pentru master

⸻

### Clase principale

**LoginWindow**

	• Fereastră modală pentru autentificare master.
	• Două moduri:
	• dacă nu există master → cere și setează noua parolă master
	• dacă master există → cere parola master pentru login
	• Setează self.password la parola introdusă (dacă e corectă), altfel afișează eroare.

**ScrollableToolbar**

	• Un Frame custom care conține un toolbar orizontal scrollabil.
	• Folosește un Canvas + Scrollbar pentru a permite derularea butoanelor când sunt prea multe (e util pe ecrane mici).
	• Metoda add(widget, ...) permite adăugarea de butoane/controale pe bară.

**UsersOverviewWindow**

	• Fereastră separată, disponibilă doar în modul MASTER.
	• În stânga: listă cu toți userii (Listbox).
	• În dreapta: Treeview cu toate parolele decriptate ale userului selectat.
	• Folosește logica de decriptare existentă în App._decrypt_entry_password.
	• Dublu click pe o intrare → copiază parola în clipboard (folosind secure_copy din App).

### App (clasa principală a GUI-ului)

**Inițializează:**

	• managerii de back-end: AuthManager, DatabaseManager, FaceAuthManager
	• starea criptografică:
	• master_key – cheia Fernet derivată din parola master
	• user_enc – EncryptionManager construit cu DEK_user
	• mode – "master" sau "user"
	• current_user – obiect User pentru userul logat (sau None dacă suntem master)

**Conține:** 
    
1. Toată logica de autentificare:

        • authenticate() – întreabă dacă vrei login ca master sau ca user
        • _master_login_flow() – login master + FaceID (dacă e activat)
        • _user_login_flow() – login user (username + parola lui, fără master)
        • logout() – revine la ecranul de alegere mod master/user
	
2. Logica de GUI:

        • create_widgets() – construiește toolbar-ul, tabelul și status bar-ul 
        • update_ui_for_role() – activează/dezactivează butoane în funcție de rol

3. Logica de gestionare a userilor:
        
        • create_user_dialog() – doar master poate crea utilizatori noi (cu DEK_user generat în DB)
        • user_login_dialog() – buton de login/relocare ca user
        • show_users_overview() – deschide fereastra UsersOverviewWindow

4. Logica de criptare / chei:

        • _get_entry_encryption_manager(entry_id) – decide ce cheie se folosește pentru o parolă:
            - în mod user → self.user_enc (DEK_user)
            - în mod master → decriptează DEK_user al owner-ului intrării și construiește un EncryptionManager temporar

        • _decrypt_entry_password(entry) – decriptează o parolă de pe baza EncryptionManager potrivit

5. Logica pentru parole:

        • add_entry() – userul adaugă o parolă nouă (verificată în prealabil cu HIBP)
        • show_selected() – afișează parola mascată + opțiune de copy
        • reveal_selected() – afișează parola în clar într-o fereastră care se închide automat după 10s
        • update_selected() – userul își poate actualiza doar parolele lui
        • delete_selected() – șterge o intrare (user: doar ale lui, master: orice)
        • check_selected() – verifică parola selectată în HIBP

6. Logica pentru HIBP global:
        
        • audit_hibp_all() – în background, verifică toate parolele din listă și actualizează coloana HIBP

7. Logica de filtrare & afișare:
    
        • refresh() – reîncarcă lista de parole în funcție de mod:
           - master → toate parolele
           - user → doar parolele userului logat

        •	search() – caută după service în parolele vizibile (filtrate pe user dacă e mod user)

8. Resetare completă:

        • reset_app() – șterge:
             -	toate parolele și userii (prin db.reset_database())
             - master password (prin auth.reset_master_password())
             - fișierele de FaceID (prin FaceAuthManager sau fallback)

9. Helperi:
       
        • mask_password() – înlocuiește parola cu bullet-uri de aceeași lungime
        • secure_copy(text, seconds=15) – copiază parola în clipboard și o șterge automat după N secunde

⸻

## Fluxuri importante

### **Login ca MASTER**

	1. authenticate() → user alege „Da” la întrebarea „Vrei să te loghezi ca MASTER?”

	2. LoginWindow cere/parolează master password

	3. EncryptionManager(master_password=...) derivă master_key

	4. dacă există FaceID → FaceAuthManager.verify()

	5. mode = "master", current_user = None, user_enc = None

    6. master vede:
       •	toate parolele
       •	toți userii
       •	poate deschide „Useri & parole”
       •	poate face Reset App, Audit HIBP, FaceID, Adaugă user

### **Login ca USER**

	1. authenticate() → user alege „Nu”

	2. _user_login_flow(startup=True):
	   • cere username + parola userului
	   • verifică credențialele în DB
	   • decriptează DEK_user cu get_user_dek_via_user_password
	   • construiește user_enc = EncryptionManager(raw_key=DEK_user)

	3.	mode = "user", current_user = user, master_key = None

	4.	userul vede doar parolele lui și poate:
	   • să le adauge / actualizeze / șteargă
	   • să le verifice în HIBP
	   • nu poate crea useri, nu poate reseta aplicația, nu poate umbla la FaceID

---

## `modules/api_check.py`

Acest modul realizează integrarea cu **Have I Been Pwned (HIBP)** pentru verificarea parolelor împotriva listelor publice de parole compromise.

Modulul implementează un mecanism sigur de interogare a API-ului folosind **k-anonymity**, trimițând doar primele 5 caractere din hash-ul SHA-1 al parolei.

---

### Funcția principală

#### `pwned_count(password: str) -> int`

Verifică dacă parola dată a apărut în breșe publice.  
Întoarce:

- `0` → parola nu apare în HIBP  
- `> 0` → numărul de apariții în baze de date compromise

---

### Cum funcționează

1. Parola este hash-uită cu **SHA-1** și convertită la uppercase:
   ```python
   sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
   prefix, suffix = sha1[:5], sha1[5:]

2.	Hash-ul este împărțit în:

- fix – primele 5 caractere
- fix – restul hash-ului

3.	Aplicația trimite la HIBP doar prefixul:

- `GET https://api.pwnedpasswords.com/range/<PREFIX>`

4.	Serverul trimite înapoi toate hash-urile compromise cu acel prefix.


5. Aplicația caută local sufixul complet și extrage numărul de apariții.

---

## `modules/auth.py`

Acest modul gestionează **parola master** a aplicației.  
Este responsabil pentru:

- crearea primei parole master (prima rulare a aplicației)
- verificarea parolei master introduse de utilizator
- stocarea hash-ului parolei master în `data/auth.json`
- resetarea parolei master
- furnizarea unor funcții auxiliare pentru GUI (setare/parolare master fără terminal)

Modulul **NU stochează niciodată parola în clar** — doar hash-ul SHA-256.

---

## Componente principale

### 1. Funcția `ask_secret(prompt: str) -> str`

Această funcție citește o parolă din terminal în mod securizat:

- folosește `pwinput` dacă este disponibil (afişează `*****`)
- altfel folosește `getpass()` cu avertismente suprimate

Este folosită doar în modul CLI sau situații fallback; aplicația GUI nu o folosește.

---

## Clasa `AuthManager`

Aceasta este clasa centrală a modulului. Gestionează întreaga logică de autentificare master.

### Atribute:

- `auth_file_path` – calea către fișierul `data/auth.json`
- `master_hash` – hash-ul parolei master încărcat din fișier

---

### `__init__(self, auth_file_path="data/auth.json")`

- verifică dacă fișierul `auth.json` există
- dacă da, încarcă `master_hash`
- dacă fișierul lipsește sau este corupt → master va trebui recreat

---

### `has_master() -> bool`

Returnează `True` dacă există un master password valid.

Folosit de GUI pentru a decide dacă trebuie să afișeze:

- **ecranul de configurare master** (prima instalare)
- sau **ecranul de autentificare master**

---

### `set_new_master(password: str)`

Folosit STRICT de interfața GUI.

- calculează hash-ul SHA-256 pentru parola master
- îl stochează în `data/auth.json`
- suprascrie orice master anterior

---

### `_hash_password(self, password: str) -> str`

Funcție internă:

- folosește SHA-256
- convertește parola într-o formă ireversibilă
- NU folosește salt — în acest proiect este acceptabil, deoarece hash-ul NU este folosit pentru criptarea datelor (criptarea reală se face cu cheia derivată ulterior)

---

### `setup_master_password(self) -> str`

Funcție folosită doar pentru modul CLI.

Etape:

1. cere utilizatorului parola master de două ori
2. verifică dacă se potrivesc
3. calculează hash-ul
4. îl salvează în `data/auth.json`
5. returnează parola în clar (pentru a fi folosită imediat la criptarea datelor)

---

### `check_password(self, password: str) -> bool`

Compară o parolă introdusă cu hash-ul salvat.

Folosit de GUI în `LoginWindow`

---

### `verify_master_password(self) -> str`

Funcție CLI pentru verificarea parolei:

- Permite 3 încercări
- Parola este corectă → o returnează în clar
- Parola este greșită de 3 ori → aplicația se închide

GUI nu folosește această funcție.

---

### `reset_master_password(self)`

Șterge complet:

- Fișierul auth.json
- Valoarea internă master_hash

Folosire:

- La apăsarea butonului Reset App
- Înainte de configurarea unui nou master

---

## `modules/database.py`

Acest modul gestionează **toată logica de persistare** a aplicației, folosind SQLite ca sistem de stocare. Este unul dintre cele mai importante fișiere ale proiectului.

El se ocupă de:

- inicializarea bazei de date (`users` și `passwords`)
- migrarea automată a coloanelor lipsă
- gestionarea userilor (creare, autentificare, listare)
- gestionarea parolelor (adăugare, citire, căutare, ștergere, update)
- manipularea și accesarea cheilor criptografice DEK per user
- operațiuni de maintenance (resetare completă a bazei de date)

---

##  Structura bazei de date

Modulul creează automat două tabele:

### **Tabela `users`**

| Coloană             | Tip    | Descriere |
|--------------------|--------|-----------|
| id                 | int, PK, autoincrement |
| username           | text, unic |
| password_hash      | text — SHA-256 pentru parola userului |
| role               | 'master' sau 'user' |
| user_key_for_master| blob — DEK_user criptată cu cheia master |
| user_key_for_user  | blob — DEK_user criptată cu parola userului |
| created_at         | datetime, implicit `CURRENT_TIMESTAMP` |

### **Tabela `passwords`**

| Coloană            | Tip    | Descriere |
|-------------------|--------|-----------|
| id                | int, PK, autoincrement |
| service           | text — ex: "gmail.com" |
| username          | text — contul asociat |
| password_encrypted| text — parola criptată |
| notes             | text |
| last_updated      | datetime |
| user_id           | int, FK către `users(id)` |

---

##  Clasa `DatabaseManager`

Aceasta este clasa centrală a modulului și oferă toate operațiile necesare pentru interacțiunea cu baza de date.

### `__init__(db_path="data/database.db")`

- creează dosarul dacă nu există
- deschide conexiunea la SQLite
- creează automat tabelele lipsă

---

##  Inițializarea / Migrarea bazei de date

### `_create_table_if_not_exists()`

- creează tabelele `users` și `passwords` dacă lipsesc
- verifică structura existentă cu `PRAGMA table_info`
- adaugă coloane noi (e.g. `user_key_for_master`, `user_key_for_user`, `user_id`) dacă lipsesc

Astfel, aplicația poate fi actualizată fără a șterge datele.

---

##  Gestionarea userilor

### `create_user(username, password, role="user", master_fernet_key=None) -> int`

Creează un user nou și:

1. Hash-uiește parola userului cu SHA-256
2. Generează **DEK_user** (cheia reală pentru parolele userului)
3. Derivă cheia Fernet din parola userului
4. Dacă master există:
   - criptează DEK_user cu cheia master → `user_key_for_master`
   - criptează DEK_user cu parola userului → `user_key_for_user`
5. Stochează toate datele în baza de date
6. Returnează **ID-ul userului**

---

### `get_user_by_username(username) -> User | None`  
### `get_user_by_id(user_id) -> User | None`

Returnează obiecte `User` definite prin `@dataclass`.

---

### `verify_user_credentials(username, password) -> User | None`

Autentificare user normal (nu master):

- compară hash-ul parolei furnizate cu cel din DB
- returnează `User` dacă autentificarea reușește

---

### `get_all_users() -> List[User]`

Folosit în GUI pentru fereastra **Useri & Parole**.

---

## Gestionarea cheilor DEK

Aceasta este partea „sensibilă” și esențială pentru securitatea aplicației.

### `get_user_dek_via_master(user, master_fernet_key) -> bytes | None`

Master poate decripta DEK_user pentru orice utilizator.

Flux:
1) ia `user_key_for_master`  
2) îl decriptează cu cheia master  
3) întoarce **DEK_user**  

---

### `get_user_dek_via_user_password(user, user_password) -> bytes | None`

Folosit la login user normal:

1. derivă cheia Fernet din parola userului
2. decriptează `user_key_for_user`
3. întoarce **DEK_user**

Fiecare user își poate decripta doar propriile parole.

---

##  Gestionarea parolelor (PasswordEntry)

### `add_entry(entry, user_id) -> int`

Introduce o parolă nouă în tabel.

---

### `get_all_entries() -> List[PasswordEntry]`

Returnează **toate parolele** — utilizată doar de master.

---

### `get_entries_for_user(user_id) -> List[PasswordEntry]`

Returnează parolele aparținând unui anumit user.

---

### `get_entry_owner_id(entry_id) -> int | None`

Returnează ID-ul userului căruia îi aparține o parolă.  
Este necesar în GUI pentru a decide cu ce cheie se face decriptarea.

---

### `get_entry_by_id(entry_id) -> PasswordEntry | None`

Returnează intrarea completă pentru afișare / editare.

---

### `update_entry_password(entry_id, new_encrypted_password)`

Actualizează parola cu una nouă, deja criptată.

---

### `delete_entry(entry_id) -> bool`

Șterge intrarea.

---

##  Căutare parole

### `find_by_service(query) -> List[PasswordEntry]`

Caută în **toate** parolele (doar master o poate folosi).

---

### `find_by_service_for_user(query, user_id)`

Caută în parolele unui user — folosit pentru modul user.

---

##  Maintenance

### `clear_all_entries()`

Șterge doar parolele, păstrând userii.

---

### `reset_database()`

Șterge TOT:

- tabela `passwords`
- tabela `users`
- secvențele autoincrement
- recreează schema de la zero

Folosit de funcția „Reset App” din GUI pentru:

- resetare master
- resetare useri
- resetare FaceID
- resetare bazei de date complet

---

### `close()`

Închide conexiunea SQLite în mod sigur.

---

## `modules/encryption.py`

Acest modul gestionează **toată criptarea și decriptarea** din aplicație.  
Este unul dintre cele mai importante fișiere, deoarece controlează:

- derivarea cheii Fernet din parola master
- generarea cheilor per-user (`DEK_user`)
- criptarea și decriptarea parolelor utilizatorilor
- criptarea/decriptarea cheilor `DEK_user` pentru stocare sigură în baza de date

Modulul folosește **Fernet** (din biblioteca `cryptography`), care oferă:

- criptare simetrică AES în mod CBC
- HMAC SHA-256 pentru integritate
- tokenizare sigură cu timestamp

---

###  Două moduri de funcționare

Clasa `EncryptionManager` poate funcționa în două moduri distincte:

#### 1. Mod MASTER (folosind master password)

    from modules.encryption import EncryptionManager

    enc = EncryptionManager(master_password="parola_master")

- parola master este hash-uită cu SHA-256
- rezultatul (32 bytes) este convertit într-o cheie Fernet
- cheia master poate decripta toate `DEK_user` pentru toți userii

#### 2. Mod USER (folosind `DEK_user`)

    from modules.encryption import EncryptionManager

    enc = EncryptionManager(raw_key=dek_user_bytes)

- `DEK_user` este o cheie aleatorie de 32 de bytes
- NU este derivată din parolă
- este folosită pentru criptarea/decriptarea parolelor unui singur utilizator

Constructorul impune regula: **ori `master_password`, ori `raw_key`, dar nu ambele și nu niciunul** – altfel ridică `ValueError`.

---

###  Constructorul clasei

Semnătura:

    def __init__(self, master_password: str = None, raw_key: bytes = None):

- dacă este furnizat `master_password` → derivează o cheie Fernet din parolă
- dacă este furnizat `raw_key` → îl folosește direct ca bază pentru cheia Fernet
- dacă sunt furnizate ambele sau niciunul → se ridică o excepție (`ValueError`)

---

###  Generarea cheii per-utilizator (`DEK_user`)

Cheia `DEK_user` este cheia „adevărată” cu care sunt criptate parolele unui utilizator.

Metoda statică:

    @staticmethod
    def generate_user_key() -> bytes:
        return os.urandom(32)

Caracteristici:

- 32 bytes (256 bit)
- generată aleatoriu cu `os.urandom`
- nu depinde de parola utilizatorului
- este criptată și stocată în DB sub două forme:
  - `user_key_for_master` – DEK_user criptată cu cheia master
  - `user_key_for_user` – DEK_user criptată cu cheia derivată din parola userului

---

###  Criptarea și decriptarea parolelor

Metodele principale:

    def encrypt(self, plain_text: str) -> str:
        encrypted = self.fernet.encrypt(plain_text.encode())
        return encrypted.decode()

    def decrypt(self, encrypted_text: str) -> str:
        decrypted = self.fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()

- `encrypt` primește text în clar (ex: parola), îl criptează cu Fernet și returnează un string (base64)
- `decrypt` primește textul criptat (string) și returnează parola în clar

Aceste metode sunt folosite în:

- `add_entry` (la salvare parolă nouă)
- `update_entry_password`
- `show_selected` / `reveal_selected`
- verificări HIBP (decriptăm înainte de trimiterea parolei la API)

---

###  Criptarea cheilor `DEK_user` pentru stocare în DB

Pentru a permite atât master-ului, cât și user-ului să acceseze propria cheie `DEK_user`, aceasta este criptată de două ori:

1. cu cheia master → `user_key_for_master`
2. cu cheia derivată din parola userului → `user_key_for_user`

Metodele statice:

    @staticmethod
    def encrypt_key(raw_key: bytes, fernet_key: bytes) -> bytes:
        """
        Criptează DEK_user folosind o cheie Fernet (ex: cheia master derivată).
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

Acestea sunt folosite în `database.py`:

- în `create_user(...)` la generarea `user_key_for_master` și `user_key_for_user`
- în:
  - `get_user_dek_via_master(...)` – master recuperează DEK_user
  - `get_user_dek_via_user_password(...)` – userul își recuperează DEK_user cu parola lui

---

###  Arhitectura cheilor

**Master flow:**

1. userul introduce parola master
2. se derivează `master_fernet_key` cu `EncryptionManager(master_password=...)`
3. `master_fernet_key` decriptează `DEK_user` pentru orice user
4. se poate construi `EncryptionManager(raw_key=dek_user)` pentru a lucra cu parolele acelui user

**User flow:**

1. userul introduce `username` + `parola userului`
2. parola userului este folosită pentru a deriva `user_fernet_key`
3. `user_fernet_key` decriptează `user_key_for_user` → obținem `DEK_user`
4. `EncryptionManager(raw_key=dek_user)` este folosit pentru a cripta/decripta parolele lui

---

## `modules/face_auth.py`

Acest modul se ocupă de **autentificarea facială (FaceID)** pentru parola master.

Folosește:

- `OpenCV` pentru captură video și detecția feței
- `Haar cascade` pentru detectarea feței în cadru
- `LBPHFaceRecognizer` (din `opencv-contrib-python`) pentru recunoaștere facială

Scopul lui este:

- să poată **enrola** fața utilizatorului (master)
- să poată **verifica** fața la login-ul de master

---

### Clasa `FaceAuthManager`

Clasa principală care gestionează tot fluxul de FaceID.

#### Constructor: `__init__(self, model_path: str = "data/face_model/lbph_face.yml")`

- `model_path` – calea unde se salvează modelul antrenat (`.yml`)
- creează folderul `data/face_model` dacă nu există
- încarcă:
  - un **detector de fețe** bazat pe `haarcascade_frontalface_default.xml`
  - un recognizer LBPH, dacă modelul există deja pe disc

Inițial se apelează metoda internă:

- `_load_model()` – dacă fișierul `.yml` există, încarcă modelul în `self.recognizer`

---

### Gestionarea modelului facial

Metode interne:

#### `_load_model(self)`

- verifică dacă `self.model_path` există
- dacă da:
  - creează un recognizer LBPH: `cv2.face.LBPHFaceRecognizer_create()`
  - încarcă modelul din fișier `.read(self.model_path)`
- dacă nu, setează `self.recognizer = None` (nu există încă FaceID salvat)

#### `_save_model(self)`

- dacă `self.recognizer` nu e `None`, salvează modelul la `self.model_path` (`.write()`)

---

### Verificare enrolare

#### `is_enrolled(self) -> bool`

- întoarce `True` dacă există deja un model facial antrenat (`self.recognizer is not None`)
- folosit de GUI pentru a decide dacă trebuie:

  - să ceară sau nu verificare facială la login
  - să ofere opțiunea de „Setează FaceID”

---

### Enrolarea feței

#### `enroll(self, num_samples: int = 20) -> bool`

Pornește camera, detectează fața utilizatorului și antrenează modelul.

- se deschide camera cu:
  
      cap = cv2.VideoCapture(1)

  (indexul camerei poate fi schimbat dacă e nevoie)

- în buclă:

  - se citește cadrul curent
  - se convertește la gri (`cv2.cvtColor`)
  - se detectează fețele cu:

        faces = self.detector.detectMultiScale(
            gray, scaleFactor=1.2, minNeighbors=5, minSize=(80, 80)
        )

  - se desenează un chenar verde în jurul feței pentru feedback vizual
  - textul „Capturi: X/Y” este afișat în colț

- control din tastatură:

  - `ESC` – oprește și anulează enrolarea → întoarce `False`
  - `SPACE` – forțează captură (dacă există față detectată)

- captură automată:

  - când există o față detectată (`len(faces) > 0`) sau la `SPACE`
  - se ia primul bounding box:

        (x, y, w, h) = faces[0]
        roi = gray[y:y+h, x:x+w]
        roi = cv2.resize(roi, (200, 200))

  - se adaugă în lista de imagini:
  
        images.append(roi)
        labels.append(1)  # eticheta 1 = utilizatorul "master"

  - se incrementează `captured` până ajunge la `num_samples`

- la final:

  - dacă nu sunt imagini capturate → `False`
  - altfel:

        recognizer = cv2.face.LBPHFaceRecognizer_create()
        recognizer.train(images, np.array(labels))
        self.recognizer = recognizer
        self._save_model()

    și întoarce `True`

- camera și ferestrele OpenCV sunt închise în `finally`:

      cap.release()
      cv2.destroyAllWindows()

---

### Verificarea feței la login

#### `verify(self, timeout_seconds: int = 10, threshold: float = 70.0) -> bool`

Verifică dacă fața din fața camerei corespunde modelului salvat.

- dacă `self.recognizer` este `None` → nu există model, întoarce `False`
- deschide camera cu `cv2.VideoCapture(1)`
- rulează o buclă până la `timeout_seconds`:

  - citește un frame
  - convertește la gri
  - detectează fețe cu același cascade
  - pentru fiecare față:

        roi = gray[y:y+h, x:x+w]
        roi = cv2.resize(roi, (200, 200))
        label, confidence = self.recognizer.predict(roi)

  - în LBPH:

    - **confidence mai mic = match mai bun**
    - dacă:
      
          label == 1 and confidence < threshold

      atunci:

      - desenează chenar verde
      - afișează text „OK (scor)”
      - închide camera și ferestrele
      - întoarce `True`

    - altfel, desenează chenar roșu + „Respins (scor)”

- se afișează permanent text de status pe imagine (“Caut fata…”, “Respins (…)” etc.)

- dacă utilizatorul apasă `ESC` → verificarea este anulată, returnează `False`

- dacă timpul expiră (`timeout_seconds`) fără match → `False`

---

### Integrare în aplicație

În `main_gui.py`:

- la login ca master:
  - după ce parola master este validă, se verifică:
    
        if face_auth.is_enrolled():
            face_auth.verify()

  - dacă verificarea facială eșuează → aplicația se închide

- la apăsarea butonului „Setează FaceID”:
  - se apelează `face_auth.enroll()`
  - se salvează modelul în fișierul `.yml` din `data/face_model/`

La resetarea aplicației (`Reset App`):

- fișierul de model (`lbph_face.yml`) este șters sau resetat împreună cu userii și parolele.

---

## `modules/password_entry.py`

Acest modul definește clasa **`PasswordEntry`**, care reprezintă o singură înregistrare de parolă din baza de date.  
Este un obiect simplu, model (data class-like), folosit pentru:

- încărcarea datelor din SQLite în obiecte Python
- pregătirea datelor pentru inserare în baza de date
- manipularea și afișarea unui entry într-un mod structurat

Acest modul **nu** știe nimic despre criptare, logare sau GUI — este strict un model de date.

---

##  Clasa `PasswordEntry`

Clasa conține toate câmpurile necesare pentru un entry de parolă:

### Atribute:

- `id` – ID-ul intrării în baza de date (autoincrement, poate fi `None`)
- `service` – numele serviciului (ex: „gmail.com”, „facebook”)
- `username` – username/email folosit la acel serviciu
- `password_encrypted` – parola criptată; parola în clar NU este stocată aici
- `notes` – câmp opțional pentru informații suplimentare
- `last_updated` – timestamp ISO pentru ultima modificare

Constructorul setează automat `last_updated` dacă nu este furnizat.

---

###  Inițializare

    entry = PasswordEntry(
        service="gmail.com",
        username="andrei@gmail.com",
        password_encrypted="gAAAAABk...",
        notes="Parola cont principal"
    )

---

###  Conversie pentru baza de date

#### `to_tuple_db(self)`

Returnează un tuple în ordinea necesară pentru inserarea în SQLite:

    (
        self.service,
        self.username,
        self.password_encrypted,
        self.notes,
        self.last_updated,
    )

Folosit în:

- `DatabaseManager.add_entry(...)`
- `DatabaseManager.update_entry_password(...)`

---

###  Crearea unui obiect dintr-un rând al bazei de date

#### `@staticmethod from_db_row(row: tuple) -> PasswordEntry`

Transformă un rând SQLite într-un obiect Python:

    return PasswordEntry(
        entry_id=row[0],
        service=row[1],
        username=row[2],
        password_encrypted=row[3],
        notes=row[4],
        last_updated=row[5],
    )

Folosit în:

- `get_all_entries()`
- `get_entries_for_user()`
- `find_by_service()`
- `find_by_service_for_user()`

---

###  Reprezentare textuală

#### `__str__(self)`

Returnează o versiune „safe” a obiectului, pentru debugging.

Caracteristici:

- afișează doar primele 10 caractere din parola criptată
- **nu afișează niciodată parola în clar**
- format lizibil, util pentru depanare

Exemplu:

    [ID: 12] gmail.com
    Username: test@gmail.com
    Password(encrypted): gAAAAABk3U...
    Notes: parola importanta
    Last Updated: 2025-01-20T21:33:12

---

## `modules/password_utils.py`

Acest modul conține funcționalități ajutătoare legate de **parole**, necesare pentru password manager:

- generarea de parole aleatoare, configurabile
- estimarea tăriei parolelor prin entropie

Modulul este independent și poate fi folosit atât în GUI, cât și în CLI.

---

## `generate_password(...)`

Funcția generează o parolă aleatorie în funcție de criteriile selectate.

**Semnătură:**

    generate_password(length=16, upper=True, lower=True, digits=True, symbols=True)

**Parametri:**

- `length` – lungimea parolei generate (implicit 16)
- `upper` – include litere mari (A–Z)
- `lower` – include litere mici (a–z)
- `digits` – include cifre (0–9)
- `symbols` – include simboluri (!@#$%^&*... etc.)

**Comportament:**

1. Construiește dinamically lista seturilor de caractere posibile
2. Verifică dacă utilizatorul a ales măcar un tip de caracter  
   - dacă nu → ridică `ValueError("Alege cel puțin un tip de caractere.")`
3. Garantează **cel puțin un caracter** din fiecare set selectat  
4. Completează restul parolei cu caractere aleatoare din toate seturile combinate
5. Amestecă (shuffle) caracterele
6. Returnează parola finală

**Exemplu de utilizare:**

    pwd = generate_password(length=20)
    print(pwd)

---

## `strength_score(pwd: str) -> (int, str)`

Funcția estimează tăria unei parole pe baza **entropiei**, într-un mod rapid și lightweight.

**Returnează:**

- un scor între **0 și 4**
- un label textual:

  - 0 → „Foarte slabă”
  - 1 → „Slabă”
  - 2 → „Mediu”
  - 3 → „Puternică”
  - 4 → „Foarte puternică”

**Cum funcționează:**

1. Identifică tipurile de caractere din parolă:
   - litere mari
   - litere mici
   - cifre
   - simboluri
2. Estimează mărimea setului total de caractere
3. Calculează entropia:

       entropie = lungime * log2(dimensiunea_charsetului)

4. Aplică praguri aproximative:

   - < 28 → foarte slabă
   - < 36 → slabă
   - < 60 → mediu
   - < 80 → puternică
   - ≥ 80 → foarte puternică

**Exemplu:**

    score, label = strength_score("Parola123!")
    print(score, label)

---
