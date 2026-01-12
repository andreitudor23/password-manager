# 🔐 Password Manager — Aplicație completă de gestionare a parolelor - Python 3.13


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

##  Ghid de instalare și rulare

Acest ghid explică pașii necesari pentru a instala și rula aplicația **Password Manager** pe un sistem local.

---

##  Cerințe preliminare

Asigură-te că ai instalate următoarele:

- **Python 3.13** 
- **pip** 
- **Git** 
- Cameră web funcțională (opțional, pentru FaceID)

### Verificare versiune Python

    python --version
    sau
    python3 --version

---

##  Descărcarea proiectului

### Varianta 1 – Clonare cu Git 

    git clone https://github.com/<username>/<repository>.git
    cd password-manager

### Varianta 2 – Descărcare ZIP

1. Descarcă arhiva ZIP din GitHub
2. Dezarhivează proiectul
3. Deschide folderul proiectului într-un terminal

---

##  Crearea unui mediu virtual (venv)


### Windows

    python -m venv .venv
    .venv\Scripts\activate

### macOS / Linux

    python3 -m venv .venv
    source .venv/bin/activate

---

##  Instalarea dependențelor

Instalează toate librăriile necesare:

    pip install -r requirements.txt

### Dependențe principale

- cryptography==42.0.5
- requests==2.31.0
- pwinput==1.0.3
- customtkinter==5.2.2
- opencv-contrib-python==4.12.0.88
- numpy==2.2.6

---

## Rularea aplicației

Din folderul principal al proiectului:

    python -m gui.main_gui

Aplicația va porni în interfața grafică.

---

## Prima rulare

La prima pornire:

1. Vei fi rugat să setezi **parola master**
2. Poți opta ulterior pentru:
   - înregistrarea FaceID (opțional)
   - crearea de utilizatori normali
3. Baza de date și fișierele de configurare vor fi create automat în folderul `data/`

---

## Resetarea aplicației

Din interfața GUI (doar MASTER):

- opțiunea **Reset App** șterge:
  - toți utilizatorii
  - toate parolele
  - parola master
  - datele FaceID

Aplicația revine la starea de „prima rulare”.

---





