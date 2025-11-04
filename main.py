from getpass import getpass
from modules.auth import AuthManager
from modules.encryption import EncryptionManager
from modules.database import DatabaseManager
from modules.password_entry import PasswordEntry

def show_menu():
    print("\n=== PASSWORD MANAGER ===")
    print("1. Adaugă parolă")
    print("2. Listează toate intrările")
    print("3. Caută după serviciu")
    print("4. Arată parola (decriptează) după ID")
    print("5. Actualizează parola după ID")
    print("6. Șterge intrare după ID")
    print("7. Golește toate intrările (reset ID)")
    print("8. Reset DB (drop & recreate)")
    print("9. Ieșire")
    print("10. Reset complet aplicație (șterge parole + resetează master password)")

def confirm(prompt: str) -> bool:
    ans = input(f"{prompt} [da/nu]: ").strip().lower()
    return ans in ("da", "d", "yes", "y")

def main():
    # 1) Autentificare & cheie de criptare
    auth = AuthManager()  # data/auth.json
    master_password = auth.verify_master_password()
    enc = EncryptionManager(master_password)

    # 2) Baza de date
    db = DatabaseManager()  # data/database.db

    try:
        while True:
            show_menu()
            choice = input("Alege opțiunea: ").strip()

            if choice == "1":
                service = input("Serviciu (ex: gmail.com): ").strip()
                username = input("Username/email: ").strip()
                pw1 = getpass("Parola: ")
                pw2 = getpass("Confirmă parola: ")
                if pw1 != pw2:
                    print("Parolele nu coincid.")
                    continue
                notes = input("Note (opțional): ").strip()

                encrypted = enc.encrypt(pw1)
                entry = PasswordEntry(service, username, encrypted, notes)
                new_id = db.add_entry(entry)
                print(f"[+] Intrare creată cu ID {new_id}.")

            elif choice == "2":
                entries = db.get_all_entries()
                if not entries:
                    print("(nu există intrări)")
                else:
                    print("\nID | Service              | Username               | Last updated")
                    print("---+----------------------+------------------------+---------------------")
                    for e in entries:
                        print(f"{e.id:>2} | {e.service[:20]:<20} | {e.username[:22]:<22} | {e.last_updated}")

            elif choice == "3":
                q = input("Caută (text în numele serviciului): ").strip()
                results = db.find_by_service(q)
                if not results:
                    print("(nimic găsit)")
                else:
                    print("\nID | Service              | Username               | Last updated")
                    print("---+----------------------+------------------------+---------------------")
                    for e in results:
                        print(f"{e.id:>2} | {e.service[:20]:<20} | {e.username[:22]:<22} | {e.last_updated}")

            elif choice == "4":
                try:
                    entry_id = int(input("ID intrare: ").strip())
                except ValueError:
                    print("ID invalid.")
                    continue
                e = db.get_entry_by_id(entry_id)
                if not e:
                    print("Nu există intrarea.")
                    continue
                try:
                    pw_plain = enc.decrypt(e.password_encrypted)
                except Exception as ex:
                    print(f"Nu pot decripta (parolă master greșită sau date corupte). Detalii: {ex}")
                    continue
                print("\n=== DETALII INTRARE ===")
                print(f"Service : {e.service}")
                print(f"Username: {e.username}")
                print(f"Parola  : {pw_plain}")
                print(f"Notes   : {e.notes}")
                print(f"Actualiz: {e.last_updated}")

            elif choice == "5":
                try:
                    entry_id = int(input("ID intrare: ").strip())
                except ValueError:
                    print("ID invalid.")
                    continue
                e = db.get_entry_by_id(entry_id)
                if not e:
                    print("Nu există intrarea.")
                    continue
                new1 = getpass("Parolă nouă: ")
                new2 = getpass("Confirmă: ")
                if new1 != new2:
                    print("Parolele nu coincid.")
                    continue
                enc_new = enc.encrypt(new1)
                db.update_entry_password(entry_id, enc_new)
                print("[✓] Parola a fost actualizată.")

            elif choice == "6":
                try:
                    entry_id = int(input("ID intrare de șters: ").strip())
                except ValueError:
                    print("ID invalid.")
                    continue
                if not confirm("Sigur vrei să ștergi această intrare?"):
                    print("Anulat.")
                    continue
                ok = db.delete_entry(entry_id)
                print("[✓] Șters." if ok else "Nu s-a găsit intrarea.")

            elif choice == "7":
                if not confirm("Atenție: șterge TOT și resetează ID-urile. Continui?"):
                    print("Anulat.")
                    continue
                # Ai nevoie de metoda clear_all_entries() care șterge și sqlite_sequence
                try:
                    db.clear_all_entries()
                    print("[✓] Baza a fost golită și ID-urile resetate.")
                except AttributeError:
                    print("Adaugă în DatabaseManager metoda clear_all_entries() cu reset la sqlite_sequence.")

            elif choice == "8":
                if not confirm("DROP & CREATE tabela passwords. Ești sigur?"):
                    print("Anulat.")
                    continue
                try:
                    db.reset_database()
                    print("[✓] Tabela a fost recreată (ID pornește de la 1).")
                except AttributeError:
                    print("Adaugă în DatabaseManager metoda reset_database().")

            elif choice == "9":
                print("Bye 👋")
                break

            elif choice == "10":
                print("\n⚠️  ATENȚIE — reset complet aplicație ⚠️")
                print("Aceasta va: (1) șterge toate parolele, (2) reseta ID-urile și (3) șterge master password-ul.")
                if not confirm("Ești sigur că vrei să continui?"):
                    print("Anulat.")
                    continue

                # 1) reset DB (drop & recreate)
                try:
                    db.reset_database()
                    print("[✓] Tabela passwords a fost recreată (date șterse).")
                except Exception as e:
                    print(f"⚠️ Eroare la resetarea DB: {e}")

                # 2) șterge fișier auth.json -> forțează re-setup la următoarea pornire
                try:
                    auth.reset_master_password()
                except Exception as e:
                    # fallback: șterge manual fișierul dacă metoda auth nu există / eșuează
                    try:
                        import os
                        if os.path.exists("data/auth.json"):
                            os.remove("data/auth.json")
                            print("[✓] Fișier auth.json sters manual.")
                    except Exception as e2:
                        print(f"⚠️ Nu am putut șterge auth.json: {e2}")
                # 3) Închidem aplicația după reset, forțăm restart manual
                print(
                    "\n✅ Reset complet efectuat. Te rog să repornești aplicația; vei fi întrebat să configurezi un nou master password.")
                break

            else:
                print("Opțiune invalidă.")
    finally:
        db.close()

if __name__ == "__main__":
    main()
