# gui/main_gui.py
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from modules.api_check import pwned_count

# permite importuri din proiect când rulezi ca script
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.auth import AuthManager
from modules.encryption import EncryptionManager
from modules.database import DatabaseManager
from modules.password_entry import PasswordEntry


class LoginWindow(tk.Toplevel):
    """
    Dialog de login/setup master. Blochează aplicația până când userul
    se autentifică cu succes sau anulează.
    """
    def __init__(self, parent, auth: AuthManager):
        super().__init__(parent)
        self.title("Autentificare")
        self.resizable(False, False)
        self.auth = auth
        self.password = None

        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

        frm = ttk.Frame(self, padding=14)
        frm.grid(row=0, column=0)

        if self.auth.has_master():
            ttk.Label(frm, text="Introdu parola master:").grid(row=0, column=0, sticky="w")
            self.e1 = ttk.Entry(frm, show="*")
            self.e1.grid(row=1, column=0, sticky="ew", pady=(2, 8))
            ttk.Button(frm, text="Autentifică", command=self.on_login).grid(row=2, column=0, sticky="ew")
        else:
            ttk.Label(frm, text="Configurează master password (prima rulare)").grid(row=0, column=0, sticky="w")
            self.e1 = ttk.Entry(frm, show="*")
            self.e2 = ttk.Entry(frm, show="*")
            self.e1.grid(row=1, column=0, sticky="ew", pady=(2, 4))
            self.e2.grid(row=2, column=0, sticky="ew", pady=(0, 8))
            self.e1.insert(0, "")
            ttk.Button(frm, text="Setează", command=self.on_setup).grid(row=3, column=0, sticky="ew")

        frm.columnconfigure(0, weight=1)
        self.grab_set()  # modal
        self.e1.focus_set()

    def on_login(self):
        pw = self.e1.get()
        if self.auth.check_password(pw):
            self.password = pw
            self.destroy()
        else:
            messagebox.showerror("Eroare", "Parolă master incorectă.")

    def on_setup(self):
        pw1 = self.e1.get().strip()
        pw2 = self.e2.get().strip()
        if len(pw1) < 6:
            messagebox.showwarning("Atenție", "Parola trebuie să aibă cel puțin 6 caractere.")
            return
        if pw1 != pw2:
            messagebox.showwarning("Atenție", "Parolele nu coincid.")
            return
        self.auth.set_new_master(pw1)
        self.password = pw1
        self.destroy()

    def on_cancel(self):
        if messagebox.askyesno("Confirmare", "Închizi aplicația?"):
            self.password = None
            self.destroy()

class ScrollableToolbar(ttk.Frame):
    """
    Toolbar orizontal scrollabil: butoanele se pun în self.inner.
    Scroll cu bara sau cu Shift + scroll (rotiță/trackpad).
    """
    def __init__(self, master, height=44, **kwargs):
        super().__init__(master, **kwargs)
        self.canvas = tk.Canvas(self, height=height, highlightthickness=0)
        self.hbar = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.inner = ttk.Frame(self.canvas)

        self.canvas.configure(xscrollcommand=self.hbar.set)
        self.canvas.pack(side="top", fill="x", expand=True)
        self.hbar.pack(side="bottom", fill="x")

        # creează containerul pentru frame-ul interior
        self.window_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        # menține scrollregion corect
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # scroll orizontal cu Shift + rotiță (Win/macOS)
        self.canvas.bind_all("<Shift-MouseWheel>", self._on_wheel)
        # Linux X11 (buton 4/5 când e ținut Shift)
        self.canvas.bind_all("<Shift-Button-4>", lambda e: self.canvas.xview_scroll(-3, "units"))
        self.canvas.bind_all("<Shift-Button-5>", lambda e: self.canvas.xview_scroll( 3, "units"))

        # fallback: dacă utilizatorul ține Shift, tratează orice MouseWheel ca orizontal
        self.canvas.bind_all("<MouseWheel>", self._maybe_shift_scroll)

    # ---- helpers ----
    def _on_inner_configure(self, _event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        # menținem doar înălțimea; lățimea rămâne naturală (poate depăși canvasul)
        self.canvas.itemconfigure(self.window_id, height=event.height)

    def _on_wheel(self, event):
        """
        Scroll orizontal. Pe Windows/macOS event.delta e +/-120, pe macOS poate fi fracționat.
        """
        delta = event.delta if hasattr(event, "delta") and event.delta else 0
        # direcție: rola sus (delta>0) -> scroll stânga
        step = -3 if delta > 0 else 3
        self.canvas.xview_scroll(step, "units")

    def _maybe_shift_scroll(self, event):
        # dacă e apăsat Shift, redirecționează către scroll orizontal
        # (masca de state pentru Shift e 0x0001 în Tk)
        if getattr(event, "state", 0) & 0x0001:
            self._on_wheel(event)

    def add(self, widget, **grid_kwargs):
        """Adaugă un widget în primul rând, coloana următoare."""
        col = self.inner.grid_size()[0]
        widget.grid(row=0, column=col, padx=6, pady=6, **grid_kwargs)
        self.after(0, lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all")))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager 🔐")
        self.geometry("820x520")
        self.minsize(780, 480)

        # back-end
        self.auth = AuthManager()        # data/auth.json
        self.db = DatabaseManager()      # data/database.db
        self.enc: EncryptionManager | None = None

        # UI: toolbar + search + tree + buttons
        self.create_widgets()

        # login flow
        self.after(50, self.authenticate)

    # ---------- UI -------------------------------------------------
    def create_widgets(self):
        """
        # Toolbar
        tb = ttk.Frame(self, padding=(8, 6))
        tb.pack(side="top", fill="x")

        ttk.Button(tb, text="Adaugă", command=self.add_entry).pack(side="left", padx=(0, 6))
        #ttk.Button(tb, text="Afișează/Copy", command=self.show_selected).pack(side="left", padx=6)
        ttk.Button(tb, text="Afișează (mascat) / Copy", command=self.show_selected).pack(side="left", padx=6)
        # buton de reveal
        ttk.Button(tb, text="Reveal 10s", command=self.reveal_selected).pack(side="left", padx=6)

        ttk.Button(tb, text="Actualizează", command=self.update_selected).pack(side="left", padx=6)
        ttk.Button(tb, text="Șterge", command=self.delete_selected).pack(side="left", padx=6)

        ttk.Separator(tb, orient="vertical").pack(side="left", fill="y", padx=10)

        ttk.Label(tb, text="Caută:").pack(side="left")
        self.search_var = tk.StringVar()
        e = ttk.Entry(tb, textvariable=self.search_var, width=24)
        e.pack(side="left", padx=6)
        ttk.Button(tb, text="Go", command=self.search).pack(side="left")
        ttk.Button(tb, text="Reset", command=self.refresh).pack(side="left", padx=6)
        ttk.Button(tb, text="Check HIBP", command=self.check_selected).pack(side="left", padx=6)

        ttk.Separator(tb, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(tb, text="Logout", command=self.logout).pack(side="left")
        ttk.Button(tb, text="Reset App", command=self.reset_app).pack(side="left", padx=6)
        """
        # Toolbar scrollabil
        tb = ScrollableToolbar(self, height=48)
        tb.pack(side="top", fill="x")

        # Adaugă butoanele exact ca înainte, dar prin tb.add(...)
        tb.add(ttk.Button(tb.inner, text="Adaugă", command=self.add_entry))
        tb.add(ttk.Button(tb.inner, text="Afișează/Copy", command=self.show_selected))
        tb.add(ttk.Button(tb.inner, text="Reveal 10s", command=self.reveal_selected))
        tb.add(ttk.Button(tb.inner, text="Actualizează", command=self.update_selected))
        tb.add(ttk.Button(tb.inner, text="Șterge", command=self.delete_selected))

        # separator vizual (poți folosi și un label „|” mic)
        tb.add(ttk.Separator(tb.inner, orient="vertical"))

        # căutare
        tb.add(ttk.Label(tb.inner, text="Caută:"))
        self.search_var = tk.StringVar()
        tb.add(ttk.Entry(tb.inner, textvariable=self.search_var, width=24))
        tb.add(ttk.Button(tb.inner, text="Go", command=self.search))
        tb.add(ttk.Button(tb.inner, text="Reset", command=self.refresh))

        tb.add(ttk.Separator(tb.inner, orient="vertical"))
        tb.add(ttk.Button(tb.inner, text="Check HIBP", command=self.check_selected))
        tb.add(ttk.Button(tb.inner, text="Logout", command=self.logout))
        tb.add(ttk.Button(tb.inner, text="Reset App", command=self.reset_app))

        # Tree
        self.tree = ttk.Treeview(self, columns=("service", "username", "updated"), show="headings", height=16)
        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("updated", text="Last updated")
        self.tree.column("service", width=240)
        self.tree.column("username", width=240)
        self.tree.column("updated", width=180)
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.status = ttk.Label(self, text="—", anchor="w")
        self.status.pack(side="bottom", fill="x", padx=8, pady=(0, 6))

        self.tree.bind("<Double-1>", lambda e: self.show_selected())

    # ---------- Auth -----------------------------------------------
    def authenticate(self):
        dlg = LoginWindow(self, self.auth)
        self.wait_window(dlg)
        if not dlg.password:
            self.destroy()
            return
        self.enc = EncryptionManager(dlg.password)
        self.refresh()

    def logout(self):
        if messagebox.askyesno("Logout", "Sigur vrei să te deloghezi?"):
            self.enc = None
            self.tree.delete(*self.tree.get_children())
            self.status.config(text="Delogat.")
            self.after(100, self.authenticate)

    # ---------- Helpers --------------------------------------------
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        rows = self.db.get_all_entries()
        for e in rows:
            self.tree.insert("", "end", iid=str(e.id), values=(e.service, e.username, e.last_updated))
        self.status.config(text=f"{len(rows)} intrări")

    def search(self):
        q = self.search_var.get().strip()
        if not q:
            self.refresh()
            return
        self.tree.delete(*self.tree.get_children())
        rows = self.db.find_by_service(q)
        for e in rows:
            self.tree.insert("", "end", iid=str(e.id), values=(e.service, e.username, e.last_updated))
        self.status.config(text=f"{len(rows)} rezultate pentru '{q}'")

    def get_selected_id(self) -> int | None:
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except ValueError:
            return None

    # ---------- Actions --------------------------------------------
    def add_entry(self):
        if self.enc is None:
            messagebox.showerror("Eroare", "Nu ești autentificat.")
            return
        service = simpledialog.askstring("Adaugă", "Serviciu (ex: gmail.com):", parent=self)
        if not service: return
        username = simpledialog.askstring("Adaugă", "Username/email:", parent=self)
        if not username: return
        pw1 = simpledialog.askstring("Adaugă", "Parolă:", parent=self, show="*")
        if not pw1: return
        pw2 = simpledialog.askstring("Adaugă", "Confirmă parola:", parent=self, show="*")
        if pw1 != pw2:
            messagebox.showwarning("Atenție", "Parolele nu coincid.")
            return
        try:
            cnt = pwned_count(pw1)
        except Exception as e:
            cnt = None  # rețea căzută etc.

        if cnt is None:
            messagebox.showwarning("HIBP", "Nu am putut verifica HIBP acum (rețea sau limită).")
        elif cnt > 0:
            if not messagebox.askyesno(
                    "Parolă compromisă",
                    f"Această parolă apare în breșe publice de {cnt} ori.\n"
                    f"Recomand schimbarea ei. Vrei totuși să continui?"
            ):
                return
        else:  # cnt == 0
            messagebox.showinfo("HIBP", "Parola NU apare în breșe publice (HIBP).")
        notes = simpledialog.askstring("Adaugă", "Note (opțional):", parent=self) or ""

        enc_pw = self.enc.encrypt(pw1)
        entry = PasswordEntry(service, username, enc_pw, notes)
        new_id = self.db.add_entry(entry)
        self.refresh()
        messagebox.showinfo("Succes", f"Intrare creată cu ID {new_id}")

    def show_selected(self):
        if self.enc is None:
            return
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare din listă.")
            return
        e = self.db.get_entry_by_id(entry_id)
        if not e:
            messagebox.showerror("Eroare", "Intrarea nu mai există.")
            self.refresh()
            return

        try:
            pwd = self.enc.decrypt(e.password_encrypted)
        except Exception as ex:
            messagebox.showerror("Eroare", f"Nu pot decripta (cheie greșită/date corupte).\n{ex}")
            return

        masked = self.mask_password(pwd)
        # Afișăm doar mascat + oferim Copy (fără să arătăm plaintext)
        txt = (
            f"Service : {e.service}\n"
            f"Username: {e.username}\n"
            f"Parola  : {masked}\n"
            f"Notes   : {e.notes}\n"
            f"Updated : {e.last_updated}"
        )
        if messagebox.askyesno("Parolă (mascată)", txt + "\n\nCopiază parola în clipboard?"):
            self.secure_copy(pwd, seconds=15)

    def reveal_selected(self):
        """Afișează parola în clar într-o fereastră care se închide automat după 10s."""
        if self.enc is None:
            return
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return

        e = self.db.get_entry_by_id(entry_id)
        if not e:
            self.refresh()
            return

        try:
            pwd = self.enc.decrypt(e.password_encrypted)
        except Exception as ex:
            messagebox.showerror("Eroare", f"Nu pot decripta parola.\n{ex}")
            return

        top = tk.Toplevel(self)
        top.title("Reveal (10s)")
        top.resizable(False, False)
        top.attributes("-topmost", True)

        container = ttk.Frame(top, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text=f"{e.service} — {e.username}",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(0, 8))

        # afișează parola în clar (monospace ca să fie lizibilă)
        show_lbl = ttk.Label(container, text=pwd, font=("Courier New", 12))
        show_lbl.pack(anchor="w", pady=(0, 8))

        # Copy + countdown
        btn_row = ttk.Frame(container)
        btn_row.pack(fill="x")

        def do_copy():
            self.secure_copy(pwd, seconds=15)

        copy_btn = ttk.Button(btn_row, text="Copy", command=do_copy)
        copy_btn.pack(side="left")

        countdown_lbl = ttk.Label(btn_row, text="Se închide în 10s")
        countdown_lbl.pack(side="right")

        # countdown + auto close la 10s
        seconds = 10

        def tick():
            nonlocal seconds
            seconds -= 1
            if seconds <= 0:
                if top.winfo_exists():
                    top.destroy()
                return
            countdown_lbl.config(text=f"Se închide în {seconds}s")
            top.after(1000, tick)

        top.after(1000, tick)

    def update_selected(self):
        if self.enc is None:
            return
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return
        e = self.db.get_entry_by_id(entry_id)
        if not e:
            messagebox.showerror("Eroare", "Intrarea nu mai există.")
            self.refresh()
            return
        new1 = simpledialog.askstring("Actualizează", "Parolă nouă:", parent=self, show="*")
        if not new1: return
        new2 = simpledialog.askstring("Actualizează", "Confirmă parola:", parent=self, show="*")
        if new1 != new2:
            messagebox.showwarning("Atenție", "Parolele nu coincid.")
            return
        enc_new = self.enc.encrypt(new1)
        self.db.update_entry_password(entry_id, enc_new)
        self.refresh()
        messagebox.showinfo("Succes", "Parola a fost actualizată.")

    def check_selected(self):
        if self.enc is None:
            return
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return
        e = self.db.get_entry_by_id(entry_id)
        if not e:
            self.refresh()
            return
        try:
            pwd = self.enc.decrypt(e.password_encrypted)
        except Exception as ex:
            messagebox.showerror("Eroare", f"Nu pot decripta parola pentru verificare.\n{ex}")
            return

        try:
            cnt = pwned_count(pwd)
        except Exception as ex:
            messagebox.showwarning("HIBP", f"Nu am putut verifica: {ex}")
            return

        if cnt > 0:
            messagebox.showwarning("HIBP",
                f"⚠️ Parola acestui cont apare în breșe de {cnt} ori.\n"
                f"Recomand să o schimbi.")
        else:
            messagebox.showinfo("HIBP", "✅ Parola NU apare în HIBP.")


    def delete_selected(self):
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return
        if not messagebox.askyesno("Confirmare", "Ștergi intrarea selectată?"):
            return
        ok = self.db.delete_entry(entry_id)
        self.refresh()
        if ok:
            messagebox.showinfo("Șters", "Intrarea a fost ștearsă.")
        else:
            messagebox.showerror("Eroare", "Nu am putut șterge intrarea.")

    def reset_app(self):
        if not messagebox.askyesno(
            "Reset aplicație",
            "Atenție: se vor șterge toate parolele și se va reseta master password.\nContinui?"
        ):
            return
        try:
            self.db.reset_database()
        except Exception as e:
            messagebox.showerror("Eroare DB", str(e))
            return
        try:
            self.auth.reset_master_password()
        except Exception as e:
            messagebox.showwarning("Avertisment", f"Nu am putut reseta complet auth: {e}")
            # fallback manual
            try:
                if os.path.exists("data/auth.json"):
                    os.remove("data/auth.json")
            except Exception:
                pass
        messagebox.showinfo("Reset", "Reset complet. Aplicația se va reloga.")
        self.logout()

    # -------- Password helpers --------
    def mask_password(self, pwd: str) -> str:
        # arată aceeași lungime, dar mascat (bullet)
        return "•" * len(pwd)

    def secure_copy(self, text: str, seconds: int = 15):
        """Copiază în clipboard și îl curăță automat după N secunde."""
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self.status.config(text=f"Parolă copiată în clipboard ({seconds}s)")

        def _clear():
            # dacă între timp userul a copiat altceva, nu-l ștergem
            try:
                if self.clipboard_get() == text:
                    self.clipboard_clear()
                    self.update()
            except Exception:
                pass
            self.status.config(text="Clipboard curățat.")
        self.after(seconds * 1000, _clear)



if __name__ == "__main__":
    app = App()
    app.mainloop()
