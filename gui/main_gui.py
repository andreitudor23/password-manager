# gui/main_gui.py
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading

# Feature flags
FACE_ID_ENABLED = False  # set True to re-enable FaceID

from modules.api_check import pwned_count
from modules.face_auth import FaceAuthManager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.auth import AuthManager
from modules.encryption import EncryptionManager
from modules.database import DatabaseManager, User
from modules.password_entry import PasswordEntry


class LoginWindow(tk.Toplevel):
    """
    Dialog de login/setup master. Blochează aplicația până când userul
    se autentifică cu succes sau anulează.
    """
    def __init__(self, parent, auth: AuthManager):
        super().__init__(parent)
        self.title("Autentificare master")
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
        self.grab_set()
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

        self.window_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.canvas.bind_all("<Shift-MouseWheel>", self._on_wheel)
        self.canvas.bind_all("<Shift-Button-4>", lambda e: self.canvas.xview_scroll(-3, "units"))
        self.canvas.bind_all("<Shift-Button-5>", lambda e: self.canvas.xview_scroll(3, "units"))
        self.canvas.bind_all("<MouseWheel>", self._maybe_shift_scroll)

    def _on_inner_configure(self, _event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfigure(self.window_id, height=event.height)

    def _on_wheel(self, event):
        delta = event.delta if hasattr(event, "delta") and event.delta else 0
        step = -3 if delta > 0 else 3
        self.canvas.xview_scroll(step, "units")

    def _maybe_shift_scroll(self, event):
        if getattr(event, "state", 0) & 0x0001:
            self._on_wheel(event)

    def add(self, widget, **grid_kwargs):
        col = self.inner.grid_size()[0]
        widget.grid(row=0, column=col, padx=6, pady=6, **grid_kwargs)
        self.after(0, lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

class UsersOverviewWindow(tk.Toplevel):
    """
    Fereastră pentru master: listează userii și parolele lor.
    """
    def __init__(self, parent: "App"):
        super().__init__(parent)
        self.parent = parent
        self.db: DatabaseManager = parent.db

        self.title("Useri & parole")
        self.geometry("900x500")
        self.minsize(800, 400)

        main = ttk.Frame(self, padding=10)
        main.pack(fill="both", expand=True)

        # stânga: lista de useri
        left = ttk.Frame(main)
        left.pack(side="left", fill="y")

        ttk.Label(left, text="Useri:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(0, 4))

        self.users_listbox = tk.Listbox(left, height=12)
        self.users_listbox.pack(fill="y", expand=False)

        self.users = self.db.get_all_users()
        for u in self.users:
            self.users_listbox.insert(tk.END, f"{u.username} ({u.role})")

        self.users_listbox.bind("<<ListboxSelect>>", self.on_user_selected)

        # dreapta: parolele userului selectat
        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))

        ttk.Label(right, text="Parolele utilizatorului selectat:",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(0, 4))

        self.tree = ttk.Treeview(
            right,
            columns=("service", "account", "password", "updated"),
            show="headings",
            height=14
        )
        self.tree.heading("service", text="Service")
        self.tree.heading("account", text="Account username")
        self.tree.heading("password", text="Parolă (decriptată)")
        self.tree.heading("updated", text="Last updated")

        self.tree.column("service", width=200, anchor="w")
        self.tree.column("account", width=200, anchor="w")
        self.tree.column("password", width=220, anchor="w")
        self.tree.column("updated", width=140, anchor="center")

        self.tree.pack(fill="both", expand=True)

        # hint jos
        ttk.Label(
            right,
            text="⏵ Dublu click pe o parolă pentru a o copia în clipboard.",
            foreground="#555"
        ).pack(anchor="w", pady=(4, 0))

        self.tree.bind("<Double-1>", self.on_double_click_entry)

        self.grab_set()
        self.users_listbox.focus_set()

    def on_user_selected(self, _event=None):
        sel = self.users_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        user = self.users[idx]

        # luăm toate parolele acelui user
        entries = self.db.get_entries_for_user(user.id)

        # curățăm tabelul
        for item in self.tree.get_children():
            self.tree.delete(item)

        # pentru fiecare intrare, decriptăm cu logica deja existentă în App
        for e in entries:
            pwd = self.parent._decrypt_entry_password(e)
            if pwd is None:
                pwd_text = "<nu pot decripta>"
            else:
                pwd_text = pwd
            self.tree.insert(
                "",
                "end",
                iid=str(e.id),
                values=(e.service, e.username, pwd_text, e.last_updated)
            )

    def on_double_click_entry(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        item = self.tree.item(iid)
        vals = item.get("values", [])
        if len(vals) < 3:
            return
        pwd = vals[2]
        if not pwd or pwd.startswith("<nu pot"):
            return
        # copiem parola în clipboard-ul principal al aplicației părinte
        self.parent.secure_copy(pwd, seconds=15)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager 🔐")
        self.geometry("820x520")
        self.minsize(780, 480)

        # back-end
        self.auth = AuthManager()
        self.db = DatabaseManager()
        self.face_auth = FaceAuthManager() if FACE_ID_ENABLED else None

        # crypto state
        self.master_key: bytes | None = None          # cheia Fernet derivată din master
        self.user_enc: EncryptionManager | None = None  # EncryptionManager cu DEK_user
        self.mode: str | None = None                  # "master" sau "user"

        # user curent (None = master)
        self.current_user: User | None = None

        # referințe la butoane
        self._btn_set_face = None
        self._btn_update = None
        self._btn_delete = None
        self._btn_audit = None
        self._btn_reset_app = None
        self._btn_user_login = None
        self._btn_new_user = None
        self._btn_new_user = None
        self._btn_users_overview = None

        self.create_widgets()

        # login flow
        self.after(50, self.authenticate)

    # ---------- HIBP helpers ----------
    def _hibp_label(self, count: int | None) -> str:
        if count is None:
            return "—"
        if count == 0:
            return "🟢 OK"
        if count <= 100:
            return f"🟠 {count}"
        return f"🔴 {count}"

    def _update_hibp_cell(self, entry_id: int, count: int | None):
        iid = str(entry_id)
        if iid not in self.tree.get_children():
            return
        vals = list(self.tree.item(iid, "values"))
        while len(vals) < 4:
            vals.append("—")
        vals[3] = self._hibp_label(count)
        self.tree.item(iid, values=tuple(vals))

    # ---------- UI -------------------------------------------------

    def create_widgets(self):
        tb = ScrollableToolbar(self, height=48)
        tb.pack(side="top", fill="x")

        btn_add = ttk.Button(tb.inner, text="Adaugă", command=self.add_entry)
        tb.add(btn_add)

        btn_show = ttk.Button(tb.inner, text="Afișează/Copy", command=self.show_selected)
        tb.add(btn_show)

        btn_reveal = ttk.Button(tb.inner, text="Reveal 10s", command=self.reveal_selected)
        tb.add(btn_reveal)

        self._btn_set_face = ttk.Button(tb.inner, text="Setează FaceID (master)", command=self.setup_face_auth)
        # Dacă FaceID e dezactivat, lăsăm butonul vizibil dar dezactivat (ca să fie clar în demo)
        if not FACE_ID_ENABLED:
            self._btn_set_face["state"] = "disabled"
            self._btn_set_face.configure(text="FaceID dezactivat")
        tb.add(self._btn_set_face)

        self._btn_update = ttk.Button(tb.inner, text="Actualizează", command=self.update_selected)
        tb.add(self._btn_update)

        self._btn_delete = ttk.Button(tb.inner, text="Șterge", command=self.delete_selected)
        tb.add(self._btn_delete)

        self._btn_audit = ttk.Button(tb.inner, text="Audit HIBP", command=self.audit_hibp_all)
        tb.add(self._btn_audit)

        tb.add(ttk.Separator(tb.inner, orient="vertical"))

        tb.add(ttk.Label(tb.inner, text="Caută:"))
        self.search_var = tk.StringVar()
        tb.add(ttk.Entry(tb.inner, textvariable=self.search_var, width=24))
        tb.add(ttk.Button(tb.inner, text="Go", command=self.search))
        tb.add(ttk.Button(tb.inner, text="Reset", command=self.refresh))

        tb.add(ttk.Separator(tb.inner, orient="vertical"))
        tb.add(ttk.Button(tb.inner, text="Check HIBP", command=self.check_selected))
        tb.add(ttk.Button(tb.inner, text="Logout", command=self.logout))

        self._btn_reset_app = ttk.Button(tb.inner, text="Reset App", command=self.reset_app)
        tb.add(self._btn_reset_app)

        tb.add(ttk.Separator(tb.inner, orient="vertical"))

        self._btn_user_login = ttk.Button(tb.inner, text="Login user", command=self.user_login_dialog)
        tb.add(self._btn_user_login)

        self._btn_new_user = ttk.Button(tb.inner, text="Adaugă user", command=self.create_user_dialog)
        tb.add(self._btn_new_user)

        self._btn_users_overview = ttk.Button(tb.inner, text="Useri & parole", command=self.show_users_overview)
        tb.add(self._btn_users_overview)

        self.tree = ttk.Treeview(
            self,
            columns=("service", "username", "updated", "hibp"),
            show="headings",
            height=16
        )

        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("updated", text="Last updated")
        self.tree.heading("hibp", text="HIBP")

        self.tree.column("service", width=260, anchor="w")
        self.tree.column("username", width=260, anchor="w")
        self.tree.column("updated", width=160, anchor="center")
        self.tree.column("hibp", width=90, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tree.bind("<Double-1>", lambda e: self.show_selected())

        self.status = ttk.Label(self, text="—", anchor="w")
        self.status.pack(side="bottom", fill="x", padx=8, pady=(0, 6))

    # ---------- Auth -----------------------------------------------

    def authenticate(self):
        """
        La pornire întrebăm: master sau user?
        - master -> parola master + (FaceID dacă e enrolled)
        - user   -> username + parola userului (fără master, fără FaceID)
        """
        answer = messagebox.askyesno(
            "Mod autentificare",
            "Vrei să te loghezi ca MASTER?\n"
            "Da = autentificare master\nNu = autentificare ca user normal"
        )
        if answer:
            ok = self._master_login_flow()
            if not ok:
                self.destroy()
        else:
            ok = self._user_login_flow(startup=True)
            if not ok:
                self.destroy()

    def _master_login_flow(self) -> bool:
        dlg = LoginWindow(self, self.auth)
        self.wait_window(dlg)
        if not dlg.password:
            return False

        # derivăm cheia master
        master_enc = EncryptionManager(master_password=dlg.password)
        self.master_key = master_enc.key

        # verificare facială (doar pentru master) – poate fi dezactivată din flag
        if FACE_ID_ENABLED and self.face_auth is not None and self.face_auth.is_enrolled():
            ok_face = self.face_auth.verify()
            if not ok_face:
                messagebox.showerror(
                    "Autentificare eșuată",
                    "Verificarea facială nu a reușit.\nAplicația va fi închisă."
                )
                self.master_key = None
                return False

        self.mode = "master"
        self.current_user = None
        self.user_enc = None

        self.update_ui_for_role()
        self.refresh()
        return True

    def _user_login_flow(self, startup: bool = False) -> bool:
        """
        Login doar cu username + parola userului.
        Fără master password, fără FaceID.
        """
        username = simpledialog.askstring("Login user", "Username:", parent=self)
        if not username:
            if startup:
                return False
            return False

        password = simpledialog.askstring("Login user", "Parolă:", show="*", parent=self)
        if password is None:
            if startup:
                return False
            return False

        user = self.db.verify_user_credentials(username, password)
        if not user:
            messagebox.showerror("Eroare", "Credentiale user incorecte.")
            return False

        dek = self.db.get_user_dek_via_user_password(user, password)
        if not dek:
            messagebox.showerror(
                "Eroare cheie",
                "Acest utilizator nu are o cheie de criptare configurată.\n"
                "Cel mai probabil a fost creat înainte de noul sistem.\n"
                "Creează userul din nou din modul master."
            )
            return False

        self.user_enc = EncryptionManager(raw_key=dek)
        self.mode = "user"
        self.current_user = user
        self.master_key = None

        self.update_ui_for_role()
        self.refresh()

        if not startup:
            messagebox.showinfo("Login user", f"Logat ca {user.username} ({user.role}).")
        return True

    def logout(self):
        if not messagebox.askyesno("Logout", "Sigur vrei să te deloghezi?"):
            return
        self.master_key = None
        self.user_enc = None
        self.mode = None
        self.current_user = None
        self.tree.delete(*self.tree.get_children())
        self.status.config(text="Delogat.")
        self.after(100, self.authenticate)

    # ---------- Helpers UI / role ----------------------------------

    def update_ui_for_role(self):
        """
        Master vs user:
        - master:
            * poate vedea toate parolele
            * poate crea useri noi
            * poate face reset & audit & FaceID
            * nu adaugă/actualizează parole pentru useri (doar userii înșiși)
        - user:
            * poate vedea/adăuga/actualiza/șterge DOAR parolele lui
            * nu poate crea useri, nu poate reseta aplicația, nu poate FaceID
        """
        if self.mode == "master":
            title = "Password Manager 🔐 — MASTER"
            if self._btn_set_face:
                self._btn_set_face["state"] = "normal" if FACE_ID_ENABLED else "disabled"
            if self._btn_update:     self._btn_update["state"] = "disabled"
            if self._btn_delete:     self._btn_delete["state"] = "normal"
            if self._btn_audit:      self._btn_audit["state"] = "normal"
            if self._btn_reset_app:  self._btn_reset_app["state"] = "normal"
            if self._btn_new_user:   self._btn_new_user["state"] = "normal"
            if hasattr(self, "_btn_users_overview") and self._btn_users_overview:
                self._btn_users_overview["state"] = "normal"
        elif self.mode == "user":
            title = f"Password Manager 🔐 — {self.current_user.username} ({self.current_user.role})"
            if self._btn_set_face:   self._btn_set_face["state"] = "disabled"
            if self._btn_update:     self._btn_update["state"] = "normal"
            if self._btn_delete:     self._btn_delete["state"] = "normal"
            if self._btn_audit:      self._btn_audit["state"] = "disabled"
            if self._btn_reset_app:  self._btn_reset_app["state"] = "disabled"
            if self._btn_new_user:   self._btn_new_user["state"] = "disabled"
            if hasattr(self, "_btn_users_overview") and self._btn_users_overview:
                self._btn_users_overview["state"] = "disabled"
        else:
            title = "Password Manager 🔐"
        self.title(title)

    def setup_face_auth(self):
        if not FACE_ID_ENABLED or self.face_auth is None:
            messagebox.showinfo("FaceID", "Funcția FaceID este dezactivată temporar.")
            return
        if self.mode != "master":
            messagebox.showwarning("FaceID", "FaceID poate fi setat doar pentru master.")
            return

        if not messagebox.askyesno(
            "Setare FaceID",
            "Aceasta va porni camera și va salva un model al feței tale pe disk.\n"
            "Vrei să continui?"
        ):
            return

        ok = self.face_auth.enroll()
        if ok:
            messagebox.showinfo("Setare FaceID", "Enrolarea facială a reușit.")
        else:
            messagebox.showwarning("Setare FaceID", "Enrolarea facială NU a reușit sau a fost anulată.")

    def user_login_dialog(self):
        """
        Butonul din toolbar:
        - dacă ești în master, trece în modul user (te loghează ca acel user)
        - dacă ești deja user, te lasă să schimbi userul.
        """
        ok = self._user_login_flow(startup=False)
        if not ok:
            return

    def create_user_dialog(self):
        """Creează un user nou (doar din modul master)."""
        if self.mode != "master" or self.master_key is None:
            messagebox.showwarning("Acces restricționat", "Doar master poate crea utilizatori.")
            return

        username = simpledialog.askstring("Adaugă user", "Username nou:", parent=self)
        if not username:
            return
        pw1 = simpledialog.askstring("Adaugă user", "Parolă user:", show="*", parent=self)
        if not pw1:
            return
        pw2 = simpledialog.askstring("Adaugă user", "Confirmă parola user:", show="*", parent=self)
        if pw1 != pw2:
            messagebox.showwarning("Atenție", "Parolele nu coincid.")
            return

        try:
            user_id = self.db.create_user(
                username,
                pw1,
                role="user",
                master_fernet_key=self.master_key
            )
        except Exception as ex:
            messagebox.showerror("Eroare", f"Nu am putut crea userul:\n{ex}")
            return

        messagebox.showinfo("User creat", f"Userul '{username}' a fost creat cu id {user_id}.")

    # ---------- Crypto Helpers -------------------------------------

    def _get_entry_encryption_manager(self, entry_id: int) -> EncryptionManager | None:
        """
        Returnează EncryptionManager corespunzător pentru intrarea dată:
        - user mode  -> self.user_enc
        - master mode -> derivează DEK_user pentru owner-ul intrării
        """
        if self.mode == "user":
            return self.user_enc

        if self.mode == "master":
            if not self.master_key:
                return None
            owner_id = self.db.get_entry_owner_id(entry_id)
            if owner_id is None:
                return None
            user = self.db.get_user_by_id(owner_id)
            if not user:
                return None
            dek = self.db.get_user_dek_via_master(user, self.master_key)
            if not dek:
                return None
            return EncryptionManager(raw_key=dek)

        return None

    def _decrypt_entry_password(self, entry: PasswordEntry) -> str | None:
        enc = self._get_entry_encryption_manager(entry.id)
        if not enc:
            return None
        try:
            return enc.decrypt(entry.password_encrypted)
        except Exception:
            return None

    # ---------- HIBP audit -----------------------------------------

    def audit_hibp_all(self):
        """
        Calculează HIBP pentru toate intrările vizibile:
        - master -> toate intrările (ale tuturor userilor)
        - user   -> doar intrările lui
        """
        if self.mode not in ("master", "user"):
            return

        if self.mode == "master":
            rows = self.db.get_all_entries()
        else:
            rows = self.db.get_entries_for_user(self.current_user.id)

        if not rows:
            messagebox.showinfo("HIBP", "Nu există intrări.")
            return

        if not hasattr(self, "_hibp_cache"):
            self._hibp_cache: dict[int, int | None] = {}

        if hasattr(self, "status"):
            self.status.config(text="Audit HIBP în curs…")

        def worker():
            for e in rows:
                count: int | None = None
                pwd = self._decrypt_entry_password(e)
                if pwd is not None:
                    try:
                        count = pwned_count(pwd)
                    except Exception:
                        count = None

                self._hibp_cache[e.id] = count
                self.after(0, lambda _id=e.id, _c=count: self._update_hibp_cell(_id, _c))

            if hasattr(self, "status"):
                self.after(0, lambda: self.status.config(text="Audit HIBP terminat."))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Refresh + search -----------------------------------

    def refresh(self):
        if not hasattr(self, "_hibp_cache"):
            self._hibp_cache: dict[int, int | None] = {}

        self.tree.delete(*self.tree.get_children())

        if self.mode == "master":
            rows = self.db.get_all_entries()
            who = "master"
        elif self.mode == "user" and self.current_user is not None:
            rows = self.db.get_entries_for_user(self.current_user.id)
            who = self.current_user.username
        else:
            rows = []
            who = "-"

        for e in rows:
            hibp_val = self._hibp_label(self._hibp_cache.get(e.id))
            self.tree.insert(
                "",
                "end",
                iid=str(e.id),
                values=(e.service, e.username, e.last_updated, hibp_val),
            )

        self.status.config(text=f"{len(rows)} intrări (mod: {self.mode or '-'}, user: {who})")

    def search(self):
        q = self.search_var.get().strip()
        if not hasattr(self, "_hibp_cache"):
            self._hibp_cache: dict[int, int | None] = {}

        self.tree.delete(*self.tree.get_children())

        if self.mode == "master":
            if not q:
                rows = self.db.get_all_entries()
            else:
                rows = self.db.find_by_service(q)
            who = "master"
        elif self.mode == "user" and self.current_user is not None:
            if not q:
                rows = self.db.get_entries_for_user(self.current_user.id)
            else:
                rows = self.db.find_by_service_for_user(q, self.current_user.id)
            who = self.current_user.username
        else:
            rows = []
            who = "-"

        for e in rows:
            hibp_val = self._hibp_label(self._hibp_cache.get(e.id))
            self.tree.insert(
                "",
                "end",
                iid=str(e.id),
                values=(e.service, e.username, e.last_updated, hibp_val),
            )

        if q:
            self.status.config(text=f"{len(rows)} rezultate pentru '{q}' (mod: {self.mode or '-'}, user: {who})")
        else:
            self.status.config(text=f"{len(rows)} intrări (mod: {self.mode or '-'}, user: {who})")

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
        if self.mode != "user" or self.user_enc is None or self.current_user is None:
            messagebox.showerror("Eroare", "Poți adăuga parole doar când ești logat ca un user normal.")
            return

        service = simpledialog.askstring("Adaugă", "Serviciu (ex: gmail.com):", parent=self)
        if not service:
            return
        username = simpledialog.askstring("Adaugă", "Username/email:", parent=self)
        if not username:
            return
        pw1 = simpledialog.askstring("Adaugă", "Parolă:", parent=self, show="*")
        if not pw1:
            return
        pw2 = simpledialog.askstring("Adaugă", "Confirmă parola:", parent=self, show="*")
        if pw1 != pw2:
            messagebox.showwarning("Atenție", "Parolele nu coincid.")
            return

        try:
            cnt = pwned_count(pw1)
        except Exception:
            cnt = None

        if cnt is None:
            messagebox.showwarning("HIBP", "Nu am putut verifica HIBP acum (rețea sau limită).")
        elif cnt > 0:
            if not messagebox.askyesno(
                "Parolă compromisă",
                f"Această parolă apare în breșe publice de {cnt} ori.\n"
                f"Recomand schimbarea ei. Vrei totuși să continui?"
            ):
                return
        else:
            messagebox.showinfo("HIBP", "Parola NU apare în breșe publice (HIBP).")

        notes = simpledialog.askstring("Adaugă", "Note (opțional):", parent=self) or ""

        enc_pw = self.user_enc.encrypt(pw1)
        entry = PasswordEntry(service, username, enc_pw, notes)
        new_id = self.db.add_entry(entry, user_id=self.current_user.id)

        def _one_check(eid=new_id, plain=pw1):
            try:
                cnt2 = pwned_count(plain)
            except Exception:
                cnt2 = None
            self._hibp_cache[eid] = cnt2
            self.after(0, lambda: self._update_hibp_cell(eid, cnt2))

        threading.Thread(target=_one_check, daemon=True).start()

        self.refresh()
        messagebox.showinfo("Succes", f"Intrare creată cu ID {new_id}")

    def show_selected(self):
        if self.mode not in ("master", "user"):
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

        pwd = self._decrypt_entry_password(e)
        if pwd is None:
            messagebox.showerror("Eroare", "Nu pot decripta parola pentru această intrare.")
            return

        masked = self.mask_password(pwd)
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
        if self.mode not in ("master", "user"):
            return
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return

        e = self.db.get_entry_by_id(entry_id)
        if not e:
            self.refresh()
            return

        pwd = self._decrypt_entry_password(e)
        if pwd is None:
            messagebox.showerror("Eroare", "Nu pot decripta parola pentru această intrare.")
            return

        top = tk.Toplevel(self)
        top.title("Reveal (10s)")
        top.resizable(False, False)
        top.attributes("-topmost", True)

        container = ttk.Frame(top, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text=f"{e.service} — {e.username}",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(0, 8))

        show_lbl = ttk.Label(container, text=pwd, font=("Courier New", 12))
        show_lbl.pack(anchor="w", pady=(0, 8))

        btn_row = ttk.Frame(container)
        btn_row.pack(fill="x")

        def do_copy():
            self.secure_copy(pwd, seconds=15)

        copy_btn = ttk.Button(btn_row, text="Copy", command=do_copy)
        copy_btn.pack(side="left")

        countdown_lbl = ttk.Label(btn_row, text="Se închide în 10s")
        countdown_lbl.pack(side="right")

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
        if self.mode != "user" or self.user_enc is None or self.current_user is None:
            messagebox.showerror("Eroare", "Actualizarea parolelor se face doar în modul user.")
            return

        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return

        owner_id = self.db.get_entry_owner_id(entry_id)
        if owner_id != self.current_user.id:
            messagebox.showerror("Eroare", "Nu poți modifica o parolă care nu îți aparține.")
            return

        e = self.db.get_entry_by_id(entry_id)
        if not e:
            messagebox.showerror("Eroare", "Intrarea nu mai există.")
            self.refresh()
            return

        new1 = simpledialog.askstring("Actualizează", "Parolă nouă:", parent=self, show="*")
        if not new1:
            return
        new2 = simpledialog.askstring("Actualizează", "Confirmă parola:", parent=self, show="*")
        if new1 != new2:
            messagebox.showwarning("Atenție", "Parolele nu coincid.")
            return

        enc_new = self.user_enc.encrypt(new1)
        self.db.update_entry_password(entry_id, enc_new)
        self.refresh()
        messagebox.showinfo("Succes", "Parola a fost actualizată.")

    def check_selected(self):
        if self.mode not in ("master", "user"):
            return

        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return

        e = self.db.get_entry_by_id(entry_id)
        if not e:
            self.refresh()
            return

        pwd = self._decrypt_entry_password(e)
        if pwd is None:
            messagebox.showerror("Eroare", "Nu pot decripta parola pentru verificare.")
            return

        try:
            cnt = pwned_count(pwd)
        except Exception as ex:
            messagebox.showwarning("HIBP", f"Nu am putut verifica: {ex}")
            return

        if not hasattr(self, "_hibp_cache"):
            self._hibp_cache: dict[int, int | None] = {}
        self._hibp_cache[e.id] = cnt
        self._update_hibp_cell(e.id, cnt)

        if cnt > 0:
            messagebox.showwarning(
                "HIBP",
                f"⚠️ Parola acestui cont apare în breșe de {cnt} ori.\n"
                f"Recomand să o schimbi."
            )
        else:
            messagebox.showinfo("HIBP", "✅ Parola NU apare în HIBP.")

    def delete_selected(self):
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showinfo("Info", "Selectează o intrare.")
            return

        if self.mode == "user":
            owner_id = self.db.get_entry_owner_id(entry_id)
            if owner_id != self.current_user.id:
                messagebox.showerror("Eroare", "Nu poți șterge o parolă care nu îți aparține.")
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
                "Atenție: se vor șterge TOȚI userii, toate parolele,\n"
                "se va reseta master password și se vor șterge modelele FaceID.\n"
                "Continui?"
        ):
            return

        # 1) baza de date (useri + parole)
        try:
            self.db.reset_database()
        except Exception as e:
            messagebox.showerror("Eroare DB", f"Eroare la resetarea bazei de date:\n{e}")
            return

        # 2) auth master (fișierul cu hash-ul parolei master)
        try:
            self.auth.reset_master_password()
        except Exception as e:
            messagebox.showwarning("Avertisment", f"Nu am putut reseta complet auth: {e}")
            try:
                if os.path.exists("data/auth.json"):
                    os.remove("data/auth.json")
            except Exception:
                pass

        # 3) FaceID / model facial (opțional)
        try:
            if self.face_auth is not None:
                # dacă FaceAuthManager are o metodă reset, o folosim
                if hasattr(self.face_auth, "reset"):
                    self.face_auth.reset()
                else:
                    # fallback: dacă există vreo cale de fișier în obiect, încercăm s-o ștergem
                    for attr in ("template_path", "model_path", "db_path", "MODEL_PATH"):
                        path = getattr(self.face_auth, attr, None)
                        if path:
                            try:
                                os.remove(str(path))
                            except FileNotFoundError:
                                pass
        except Exception:
            # nu blocăm resetul aplicației dacă ceva nu merge aici
            pass

        messagebox.showinfo("Reset", "Reset complet. Aplicația se va reloga.")
        self.logout()

    # -------- Password helpers --------
    def mask_password(self, pwd: str) -> str:
        return "•" * len(pwd)

    def secure_copy(self, text: str, seconds: int = 15):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self.status.config(text=f"Parolă copiată în clipboard ({seconds}s)")

        def _clear():
            try:
                if self.clipboard_get() == text:
                    self.clipboard_clear()
                    self.update()
            except Exception:
                pass
            self.status.config(text="Clipboard curățat.")
        self.after(seconds * 1000, _clear)

    def show_users_overview(self):
        """Disponibil doar pentru master: listă useri + parolele lor."""
        if self.mode != "master" or self.master_key is None:
            messagebox.showwarning("Acces restricționat", "Trebuie să fii logat ca MASTER.")
            return
        UsersOverviewWindow(self)


if __name__ == "__main__":
    app = App()
    app.mainloop()