# gui/main_gui.py
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading

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

class UserChoiceWindow(tk.Toplevel):
    """
    Fereastră care îți arată utilizatorii existenți și îți permite să alegi
    ca cine vrei să lucrezi (master sau un user normal).
    NU verifică parole aici, doar alege identitatea.
    """
    def __init__(self, parent, db: DatabaseManager):
        super().__init__(parent)
        self.title("Alege utilizator")
        self.resizable(False, False)

        self.db = db
        self.selected_user: User | None = None
        self.cancelled = False

        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        ttk.Label(frm, text="Alege cu ce utilizator vrei să deschizi aplicația:").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )

        # listă de useri
        self.listbox = tk.Listbox(frm, height=6)
        self.listbox.grid(row=1, column=0, columnspan=2, sticky="nsew")

        # primul element: master
        self.listbox.insert(tk.END, "Master (admin)")
        self.users = self.db.get_all_users()  # list[User]

        for u in self.users:
            self.listbox.insert(tk.END, f"{u.username} ({u.role})")

        self.listbox.selection_set(0)
        self.listbox.bind("<Double-1>", lambda e: self.on_ok())

        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=(8, 0), sticky="e")

        ttk.Button(btn_frame, text="Anulează", command=self.on_cancel).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Continuă", command=self.on_ok).pack(side="right")

        frm.rowconfigure(1, weight=1)
        frm.columnconfigure(0, weight=1)

        self.grab_set()
        self.listbox.focus_set()

    def on_ok(self):
        sel = self.listbox.curselection()
        if not sel:
            self.selected_user = None
        else:
            idx = sel[0]
            if idx == 0:
                # Master
                self.selected_user = None
            else:
                # users[idx-1] (pentru că 0 e Master)
                self.selected_user = self.users[idx - 1]
        self.destroy()

    def on_cancel(self):
        # dacă anulezi, considerăm că vrei să închizi aplicația
        self.cancelled = True
        self.selected_user = None
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
        self.canvas.bind_all("<Shift-Button-5>", lambda e: self.canvas.xview_scroll(3, "units"))

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
        self.face_auth = FaceAuthManager()
        self.enc: EncryptionManager | None = None

        # user curent (None = master / vede tot)
        self.current_user: User | None = None

        # vom păstra referințe la anumite butoane ca să le putem activa/dezactiva
        self._btn_set_face = None
        self._btn_update = None
        self._btn_delete = None
        self._btn_audit = None
        self._btn_reset_app = None
        self._btn_user_login = None
        self._btn_new_user = None

        # UI: toolbar + search + tree + status
        self.create_widgets()

        # login flow
        self.after(50, self.authenticate)

    # ---------- HIBP helpers ----------
    def _hibp_label(self, count: int | None) -> str:
        """Etichetă frumoasă pentru coloana HIBP."""
        if count is None:
            return "—"
        if count == 0:
            return "🟢 OK"
        if count <= 100:
            return f"🟠 {count}"
        return f"🔴 {count}"

    def _update_hibp_cell(self, entry_id: int, count: int | None):
        """Actualizează doar coloana HIBP pentru rândul cu id-ul dat."""
        iid = str(entry_id)
        if iid not in self.tree.get_children():
            return
        vals = list(self.tree.item(iid, "values"))
        # ne asigurăm că avem 4 coloane
        while len(vals) < 4:
            vals.append("—")
        vals[3] = self._hibp_label(count)
        self.tree.item(iid, values=tuple(vals))

    # ---------- UI -------------------------------------------------

    def create_widgets(self):
        # Toolbar scrollabil
        tb = ScrollableToolbar(self, height=48)
        tb.pack(side="top", fill="x")

        # butoane principale
        btn_add = ttk.Button(tb.inner, text="Adaugă", command=self.add_entry)
        tb.add(btn_add)

        btn_show = ttk.Button(tb.inner, text="Afișează/Copy", command=self.show_selected)
        tb.add(btn_show)

        btn_reveal = ttk.Button(tb.inner, text="Reveal 10s", command=self.reveal_selected)
        tb.add(btn_reveal)

        self._btn_set_face = ttk.Button(tb.inner, text="Seteaza FaceID", command=self.setup_face_auth)
        tb.add(self._btn_set_face)

        self._btn_update = ttk.Button(tb.inner, text="Actualizează", command=self.update_selected)
        tb.add(self._btn_update)

        self._btn_delete = ttk.Button(tb.inner, text="Șterge", command=self.delete_selected)
        tb.add(self._btn_delete)

        self._btn_audit = ttk.Button(tb.inner, text="Audit HIBP", command=self.audit_hibp_all)
        tb.add(self._btn_audit)

        # separator vizual
        tb.add(ttk.Separator(tb.inner, orient="vertical"))

        # căutare
        tb.add(ttk.Label(tb.inner, text="Caută:"))
        self.search_var = tk.StringVar()
        tb.add(ttk.Entry(tb.inner, textvariable=self.search_var, width=24))
        tb.add(ttk.Button(tb.inner, text="Go", command=self.search))
        tb.add(ttk.Button(tb.inner, text="Reset", command=self.refresh))

        # separator + acțiuni diverse
        tb.add(ttk.Separator(tb.inner, orient="vertical"))
        tb.add(ttk.Button(tb.inner, text="Check HIBP", command=self.check_selected))
        tb.add(ttk.Button(tb.inner, text="Logout master", command=self.logout))

        self._btn_reset_app = ttk.Button(tb.inner, text="Reset App", command=self.reset_app)
        tb.add(self._btn_reset_app)

        # separator pentru zona de useri
        tb.add(ttk.Separator(tb.inner, orient="vertical"))

        # butoane user: login + creare user nou (doar pentru master)
        self._btn_user_login = ttk.Button(tb.inner, text="Login user", command=self.user_login_dialog)
        tb.add(self._btn_user_login)

        self._btn_new_user = ttk.Button(tb.inner, text="Adauga user", command=self.create_user_dialog)
        tb.add(self._btn_new_user)

        # === TABEL INTRĂRI ===
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
        1. Dacă există useri în DB, deschide fereastra de alegere utilizator.
        2. Cere master password (ca să poată decripta baza).
        3. Dacă s-a ales un user normal, setăm current_user = acel user,
           altfel rămânem în modul master.
        """
        # 1) alegem utilizatorul (dacă există useri)
        chosen_user: User | None = None
        has_users = bool(self.db.get_all_users())
        if has_users:
            udlg = UserChoiceWindow(self, self.db)
            self.wait_window(udlg)
            if udlg.cancelled:
                self.destroy()
                return
            chosen_user = udlg.selected_user
        else:
            # nu avem useri încă -> master implicit
            chosen_user = None

        # 2) dialog de master password (ca până acum)
        dlg = LoginWindow(self, self.auth)
        self.wait_window(dlg)
        if not dlg.password:
            self.destroy()
            return

        # setăm cheia de criptare (master password verificat deja in LoginWindow)
        self.enc = EncryptionManager(dlg.password)

        # daca exista template facial, facem si verificarea faciala
        if self.face_auth.is_enrolled():
            ok = self.face_auth.verify()
            if not ok:
                messagebox.showerror(
                    "Autentificare esuata",
                    "Verificarea faciala nu a reusit.\nAplicatia va fi inchisa."
                )
                self.enc = None
                self.destroy()
                return

        # 3) dacă userul ales este None => master; altfel user normal
        self.current_user = chosen_user
        self.update_ui_for_role()
        self.refresh()

    def logout(self):
        if messagebox.askyesno("Logout", "Sigur vrei să te deloghezi?"):
            self.enc = None
            self.current_user = None
            self.tree.delete(*self.tree.get_children())
            self.status.config(text="Delogat.")
            self.after(100, self.authenticate)

    # ---------- Helpers --------------------------------------------

    def update_ui_for_role(self):
        """
        Activează/dezactivează butoane în funcție de rol:
        - master (current_user is None) -> totul activ
        - user normal -> fără reset, fără FaceID, fără audit global, fără creare useri
        """
        if self.current_user is None:
            title = "Password Manager 🔐 — master"
            if self._btn_set_face:   self._btn_set_face["state"] = "normal"
            if self._btn_update:     self._btn_update["state"] = "normal"
            if self._btn_delete:     self._btn_delete["state"] = "normal"
            if self._btn_audit:      self._btn_audit["state"] = "normal"
            if self._btn_reset_app:  self._btn_reset_app["state"] = "normal"
            if self._btn_new_user:   self._btn_new_user["state"] = "normal"
        else:
            title = f"Password Manager 🔐 — {self.current_user.username} ({self.current_user.role})"
            # userul poate vedea/adăuga parole,
            # dar NU poate reseta app, NU poate crea useri,
            # NU poate face audit global, NU poate seta FaceID,
            # NU poate actualiza sau șterge intrări
            if self._btn_set_face:   self._btn_set_face["state"] = "disabled"
            if self._btn_update:     self._btn_update["state"] = "disabled"
            if self._btn_delete:     self._btn_delete["state"] = "disabled"
            if self._btn_audit:      self._btn_audit["state"] = "disabled"
            if self._btn_reset_app:  self._btn_reset_app["state"] = "disabled"
            if self._btn_new_user:   self._btn_new_user["state"] = "disabled"

        self.title(title)

    def setup_face_auth(self):
        if not messagebox.askyesno(
                "Setare FaceID",
                "Aceasta va porni camera si va salva un model al fetei tale pe disk.\n"
                "Vrei sa continui?"
        ):
            return

        ok = self.face_auth.enroll()
        if ok:
            messagebox.showinfo("Setare FaceID", "Enrolarea faciala a reusit.")
        else:
            messagebox.showwarning(
                "Setare FaceID",
                "Enrolarea faciala NU a reusit sau a fost anulata."
            )

    def user_login_dialog(self):
        """Login ca user normal (după ce master a deblocat aplicația)."""
        if self.enc is None:
            messagebox.showerror("Eroare", "Întâi trebuie deblocat cu master password.")
            return

        username = simpledialog.askstring("Login user", "Username:", parent=self)
        if not username:
            return
        password = simpledialog.askstring("Login user", "Parolă:", show="*", parent=self)
        if password is None:
            return

        user = self.db.verify_user_credentials(username, password)
        if not user:
            messagebox.showerror("Eroare", "Credentiale user incorecte.")
            return

        self.current_user = user
        self.update_ui_for_role()
        self.refresh()
        messagebox.showinfo("Login user", f"Logat ca {user.username} ({user.role}).")

    def create_user_dialog(self):
        """Creează un user nou (doar din modul master)."""
        if self.current_user is not None:
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

        # pentru început, toți userii creați sunt 'user' (nu 'master')
        try:
            user_id = self.db.create_user(username, pw1, role="user")
        except Exception as ex:
            messagebox.showerror("Eroare", f"Nu am putut crea userul:\n{ex}")
            return

        messagebox.showinfo("User creat", f"Userul '{username}' a fost creat cu id {user_id}.")

    # ---------- HIBP audit -----------------------------------------

    def audit_hibp_all(self):
        """Calculează HIBP pentru toate intrările, în background, cu update live.
           Master -> toate intrările, user normal -> doar intrările lui (dar butonul e dezactivat la user).
        """
        if self.enc is None:
            return

        if self.current_user is None:
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
                # IMPORTANT: inițializăm count la None la fiecare iterație,
                # deci există mereu, indiferent de excepții.
                count: int | None = None

                # 1) decriptează
                try:
                    pwd = self.enc.decrypt(e.password_encrypted)
                except Exception:
                    # dacă nu putem decripta, lăsăm count = None (status „—”)
                    pass
                else:
                    # 2) verifică HIBP
                    try:
                        count = pwned_count(pwd)
                    except Exception:
                        # dacă pică rețeaua / API-ul, lăsăm None
                        count = None

                # 3) salvăm în cache + actualizăm UI pentru rândul curent
                self._hibp_cache[e.id] = count
                self.after(0, lambda _id=e.id, _c=count: self._update_hibp_cell(_id, _c))

            # 4) la final, mesaj în status bar
            if hasattr(self, "status"):
                self.after(0, lambda: self.status.config(text="Audit HIBP terminat."))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Refresh + search -----------------------------------

    def refresh(self):
        """Reîncarcă toate intrările din baza de date în tabel."""
        if not hasattr(self, "_hibp_cache"):
            self._hibp_cache: dict[int, int | None] = {}

        self.tree.delete(*self.tree.get_children())

        # master vede toate intrările, userul vede doar intrările lui
        if self.current_user is None:
            rows = self.db.get_all_entries()
        else:
            rows = self.db.get_entries_for_user(self.current_user.id)

        for e in rows:
            hibp_val = self._hibp_label(self._hibp_cache.get(e.id))
            self.tree.insert(
                "",
                "end",
                iid=str(e.id),
                values=(e.service, e.username, e.last_updated, hibp_val),
            )

        who = "master" if self.current_user is None else self.current_user.username
        self.status.config(text=f"{len(rows)} intrări (user: {who})")

    def search(self):
        """Caută după text în service și afișează rezultatele."""
        q = self.search_var.get().strip()
        if not hasattr(self, "_hibp_cache"):
            self._hibp_cache: dict[int, int | None] = {}

        self.tree.delete(*self.tree.get_children())

        if self.current_user is None:
            # master caută în toate
            if not q:
                rows = self.db.get_all_entries()
            else:
                rows = self.db.find_by_service(q)
        else:
            # user normal caută doar în parolele lui
            if not q:
                rows = self.db.get_entries_for_user(self.current_user.id)
            else:
                rows = self.db.find_by_service_for_user(q, self.current_user.id)

        for e in rows:
            hibp_val = self._hibp_label(self._hibp_cache.get(e.id))
            self.tree.insert(
                "",
                "end",
                iid=str(e.id),
                values=(e.service, e.username, e.last_updated, hibp_val),
            )

        who = "master" if self.current_user is None else self.current_user.username
        if q:
            self.status.config(text=f"{len(rows)} rezultate pentru '{q}' (user: {who})")
        else:
            self.status.config(text=f"{len(rows)} intrări (user: {who})")

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
        user_id = self.current_user.id if self.current_user is not None else None
        new_id = self.db.add_entry(entry, user_id=user_id)

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
        if not new1:
            return
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