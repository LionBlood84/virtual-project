import hashlib
import os
import secrets
import sqlite3
import string
import tkinter as tk
from tkinter import messagebox, ttk

DB_NAME = "vault.db"


class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME)
        self.cursor = self.conn.cursor()
        self.init_db()

    def init_db(self):
        # Users table for authentication
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """
        )
        # Passwords table for credential storage
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                account_username TEXT NOT NULL,
                account_password TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """
        )
        self.conn.commit()

    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
        if salt is None:
            salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100000
        )
        return pwd_hash.hex(), salt.hex()

    def register_user(self, username, password):
        if not username or not password:
            return False, "Fields cannot be empty."
        pwd_hash, salt = self.hash_password(password)
        try:
            self.cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, pwd_hash, salt),
            )
            self.conn.commit()
            return True, "Registration successful! You can now log in."
        except sqlite3.IntegrityError:
            return False, "Username already exists."

    def authenticate_user(self, username, password):
        self.cursor.execute(
            "SELECT id, password_hash, salt FROM users WHERE username = ?",
            (username,),
        )
        row = self.cursor.fetchone()
        if not row:
            return None
        user_id, stored_hash, salt_hex = row
        salt = bytes.fromhex(salt_hex)
        check_hash, _ = self.hash_password(password, salt)
        if check_hash == stored_hash:
            return user_id
        return None

    def add_credential(self, user_id, service, acc_user, acc_pwd):
        self.cursor.execute(
            "INSERT INTO credentials (user_id, service, account_username, account_password) VALUES (?, ?, ?, ?)",
            (user_id, service, acc_user, acc_pwd),
        )
        self.conn.commit()

    def get_credentials(self, user_id):
        self.cursor.execute(
            "SELECT id, service, account_username, account_password FROM credentials WHERE user_id = ?",
            (user_id,),
        )
        return self.cursor.fetchall()

    def delete_credential(self, cred_id, user_id):
        self.cursor.execute(
            "DELETE FROM credentials WHERE id = ? AND user_id = ?",
            (cred_id, user_id),
        )
        self.conn.commit()


class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Desktop Password Manager")
        self.geometry("700x520")
        self.resizable(False, False)
        self.configure(bg="#f4f5f7")

        self.db = Database()
        self.current_user_id = None
        self.current_username = ""

        # Container frame for page swapping
        self.container = tk.Frame(self, bg="#f4f5f7")
        self.container.pack(fill="both", expand=True)

        self.show_login_frame()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    # --- Authentication Views ---
    def show_login_frame(self):
        self.clear_container()

        frame = tk.Frame(self.container, bg="white", padx=30, pady=30, relief="groove", bd=1)
        frame.place(relx=0.5, rely=0.5, anchor="center", width=380)

        tk.Label(frame, text="Password Vault", font=("Helvetica", 18, "bold"), bg="white", fg="#222").pack(pady=(0, 5))
        tk.Label(frame, text="Login to your account", font=("Helvetica", 10), bg="white", fg="#666").pack(pady=(0, 20))

        tk.Label(frame, text="Username", font=("Helvetica", 9, "bold"), bg="white", anchor="w").pack(fill="x")
        user_entry = tk.Entry(frame, font=("Helvetica", 11), relief="solid", bd=1)
        user_entry.pack(fill="x", pady=(2, 12), ipady=4)

        tk.Label(frame, text="Master Password", font=("Helvetica", 9, "bold"), bg="white", anchor="w").pack(fill="x")
        pwd_entry = tk.Entry(frame, font=("Helvetica", 11), show="*", relief="solid", bd=1)
        pwd_entry.pack(fill="x", pady=(2, 18), ipady=4)

        def handle_login():
            user = user_entry.get().strip()
            pwd = pwd_entry.get().strip()
            user_id = self.db.authenticate_user(user, pwd)
            if user_id:
                self.current_user_id = user_id
                self.current_username = user
                self.show_dashboard_frame()
            else:
                messagebox.showerror("Error", "Invalid username or password.")

        login_btn = tk.Button(frame, text="Log In", font=("Helvetica", 10, "bold"), bg="#1a73e8", fg="white",
                              activebackground="#1558b0", activeforeground="white", relief="flat", cursor="hand2",
                              command=handle_login)
        login_btn.pack(fill="x", ipady=5, pady=(0, 10))

        reg_btn = tk.Button(frame, text="Create New Account", font=("Helvetica", 9), bg="#f1f3f4", fg="#333",
                            relief="flat", cursor="hand2", command=self.show_register_frame)
        reg_btn.pack(fill="x", ipady=3)

    def show_register_frame(self):
        self.clear_container()

        frame = tk.Frame(self.container, bg="white", padx=30, pady=30, relief="groove", bd=1)
        frame.place(relx=0.5, rely=0.5, anchor="center", width=380)

        tk.Label(frame, text="Register Vault", font=("Helvetica", 18, "bold"), bg="white", fg="#222").pack(pady=(0, 5))
        tk.Label(frame, text="Create a master account", font=("Helvetica", 10), bg="white", fg="#666").pack(pady=(0, 20))

        tk.Label(frame, text="Username", font=("Helvetica", 9, "bold"), bg="white", anchor="w").pack(fill="x")
        user_entry = tk.Entry(frame, font=("Helvetica", 11), relief="solid", bd=1)
        user_entry.pack(fill="x", pady=(2, 12), ipady=4)

        tk.Label(frame, text="Master Password", font=("Helvetica", 9, "bold"), bg="white", anchor="w").pack(fill="x")
        pwd_entry = tk.Entry(frame, font=("Helvetica", 11), show="*", relief="solid", bd=1)
        pwd_entry.pack(fill="x", pady=(2, 18), ipady=4)

        def handle_register():
            user = user_entry.get().strip()
            pwd = pwd_entry.get().strip()
            success, msg = self.db.register_user(user, pwd)
            if success:
                messagebox.showinfo("Success", msg)
                self.show_login_frame()
            else:
                messagebox.showerror("Error", msg)

        save_btn = tk.Button(frame, text="Register", font=("Helvetica", 10, "bold"), bg="#28a745", fg="white",
                             activebackground="#218838", relief="flat", cursor="hand2", command=handle_register)
        save_btn.pack(fill="x", ipady=5, pady=(0, 10))

        back_btn = tk.Button(frame, text="Back to Login", font=("Helvetica", 9), bg="#f1f3f4", fg="#333",
                             relief="flat", cursor="hand2", command=self.show_login_frame)
        back_btn.pack(fill="x", ipady=3)

    # --- Dashboard View ---
    def show_dashboard_frame(self):
        self.clear_container()

        # Top Bar
        header = tk.Frame(self.container, bg="#1a73e8", padx=20, pady=12)
        header.pack(fill="x")

        tk.Label(header, text=f"Password Vault - Logged in as: {self.current_username}",
                 font=("Helvetica", 12, "bold"), bg="#1a73e8", fg="white").pack(side="left")

        def handle_logout():
            self.current_user_id = None
            self.current_username = ""
            self.show_login_frame()

        logout_btn = tk.Button(header, text="Logout", font=("Helvetica", 9, "bold"), bg="#d93025", fg="white",
                               relief="flat", cursor="hand2", command=handle_logout)
        logout_btn.pack(side="right")

        # Main Body
        body = tk.Frame(self.container, bg="#f4f5f7", padx=20, pady=15)
        body.pack(fill="both", expand=True)

        # Input Card
        entry_card = tk.LabelFrame(body, text=" Add New Credential ", bg="white", font=("Helvetica", 10, "bold"), padx=15, pady=10)
        entry_card.pack(fill="x", pady=(0, 12))

        tk.Label(entry_card, text="Service / Website:", bg="white", font=("Helvetica", 9)).grid(row=0, column=0, sticky="w", pady=3)
        service_entry = tk.Entry(entry_card, width=22, relief="solid", bd=1)
        service_entry.grid(row=0, column=1, padx=(5, 15), pady=3)

        tk.Label(entry_card, text="Username / Email:", bg="white", font=("Helvetica", 9)).grid(row=0, column=2, sticky="w", pady=3)
        acc_user_entry = tk.Entry(entry_card, width=22, relief="solid", bd=1)
        acc_user_entry.grid(row=0, column=3, padx=(5, 15), pady=3)

        tk.Label(entry_card, text="Password:", bg="white", font=("Helvetica", 9)).grid(row=1, column=0, sticky="w", pady=3)
        acc_pwd_entry = tk.Entry(entry_card, width=22, relief="solid", bd=1)
        acc_pwd_entry.grid(row=1, column=1, padx=(5, 15), pady=3)

        def generate_password():
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            gen = "".join(secrets.choice(chars) for _ in range(14))
            acc_pwd_entry.delete(0, tk.END)
            acc_pwd_entry.insert(0, gen)

        gen_btn = tk.Button(entry_card, text="Generate", bg="#f1f3f4", font=("Helvetica", 8), command=generate_password)
        gen_btn.grid(row=1, column=2, sticky="w", pady=3)

        def add_record():
            serv = service_entry.get().strip()
            user = acc_user_entry.get().strip()
            pwd = acc_pwd_entry.get().strip()
            if not serv or not user or not pwd:
                messagebox.showwarning("Incomplete", "Please complete all fields.")
                return
            self.db.add_credential(self.current_user_id, serv, user, pwd)
            service_entry.delete(0, tk.END)
            acc_user_entry.delete(0, tk.END)
            acc_pwd_entry.delete(0, tk.END)
            refresh_table()

        save_btn = tk.Button(entry_card, text="Save Entry", bg="#1a73e8", fg="white", font=("Helvetica", 9, "bold"),
                             relief="flat", cursor="hand2", command=add_record)
        save_btn.grid(row=1, column=3, sticky="e", pady=3)

        # Table Card
        table_card = tk.Frame(body, bg="white", relief="groove", bd=1)
        table_card.pack(fill="both", expand=True)

        columns = ("id", "service", "account_user", "password")
        tree = ttk.Treeview(table_card, columns=columns, show="headings", selectmode="browse")
        tree.heading("id", text="ID")
        tree.heading("service", text="Service / Site")
        tree.heading("account_user", text="Username / Email")
        tree.heading("password", text="Password")

        tree.column("id", width=40, anchor="center")
        tree.column("service", width=180, anchor="w")
        tree.column("account_user", width=200, anchor="w")
        tree.column("password", width=160, anchor="w")

        scrollbar = ttk.Scrollbar(table_card, orient="vertical", command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)

        def refresh_table():
            for row in tree.get_children():
                tree.delete(row)
            for row in self.db.get_credentials(self.current_user_id):
                tree.insert("", "end", values=row)

        def delete_selected():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Select", "Please select a record from the table to delete.")
                return
            item = tree.item(selected[0])
            record_id = item["values"][0]
            self.db.delete_credential(record_id, self.current_user_id)
            refresh_table()

        # Action bar under table
        actions = tk.Frame(body, bg="#f4f5f7")
        actions.pack(fill="x", pady=(8, 0))

        del_btn = tk.Button(actions, text="Delete Selected", bg="#d93025", fg="white", font=("Helvetica", 9),
                            relief="flat", cursor="hand2", command=delete_selected)
        del_btn.pack(side="right")

        refresh_table()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()