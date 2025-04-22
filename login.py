from tkinter import *
from tkinter import messagebox
import sqlite3
import hashlib

class LoginSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Login | Inventory Management System")
        self.root.geometry("400x300+500+200")
        self.root.config(bg="white")

        self.username = StringVar()
        self.password = StringVar()

        # Title Label
        Label(self.root, text="Login", font=("Helvetica", 30), bg="white").pack(pady=20)

        # Username Label and Entry
        Label(self.root, text="Username", font=("Helvetica", 15), bg="white").pack(pady=5)
        self.username_entry = Entry(self.root, textvariable=self.username, font=("Helvetica", 15))
        self.username_entry.pack(pady=10)

        # Password Label and Entry
        Label(self.root, text="Password", font=("Helvetica", 15), bg="white").pack(pady=5)
        self.password_entry = Entry(self.root, textvariable=self.password, font=("Helvetica", 15), show="*")
        self.password_entry.pack(pady=10)

        # Login Button
        Button(self.root, text="Login", font=("Helvetica", 15), bg="green", fg="white", command=self.login).pack(pady=10)

        # Register Button
        Button(self.root, text="Create Account", font=("Helvetica", 12), bg="blue", fg="white", command=self.create_account).pack(pady=5)

    def login(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Both fields are required!", parent=self.root)
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
                user = c.fetchone()

                if user:
                    messagebox.showinfo("Success", "Login Successful!", parent=self.root)
                    self.root.destroy()  # Close the login window
                    import dashboard  # Assuming your dashboard code is in dashboard.py
                else:
                    messagebox.showerror("Error", "Invalid username or password!", parent=self.root)
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}", parent=self.root)

    def create_account(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Both fields are required!", parent=self.root)
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                messagebox.showinfo("Success", "Account Created Successfully!", parent=self.root)
                self.username.set("")
                self.password.set("")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already taken, try another one.", parent=self.root)
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}", parent=self.root)

if __name__ == "__main__":
    root = Tk()
    login_system = LoginSystem(root)
    root.mainloop()