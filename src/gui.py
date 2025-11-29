import tkinter as tk
from tkinter import messagebox, filedialog
from signer import generate_keys, sign_message, verify_signature
import os

# ---------------- GUI Functions ---------------- #

def gen_keys():
    generate_keys()
    messagebox.showinfo("Success", "Keys generated successfully!\nprivate_key.pem & public_key.pem created.")

def select_file(entry_widget):
    filename = filedialog.askopenfilename()
    if filename:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)

def sign_file():
    file_path = entry_file.get()
    if not file_path or not os.path.isfile(file_path):
        messagebox.showwarning("Warning", "Select a valid file to sign")
        return
    signature_path = filedialog.asksaveasfilename(defaultextension=".sig", title="Save Signature As")
    if not signature_path:
        return
    sign_message("private_key.pem", file_path, signature_path)
    messagebox.showinfo("Success", f"File signed!\nSignature saved as:\n{signature_path}")

def verify_file():
    file_path = entry_file.get()
    if not file_path or not os.path.isfile(file_path):
        messagebox.showwarning("Warning", "Select a valid file to verify")
        return
    sig_path = filedialog.askopenfilename(title="Select Signature File", filetypes=[("Signature files", "*.sig")])
    if not sig_path:
        return
    valid = verify_signature("public_key.pem", file_path, sig_path)
    if valid:
        messagebox.showinfo("Result", "Signature is VALID ✅")
    else:
        messagebox.showerror("Result", "Signature is INVALID ❌")

# ---------------- GUI Setup ---------------- #

root = tk.Tk()
root.title("Digital Signature System (File Version)")
root.geometry("500x250")
root.resizable(False, False)

# Generate Keys
tk.Button(root, text="Generate Keys", command=gen_keys, width=20, bg="#4CAF50", fg="white").pack(pady=10)

# File selection
frame_file = tk.Frame(root)
frame_file.pack(pady=10)
entry_file = tk.Entry(frame_file, width=50)
entry_file.pack(side=tk.LEFT, padx=5)
tk.Button(frame_file, text="Select File", command=lambda: select_file(entry_file)).pack(side=tk.LEFT)

# Sign / Verify buttons
frame_actions = tk.Frame(root)
frame_actions.pack(pady=10)
tk.Button(frame_actions, text="Sign File", command=sign_file, width=15, bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=10)
tk.Button(frame_actions, text="Verify File", command=verify_file, width=15, bg="#f44336", fg="white").pack(side=tk.LEFT, padx=10)

root.mainloop()
