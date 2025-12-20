import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from signer import generate_keys, sign_file, verify_file, export_report
import os

# ------------------------------
# GUI Functions
# ------------------------------
def select_file(entry_widget):
    path = filedialog.askopenfilename()
    if path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)

def gui_generate_keys():
    key_size = int(key_size_var.get())
    priv_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Private Key")
    pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Public Key")
    if not priv_path or not pub_path:
        return
    info = generate_keys(key_size, priv_path, pub_path)
    cert_text.delete(1.0, tk.END)
    cert_text.insert(tk.END, f"Modulus bits: {info['modulus_bits']}\nPublic exponent: {info['exponent']}")
    messagebox.showinfo("Keys Generated", f"Private: {info['private']}\nPublic: {info['public']}")

def gui_sign_file():
    file_path = entry_file.get()
    if not file_path or not os.path.isfile(file_path):
        return messagebox.showerror("Error", "Select a valid file")
    priv_path = filedialog.askopenfilename(title="Select Private Key")
    if not priv_path:
        return
    sig_path = filedialog.asksaveasfilename(defaultextension=".sig", title="Save Signature As")
    if not sig_path:
        return
    info = sign_file(priv_path, file_path, sig_path)
    hash_text.delete(1.0, tk.END)
    hash_text.insert(tk.END, info["sha256"])
    messagebox.showinfo("Signed", f"Signature saved at: {sig_path}")

def gui_verify_file():
    file_path = entry_file.get()
    if not file_path or not os.path.isfile(file_path):
        return messagebox.showerror("Error", "Select a valid file")
    pub_path = filedialog.askopenfilename(title="Select Public Key")
    if not pub_path:
        return
    sig_path = filedialog.askopenfilename(title="Select Signature File", filetypes=[("Signature files","*.sig")])
    if not sig_path:
        return
    result = verify_file(pub_path, file_path, sig_path)
    hash_text.delete(1.0, tk.END)
    hash_text.insert(tk.END, result["sha256"])
    messagebox.showinfo("Verification", "Signature is VALID ✅" if result["valid"] else "Signature is INVALID ❌")
    # Export report
    report_path = filedialog.asksaveasfilename(defaultextension=".json", title="Save Verification Report")
    if report_path:
        export_report(os.path.basename(file_path), os.path.basename(pub_path), result["valid"], result["sha256"], report_path)
        messagebox.showinfo("Report", f"Report saved: {report_path}")

# ------------------------------
# Build GUI
# ------------------------------
root = tk.Tk()
root.title("Digital Signature ")
root.geometry("650x450")
root.configure(bg="#e6ffe6")

# Key generation frame
frame_keys = tk.LabelFrame(root, text="Generate Keys", bg="#e6ffe6", fg="#004d00", font=("Arial", 12, "bold"))
frame_keys.pack(pady=10, fill="x", padx=10)

tk.Label(frame_keys, text="Key size:", bg="#e6ffe6", fg="#004d00").pack(side=tk.LEFT, padx=5)
key_size_var = tk.StringVar(value="2048")
ttk.Combobox(frame_keys, textvariable=key_size_var, values=["1024","2048","4096"], width=6).pack(side=tk.LEFT, padx=5)
tk.Button(frame_keys, text="Generate Keys", command=gui_generate_keys, bg="#5cb85c", fg="white", width=15).pack(side=tk.LEFT, padx=10)

# File selection frame
frame_file = tk.LabelFrame(root, text="Select File", bg="#e6ffe6", fg="#004d00", font=("Arial", 12, "bold"))
frame_file.pack(pady=10, fill="x", padx=10)

entry_file = tk.Entry(frame_file, width=50, font=("Arial", 11))
entry_file.pack(side=tk.LEFT, padx=5)
tk.Button(frame_file, text="Browse", command=lambda: select_file(entry_file), bg="#8ad98a", fg="white", width=12).pack(side=tk.LEFT)

# Action buttons
frame_actions = tk.Frame(root, bg="#e6ffe6")
frame_actions.pack(pady=10)
tk.Button(frame_actions, text="Sign File", command=gui_sign_file, bg="#4cae4c", fg="white", width=15).pack(side=tk.LEFT, padx=10)
tk.Button(frame_actions, text="Verify File", command=gui_verify_file, bg="#3d8f3d", fg="white", width=15).pack(side=tk.LEFT, padx=10)

# Hash display
hash_frame = tk.LabelFrame(root, text="File Hash (SHA-256)", bg="#e6ffe6", fg="#004d00")
hash_frame.pack(pady=5, fill="x", padx=10)
hash_text = scrolledtext.ScrolledText(hash_frame, height=2)
hash_text.pack(fill="x", padx=5, pady=2)

# Certificate info
cert_frame = tk.LabelFrame(root, text="Certificate Info", bg="#e6ffe6", fg="#004d00")
cert_frame.pack(pady=5, fill="x", padx=10)
cert_text = scrolledtext.ScrolledText(cert_frame, height=4)
cert_text.pack(fill="x", padx=5, pady=2)

root.mainloop()
