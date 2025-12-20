# 🔐 Digital Signature System

## 📖 Overview
This project implements a **Digital Signature System** using **Python**, **Tkinter**, and the **cryptography** library.  
It allows users to generate RSA key pairs, sign files, verify digital signatures, and view SHA-256 hashes through a user-friendly GUI.

The system ensures:
- **Authenticity**
- **Integrity**
- **Non-repudiation**

of digital documents.

---

## ✨ Features
- RSA key generation (2048 / 4096 bits)
- File signing using **SHA-256 + RSA-PSS**
- Digital signature verification
- JSON-based verification reports
- Simple and beginner-friendly GUI

---

## 🛠 Technologies Used
- **Language:** Python  
- **GUI:** Tkinter  
- **Cryptography:** `cryptography` library  
- **Hashing:** `hashlib` (SHA-256)  
- **Reporting:** JSON, `datetime`

---

## ▶ Usage

### Installation
Install required dependency:
```bash
pip install cryptography
how to run : 
python gui.py
