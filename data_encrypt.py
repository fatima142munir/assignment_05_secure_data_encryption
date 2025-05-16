import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os

# --- Key Handling ---


def load_or_create_key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Load Encryption Key
encryption_key = load_or_create_key()
secure_cipher = Fernet(encryption_key)

# --- File for Data Storage ---
DATA_FILE = "secure_data.json"

# --- Load Existing Data ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# --- Save Updated Data ---
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# --- In-Memory Variables ---
database = load_data()
attempt_counter = 0

# --- Utility Functions ---
def create_hash(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def lock_data(plain_text):
    return secure_cipher.encrypt(plain_text.encode()).decode()

def unlock_data(cipher_text, passkey):
    global attempt_counter
    hashed = create_hash(passkey)

    for item in database.values():
        if item["ciphertext"] == cipher_text and item["hashed_key"] == hashed:
            attempt_counter = 0
            return secure_cipher.decrypt(cipher_text.encode()).decode()

    attempt_counter += 1
    return None

def clear_attempts():
    global attempt_counter
    attempt_counter = 0

# --- Streamlit UI ---
st.set_page_config(page_title="SecureVault", page_icon="🔐")
st.title("🔐 SecureVault: Encrypted Data Locker")

# Navigation
menu = ["🏠 Home", "🛡️ Save Data", "🔓 Access Data", "🔑 Admin Login"]
choice = st.sidebar.selectbox("Navigate", menu)

# --- Pages ---
if choice == "🏠 Home":
    st.markdown("Welcome to **SecureVault** 🔐")
    st.write("Use this app to securely save & retrieve encrypted data using your private key.")

elif choice == "🛡️ Save Data":
    st.subheader("Encrypt and Store Your Information")
    input_data = st.text_area("Enter confidential data:")
    user_key = st.text_input("Create a passkey:", type="password")

    if st.button("🔐 Encrypt & Store"):
        if input_data and user_key:
            hashed_key = create_hash(user_key)
            encrypted_msg = lock_data(input_data)

            database[encrypted_msg] = {
                "ciphertext": encrypted_msg,
                "hashed_key": hashed_key
            }
            save_data(database)

            st.success("✅ Your data has been securely stored!")
            st.markdown("### 🔐 Encrypted Text:")
            st.code(encrypted_msg)
        else:
            st.error("🚨 Both fields are required.")

elif choice == "🔓 Access Data":
    st.subheader("Retrieve Your Encrypted Information")
    encrypted_input = st.text_area("Paste your encrypted text here:")
    access_key = st.text_input("Enter your passkey:", type="password")

    if st.button("🔍 Decrypt"):
        if encrypted_input and access_key:
            result = unlock_data(encrypted_input, access_key)

            if result:
                st.success(f"✅ Decrypted Message: {result}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - attempt_counter}")
                if attempt_counter >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Admin Login...")
                    st.experimental_rerun()
        else:
            st.error("🚨 Both fields are required.")

elif choice == "🔑 Admin Login":
    st.subheader("🔐 Admin Access")
    master = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master == "admin123":
            clear_attempts()
            st.success("✅ Access granted. Redirecting to Access Data...")
            st.rerun()
        else:
            st.error("❌ Incorrect master password!")

