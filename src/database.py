import sqlite3
import os
import base64
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "chat_history.db")
KEY_FILE_PATH = os.path.join(PROJECT_ROOT, "local_storage.key")

class ChatDatabase:
    def __init__(self, db_name=DEFAULT_DB_PATH):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self._create_tables()
        self._load_or_generate_key()

    def _create_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                user_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                is_sent_by_me INTEGER NOT NULL
            )
        """)
        self.conn.commit()

    def _load_or_generate_key(self):
        if os.path.exists(KEY_FILE_PATH):
            with open(KEY_FILE_PATH, "rb") as f:
                self.local_key = f.read()
        else:
            self.local_key = os.urandom(32)
            with open(KEY_FILE_PATH, "wb") as f:
                f.write(self.local_key)

    def _encrypt_text(self, plaintext):
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.local_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception as e:
            print(f"Erro de criptografia local: {e}")
            return plaintext

    def _decrypt_text(self, encrypted_b64):
        try:
            data = base64.b64decode(encrypted_b64)
            iv = data[:16]
            ciphertext = data[16:]
            
            cipher = Cipher(algorithms.AES(self.local_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
        except Exception:
            return "[Conteúdo ilegível ou corrompido]"

    def save_message(self, user_id, sender, recipient, text, timestamp, is_sent_by_me):
        encrypted_text = self._encrypt_text(text)
        
        self.cursor.execute(
            "INSERT INTO messages (user_id, sender, recipient, text, timestamp, is_sent_by_me) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, sender, recipient, encrypted_text, timestamp, 1 if is_sent_by_me else 0)
        )
        self.conn.commit()

    def get_conversation_history(self, user_id, partner_name):
        self.cursor.execute("""
            SELECT sender, recipient, text, timestamp, is_sent_by_me 
            FROM messages 
            WHERE user_id = ? AND (
                (sender = ? AND recipient = ?) OR 
                (sender = ? AND recipient = ?)
            )
            ORDER BY id ASC
        """, (user_id, user_id, partner_name, partner_name, user_id))
        
        history = []
        for sender, recipient, text, timestamp, is_sent_by_me in self.cursor.fetchall():
            decrypted_text = self._decrypt_text(text)
            history.append({
                "sender": sender,
                "recipient": recipient,
                "text": decrypted_text,
                "timestamp": timestamp,
                "is_sent_by_me": bool(is_sent_by_me)
            })
        return history

    def close(self):
        self.conn.close()