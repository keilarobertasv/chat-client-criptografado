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
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
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
        
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS p2p_sessions (
                partner_username TEXT PRIMARY KEY,
                aes_key TEXT NOT NULL,
                hmac_key TEXT NOT NULL,
                start_time TEXT NOT NULL,
                msg_count INTEGER NOT NULL
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

    def save_session(self, partner_username, aes_key_bytes, hmac_key_bytes, start_time_dt, msg_count):
        aes_b64 = base64.b64encode(aes_key_bytes).decode('utf-8')
        hmac_b64 = base64.b64encode(hmac_key_bytes).decode('utf-8')
        
        enc_aes = self._encrypt_text(aes_b64)
        enc_hmac = self._encrypt_text(hmac_b64)
        
        start_str = start_time_dt.isoformat()

        self.cursor.execute("""
            INSERT OR REPLACE INTO p2p_sessions 
            (partner_username, aes_key, hmac_key, start_time, msg_count)
            VALUES (?, ?, ?, ?, ?)
        """, (partner_username, enc_aes, enc_hmac, start_str, msg_count))
        self.conn.commit()

    def load_sessions(self):
        self.cursor.execute("SELECT partner_username, aes_key, hmac_key, start_time, msg_count FROM p2p_sessions")
        sessions = {}
        rows = self.cursor.fetchall()
        
        for row in rows:
            partner, enc_aes, enc_hmac, start_str, count = row
            try:
                aes_b64 = self._decrypt_text(enc_aes)
                hmac_b64 = self._decrypt_text(enc_hmac)
                
                aes_bytes = base64.b64decode(aes_b64)
                hmac_bytes = base64.b64decode(hmac_b64)
                start_dt = datetime.fromisoformat(start_str)
                
                sessions[partner] = {
                    'aes': aes_bytes,
                    'hmac': hmac_bytes,
                    'verified': True,
                    'msg_count': count,
                    'start_time': start_dt
                }
            except Exception as e:
                print(f"Erro ao carregar sessão de {partner}: {e}")
        
        return sessions
    
    def delete_session(self, partner_username):
        self.cursor.execute("DELETE FROM p2p_sessions WHERE partner_username = ?", (partner_username,))
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