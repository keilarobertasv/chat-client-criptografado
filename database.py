import sqlite3
from datetime import datetime

class ChatDatabase:
    def __init__(self, db_name="chat_history.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self._create_tables()

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

    def save_message(self, user_id, sender, recipient, text, timestamp, is_sent_by_me):
        self.cursor.execute(
            "INSERT INTO messages (user_id, sender, recipient, text, timestamp, is_sent_by_me) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, sender, recipient, text, timestamp, 1 if is_sent_by_me else 0)
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
            history.append({
                "sender": sender,
                "recipient": recipient,
                "text": text,
                "timestamp": timestamp,
                "is_sent_by_me": bool(is_sent_by_me)
            })
        return history

    def close(self):
        self.conn.close()