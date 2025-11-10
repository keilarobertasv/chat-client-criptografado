import sys
import os
from PyQt6.QtWidgets import QMainWindow, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QLabel, QInputDialog
from PyQt6 import QtCore
from PyQt6.QtGui import QFont, QColor, QPixmap, QPainter, QBrush, QIcon, QTextCursor 
from datetime import datetime
from login_ui import Ui_MainWindow as Ui_LoginWindow
from chat_ui import Ui_MainWindow as Ui_ChatWindow
from network import NetworkClient
from database import ChatDatabase
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

class ChatWindow(QMainWindow):
    def __init__(self, network_client, current_username, db, private_key): 
        super().__init__()
        self.network_client = network_client
        self.current_user = current_username
        self.db = db 
        self.private_key = private_key
        self.ui = Ui_ChatWindow()
        self.ui.setupUi(self)
        
        self.setWindowTitle(f"KeiChat - Conectado como {self.current_user}")

        self.chat_display = self.ui.messages_display
        self.message_entry = self.ui.message_input
        self.send_button = self.ui.send_button
        self.contacts_list = self.ui.contacts_list
        
        self.message_cache = {}

        self.ui.horizontalLayout.setStretch(0, 1)
        self.ui.horizontalLayout.setStretch(1, 3)
        
        self.typing_status_label = QLabel("")
        self.typing_status_label.setStyleSheet("padding: 2px; font-style: italic; color: #888;")
        self.statusBar().addWidget(self.typing_status_label)
        self.statusBar().setStyleSheet("border-top: 1px solid #333;")

        self.online_icon = self._create_status_icon(QColor("green"))
        self.offline_icon = self._create_status_icon(QColor("#AAAAAA"))

        self.all_users = []
        self.online_users = set()
        self.unread_senders = set()
        
        self.typing_timer = QtCore.QTimer(self)
        self.typing_timer.setInterval(1500) 
        self.typing_timer.setSingleShot(True)
        self.typing_timer.timeout.connect(self.stop_typing_event)
        self.is_typing = False

        self.send_button.clicked.connect(self.send_message_action)
        self.message_entry.returnPressed.connect(self.send_message_action)
        self.contacts_list.currentItemChanged.connect(self.on_contact_selected)
        self.message_entry.textChanged.connect(self.start_typing_action) 
        
        self.network_client.message_received.connect(self.on_message_received)
        self.network_client.connection_error.connect(self.on_connection_error)
        self.network_client.start_listening()
        
        self.request_initial_data()

    def _create_status_icon(self, color):
        pixmap = QPixmap(16, 16)
        pixmap.fill(QtCore.Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QBrush(color))
        painter.setPen(QtCore.Qt.PenStyle.NoPen)
        painter.drawEllipse(3, 3, 10, 10)
        painter.end()
        return QIcon(pixmap)

    def request_initial_data(self):
        self.network_client.send_request({"action": "get_contact_list"})
        self.network_client.send_request({"action": "get_offline_messages"})
        
    @QtCore.pyqtSlot(str)
    def on_connection_error(self, message):
        self.show_error("Erro de Conexão", message)

    @QtCore.pyqtSlot(dict)
    def on_message_received(self, message):
        msg_type = message.get("type")
        if msg_type == "contact_list":
            self.all_users = message.get("all_users", [])
            self.online_users = set(message.get("online_users", []))
            self.populate_contacts()
        elif msg_type == "status_update":
            user, status = message.get("user"), message.get("status")
            if user:
                if status == "online": self.online_users.add(user)
                elif status == "offline": self.online_users.discard(user)
                self.populate_contacts()
        elif msg_type in ["new_message", "offline_message"]:
            sender = message.get("sender")
            text = message.get("text")
            timestamp = message.get("timestamp", "") or datetime.now().strftime("%H:%M")
            
            self.db.save_message(
                user_id=self.current_user,
                sender=sender,
                recipient=self.current_user,
                text=text,
                timestamp=timestamp,
                is_sent_by_me=False
            )
            
            current_selection = self.contacts_list.currentItem()
            active_contact = current_selection.data(QtCore.Qt.ItemDataRole.UserRole) if current_selection else None
            
            if active_contact != sender:
                self.unread_senders.add(sender)
                self.populate_contacts()

            self.display_message(sender, self.current_user, text, timestamp) 
            
            self.handle_typing_indicator(sender, "stopped") 
            
        elif msg_type == "typing_indicator": 
            sender = message.get("sender")
            status = message.get("event_type") 
            self.handle_typing_indicator(sender, status)

    def start_typing_action(self):
        if not self.message_entry.text():
            if self.is_typing:
                self.stop_typing_event()
            return

        if not self.is_typing:
            self.is_typing = True
            selected_item = self.contacts_list.currentItem()
            if selected_item and selected_item.flags() & QtCore.Qt.ItemFlag.ItemIsSelectable:
                recipient = selected_item.data(QtCore.Qt.ItemDataRole.UserRole)
                request = {
                    "action": "typing_event", 
                    "payload": {
                        "recipient": recipient, 
                        "event_type": "typing" 
                    }
                }
                self.network_client.send_request(request)
        
        self.typing_timer.start() 
        
    def stop_typing_event(self):
        if self.is_typing:
            self.is_typing = False
            selected_item = self.contacts_list.currentItem()
            if selected_item and selected_item.flags() & QtCore.Qt.ItemFlag.ItemIsSelectable:
                recipient = selected_item.data(QtCore.Qt.ItemDataRole.UserRole)
                request = {
                    "action": "typing_event", 
                    "payload": {
                        "recipient": recipient, 
                        "event_type": "stopped" 
                    }
                }
                self.network_client.send_request(request)

    def handle_typing_indicator(self, user, status):
        current_selection = self.contacts_list.currentItem()
        active_contact = current_selection.data(QtCore.Qt.ItemDataRole.UserRole) if current_selection else None
        
        base_title = f"KeiChat - {self.current_user} - Conversando com {user}"
        
        if user == active_contact:
            if status == "typing":
                self.typing_status_label.setText(f"...{user} está digitando...")
                self.setWindowTitle(f"{base_title} (Digitando...)")
            else:
                self.typing_status_label.setText("")
                self.setWindowTitle(base_title)
        
        elif status == "stopped":
            self.typing_status_label.setText("")

    def populate_contacts(self):
        current_selection_data = self.contacts_list.currentItem().data(QtCore.Qt.ItemDataRole.UserRole) if self.contacts_list.currentItem() else None
        self.contacts_list.clear()

        self._add_contact_section("Online", sorted(list(self.online_users)), is_online=True)
        self._add_contact_section("Offline", sorted(self.all_users), is_online=False)
        
        if current_selection_data:
            for i in range(self.contacts_list.count()):
                item = self.contacts_list.item(i)
                if item.data(QtCore.Qt.ItemDataRole.UserRole) == current_selection_data:
                    self.contacts_list.setCurrentItem(item)
                    break

    def _add_contact_section(self, title, users, is_online):
        header = QListWidgetItem(title)
        header.setFlags(header.flags() & ~QtCore.Qt.ItemFlag.ItemIsSelectable)
        font = header.font()
        font.setItalic(True)
        header.setFont(font)
        self.contacts_list.addItem(header)

        for user in users:
            if user == self.current_user: continue
            if not is_online and user in self.online_users: continue

            display_text = f"{user} ✉️" if user in self.unread_senders else user
            item = QListWidgetItem(display_text)
            
            item.setData(QtCore.Qt.ItemDataRole.UserRole, user)

            font = QFont()
            if is_online:
                font.setBold(True)
                item.setIcon(self.online_icon)
            else:
                item.setIcon(self.offline_icon)
            item.setFont(font)
            self.contacts_list.addItem(item)
            
    def send_message_action(self):
        selected_item = self.contacts_list.currentItem()
        if not selected_item or not selected_item.flags() & QtCore.Qt.ItemFlag.ItemIsSelectable:
            return
        
        recipient = selected_item.data(QtCore.Qt.ItemDataRole.UserRole)
        text = self.message_entry.text()
        if not text: return
        
        request = { "action": "send_message", "payload": { "recipient": recipient, "text": text } }
        self.network_client.send_request(request)
        
        timestamp = datetime.now().strftime("%H:%M")
        
        self.db.save_message(
            user_id=self.current_user,
            sender=self.current_user,
            recipient=recipient,
            text=text,
            timestamp=timestamp,
            is_sent_by_me=True
        )
        
        self.display_message(self.current_user, recipient, text, timestamp) 
        
        self.message_entry.clear()
        self.stop_typing_event() 

    def on_contact_selected(self, current_item, previous_item):
        if not current_item or not current_item.flags() & QtCore.Qt.ItemFlag.ItemIsSelectable:
            self.chat_display.clear()
            self.setWindowTitle(f"KeiChat - Conectado como {self.current_user}")
            
            self.typing_status_label.setText("") 
            return
        
        contact_name = current_item.data(QtCore.Qt.ItemDataRole.UserRole)

        if contact_name in self.unread_senders:
            self.unread_senders.discard(contact_name)
            self.populate_contacts()
        
        self.chat_display.clear()
        
        history = self.db.get_conversation_history(self.current_user, contact_name)
        
        for message in history:
            self.display_message(
                sender=message['sender'], 
                recipient=message['recipient'], 
                text=message['text'], 
                timestamp=message['timestamp']
            )
        
        self.setWindowTitle(f"KeiChat - {self.current_user} - Conversando com {contact_name}")
        
        self.typing_status_label.setText("")
        
        self.chat_display.ensureCursorVisible()
        
    def display_message(self, sender, recipient, text, timestamp=""):
        conversation_partner = recipient if sender == self.current_user else sender
        is_sent_by_me = sender == self.current_user
        
        if not timestamp:
             timestamp = datetime.now().strftime("%H:%M")

        self.handle_typing_indicator(conversation_partner, "stopped")

        display_sender = "Você" if is_sent_by_me else sender
        time_html = f"<sub style='font-size: 8pt; color: #888;'> {timestamp}</sub>"

        if is_sent_by_me:
            formatted_html = f"""
            <table width='100%'><tr><td align='right'>
                <span style='background-color: #415a72; color: #ffffff; padding: 8px; border-radius: 8px;'>
                    <b>{display_sender}</b>: {text}{time_html}
                </span>
            </td></tr></table>
            """
        else:
            formatted_html = f"""
            <table width='100%'><tr><td align='left'>
                <span style='background-color: #ffffff; padding: 8px; border-radius: 8px;'>
                    <b>{display_sender}</b>: {text}{time_html}
                </span>
            </td></tr></table>
            """

        current_selection = self.contacts_list.currentItem()
        if current_selection and current_selection.data(QtCore.Qt.ItemDataRole.UserRole) == conversation_partner:
            self.chat_display.append(formatted_html)
            self.chat_display.ensureCursorVisible()

    def show_error(self, title, message):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.exec()

    def closeEvent(self, event):
        self.network_client.close()
        event.accept()

class LoginWindow(QMainWindow):
    def __init__(self, network_client, db): 
        super().__init__()
        self.network_client = network_client
        self.db = db 
        self.chat_window = None
        self.ui = Ui_LoginWindow()
        self.ui.setupUi(self)
        self.is_switching_windows = False
        
        self.setWindowTitle("KeiChat - Login")
        
        self.ui.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.ui.login_button.clicked.connect(self.login_action)
        self.ui.register_button.clicked.connect(self.register_action)
        self.ui.username_entry.returnPressed.connect(self.login_action)
        self.ui.password_entry.returnPressed.connect(self.login_action)
        
    def show_error(self, title, message):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.exec()
        
    def show_info(self, title, message):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.exec()

    def login_action(self):
        username = self.ui.username_entry.text()
        password = self.ui.password_entry.text()
        if not username or not password:
            self.show_error("Erro", "Usuário e senha não podem estar vazios.")
            return

        if not self.network_client.socket:
            if not self.network_client.connect(): 
                self.show_error("Falha na Conexão", "Não foi possível conectar ao servidor. Verifique o host/porta.")
                return

        request = {"action": "login", "payload": {"username": username, "password": password}}
        response = self.network_client.send_request(request)

        if response and response.get("status") == "success":
            self.open_chat_window()
        else:
            error_message = response.get("message", "Erro desconhecido.") if response else "Servidor não respondeu."
            self.show_error("Falha no Login", error_message)

    def register_action(self):
        username = self.ui.username_entry.text()
        password = self.ui.password_entry.text()
        if not username or not password:
            self.show_error("Erro", "Usuário e senha não podem estar vazios.")
            return

        request = {"action": "register", "payload": {"username": username, "password": password}}
        response = self.network_client.send_request(request)

        if response and response.get("status") == "success":
            self.show_info("Sucesso", response.get("message"))
        else:
            error_message = response.get("message", "Erro desconhecido.") if response else "Servidor não respondeu."
            self.show_error("Falha no Registro", error_message)
    
    def _generate_and_store_keys(self, username, passphrase):
        private_key_file = f"{username}_private_key.pem"
        public_key_file = f"{username}_public_key.pem"

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
        )
        with open(private_key_file, 'wb') as f:
            f.write(pem_private)

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_file, 'wb') as f:
            f.write(pem_public)
        
        return private_key

    def _load_private_key(self, username, passphrase):
        private_key_file = f"{username}_private_key.pem"
        try:
            with open(private_key_file, "rb") as key_file:
                private_key = load_pem_private_key(
                    key_file.read(),
                    password=passphrase.encode('utf-8'),
                    backend=default_backend()
                )
            return private_key
        except (ValueError, TypeError):
            self.show_error("Erro de Chave", "Senha da chave privada incorreta.")
            return None
        except FileNotFoundError:
             self.show_error("Erro de Chave", "Arquivo de chave privada não encontrado.")
             return None
        except Exception as e:
            self.show_error("Erro ao Carregar Chave", f"Um erro inesperado ocorreu: {e}")
            return None

    def open_chat_window(self):
        current_username = self.ui.username_entry.text()
        private_key_file = f"{current_username}_private_key.pem"
        private_key = None

        if os.path.exists(private_key_file):
            passphrase, ok = QInputDialog.getText(self, "Chave Privada", 
                                                 "Digite a senha para descriptografar sua chave privada:", 
                                                 QLineEdit.EchoMode.Password)
            if not ok or not passphrase:
                return 
            
            private_key = self._load_private_key(current_username, passphrase)
        
        else:
            QMessageBox.information(self, "Configuração Inicial", 
                                    "Não encontramos chaves de criptografia. Vamos criar um par de chaves (pública/privada) para você.")
            
            passphrase, ok = QInputDialog.getText(self, "Criar Senha da Chave", 
                                                 "Crie uma senha FORTE para proteger sua nova chave privada.\n"
                                                 "NÃO ESQUEÇA ESSA SENHA!", 
                                                 QLineEdit.EchoMode.Password)
            
            if not ok or not passphrase:
                self.show_error("Criação de Chave Cancelada", "Você precisa criar uma senha para a chave para continuar.")
                return

            try:
                private_key = self._generate_and_store_keys(current_username, passphrase)
                self.show_info("Sucesso", f"Chaves salvas como {private_key_file} e {current_username}_public_key.pem")
            except Exception as e:
                self.show_error("Erro ao Gerar Chave", f"Não foi possível gerar as chaves: {e}")
                return

        if private_key:
            public_key_file = f"{current_username}_public_key.pem"
            try:
                with open(public_key_file, 'r') as f:
                    public_key_content = f.read()
                
                request = {"action": "store_public_key", "payload": {"public_key": public_key_content}}
                response = self.network_client.send_request(request)

                if not response or response.get("status") != "success":
                    error_msg = response.get("message", "Erro desconhecido.") if response else "Servidor não respondeu."
                    self.show_error("Falha ao Enviar Chave", f"Não foi possível salvar sua chave pública no servidor: {error_msg}")
                    return

            except FileNotFoundError:
                self.show_error("Erro de Chave", f"Arquivo de chave pública {public_key_file} não encontrado.")
                return
            except Exception as e:
                self.show_error("Erro Inesperado", f"Não foi possível ler ou enviar a chave: {e}")
                return
            
            self.is_switching_windows = True
            self.chat_window = ChatWindow(self.network_client, current_username, self.db, private_key)
            self.chat_window.show()
            self.close()

    def closeEvent(self, event):
        if not self.is_switching_windows:
            self.network_client.close()
        event.accept()