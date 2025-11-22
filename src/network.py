import socket
import json
import threading
import os
import base64
import hashlib
from datetime import datetime
from PyQt6 import QtCore

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import (
    load_pem_parameters,
    load_pem_public_key,
    Encoding,
    PublicFormat
)
from cryptography.exceptions import InvalidSignature

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
PARAMS_PATH = os.path.join(PROJECT_ROOT, "dh_params.pem")

class NetworkClient(QtCore.QObject):
    message_received = QtCore.pyqtSignal(dict)
    connection_error = QtCore.pyqtSignal(str)
    p2p_handshake_needed = QtCore.pyqtSignal(str)

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.socket = None
        self.listening = False
        self.listener_thread = None
        self.lock = threading.Lock()
        
        self.dh_parameters = None
        
        self.session_aes_key = None
        self.session_hmac_key = None
        
        self.pending_rekey_private_key = None
        self.pending_rekey_salt = None

        self.p2p_sessions = {} 
        self.pending_p2p_handshakes = {} 

    def connect(self):
        try:
            with open(PARAMS_PATH, "rb") as f:
                self.dh_parameters = load_pem_parameters(f.read())
        except Exception as e:
            print(f"Erro fatal: {e}")
            return False
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except ConnectionRefusedError:
            self.socket = None
            return False

    def _encrypt_payload(self, plaintext_json_str, aes_key, hmac_key):
        if not aes_key or not hmac_key:
            raise Exception("Chaves de criptografia ausentes.")
        
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext_json_str.encode('utf-8')) + padder.finalize()
        
        iv = os.urandom(algorithms.AES.block_size // 8)
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(iv + ciphertext) 
        mac = h.finalize()
        
        encrypted_payload = {
            "iv": base64.b64encode(iv).decode('utf-8'),
            "ct": base64.b64encode(ciphertext).decode('utf-8'),
            "mac": base64.b64encode(mac).decode('utf-8')
        }
        return json.dumps(encrypted_payload).encode('utf-8')

    def _decrypt_payload(self, encrypted_payload_bytes, aes_key, hmac_key):
        if not aes_key or not hmac_key:
            raise Exception("Chaves de criptografia ausentes.")
        
        try:
            wrapper = json.loads(encrypted_payload_bytes.decode('utf-8'))
            iv = base64.b64decode(wrapper['iv'])
            ciphertext = base64.b64decode(wrapper['ct'])
            received_mac = base64.b64decode(wrapper['mac'])
            
            h = hmac.HMAC(hmac_key, hashes.SHA256())
            h.update(iv + ciphertext)
            h.verify(received_mac)
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
        except (InvalidSignature, KeyError, json.JSONDecodeError, Exception):
            return None

    def perform_handshake(self):
        try:
            print("Iniciando handshake com Servidor...")
            salt_bytes = os.urandom(16)
            client_private_key = self.dh_parameters.generate_private_key()
            client_public_key = client_private_key.public_key()
            
            client_public_key_pem = client_public_key.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
            
            request = {
                "action": "handshake",
                "payload": {
                    "dhe_public_key": client_public_key_pem.decode('utf-8'),
                    "salt": base64.b64encode(salt_bytes).decode('utf-8')
                }
            }
            
            self.socket.sendall(json.dumps(request).encode("utf-8") + b'\n')
            
            response_data = self.socket.recv(2048)
            if not response_data:
                return False, "Servidor não respondeu."
                
            response = json.loads(response_data.decode('utf-8'))
            if response.get("status") != "success":
                return False, response.get("message", "Falha no handshake.")
                
            server_public_key_pem = response["payload"]["server_dhe_public_key"]
            server_public_key = load_pem_public_key(server_public_key_pem.encode('utf-8'))
            
            shared_secret = client_private_key.exchange(server_public_key)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(), length=64, salt=salt_bytes, info=b'session-key-derivation',
            )
            derived_keys = hkdf.derive(shared_secret)
            
            self.session_aes_key = derived_keys[:32]
            self.session_hmac_key = derived_keys[32:]
            
            return True, "Handshake concluído."
        except Exception as e:
            return False, f"Erro handshake: {e}"

    def start_p2p_handshake(self, target_username):
        try:
            print(f"[P2P] Iniciando negociação segura com {target_username}...")
            p2p_private_key = self.dh_parameters.generate_private_key()
            p2p_public_key = p2p_private_key.public_key()
            
            self.pending_p2p_handshakes[target_username] = p2p_private_key
            
            public_pem = p2p_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            salt = os.urandom(16)
            
            request = {
                "action": "send_message",
                "payload": {
                    "recipient": target_username,
                    "text": json.dumps({
                        "type": "p2p_handshake_init",
                        "public_key": public_pem.decode('utf-8'),
                        "salt": base64.b64encode(salt).decode('utf-8')
                    })
                }
            }
            
            self.send_request(request)
            
        except Exception as e:
            print(f"Erro ao iniciar P2P: {e}")

    def process_incoming_p2p_handshake(self, sender, payload):
        try:
            print(f"[P2P] Recebido convite de handshake de {sender}.")
            sender_pub_pem = payload.get("public_key")
            salt_b64 = payload.get("salt")
            
            if not sender_pub_pem or not salt_b64: return

            my_private_key = self.dh_parameters.generate_private_key()
            my_public_key = my_private_key.public_key()
            
            sender_public_key = load_pem_public_key(sender_pub_pem.encode('utf-8'))
            
            shared_secret = my_private_key.exchange(sender_public_key)
            salt = base64.b64decode(salt_b64)
            
            hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b'p2p-key-derivation')
            derived_keys = hkdf.derive(shared_secret)
            
            self.p2p_sessions[sender] = {
                'aes': derived_keys[:32],
                'hmac': derived_keys[32:],
                'verified': False,
                'msg_count': 0, 
                'start_time': datetime.now()
            }

            my_pub_pem = my_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            
            response_pkt = {
                "action": "send_message",
                "payload": {
                    "recipient": sender,
                    "text": json.dumps({
                        "type": "p2p_handshake_finish",
                        "public_key": my_pub_pem.decode('utf-8'),
                        "salt": salt_b64
                    })
                }
            }
            self.send_request(response_pkt)
            
            self.message_received.emit({"type": "p2p_ready", "sender": sender})

        except Exception as e:
            print(f"Erro processando convite P2P: {e}")

    def finalize_p2p_handshake(self, sender, payload):
        try:
            if sender not in self.pending_p2p_handshakes:
                return
            
            print(f"[P2P] Finalizando handshake com {sender}.")
            sender_pub_pem = payload.get("public_key")
            salt_b64 = payload.get("salt")
            
            my_private_key = self.pending_p2p_handshakes.pop(sender)
            sender_public_key = load_pem_public_key(sender_pub_pem.encode('utf-8'))
            
            shared_secret = my_private_key.exchange(sender_public_key)
            salt = base64.b64decode(salt_b64)
            
            hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b'p2p-key-derivation')
            derived_keys = hkdf.derive(shared_secret)
            
            self.p2p_sessions[sender] = {
                'aes': derived_keys[:32],
                'hmac': derived_keys[32:],
                'verified': False,
                'msg_count': 0,
                'start_time': datetime.now()
            }
            
            self.message_received.emit({"type": "p2p_ready", "sender": sender})
            
        except Exception as e:
            print(f"Erro finalizando P2P: {e}")

    def send_p2p_message(self, recipient, plaintext_text, is_internal=False):
        if recipient not in self.p2p_sessions:
            if not is_internal:
                self.start_p2p_handshake(recipient)
            return False 

        session = self.p2p_sessions[recipient]
        elapsed_seconds = (datetime.now() - session['start_time']).total_seconds()
        
        if (session['msg_count'] >= 100 or elapsed_seconds > 3600) and not is_internal:
            print(f"[P2P] Sessão com {recipient} expirou (Count: {session['msg_count']}). Renovando chaves...")
            self.start_p2p_handshake(recipient)
            return False 

        keys = self.p2p_sessions[recipient]
        encrypted_content = self._encrypt_payload(plaintext_text, keys['aes'], keys['hmac'])
        
        if not is_internal:
            session['msg_count'] += 1
        
        request = {
            "action": "send_message",
            "payload": {
                "recipient": recipient,
                "text": encrypted_content.decode('utf-8')
            }
        }
        
        self.send_request(request)
        return True

    def send_p2p_auth_challenge(self, target_username):
        if target_username not in self.p2p_sessions: return
        
        try:
            print(f"[Auth] Enviando desafio de autenticação para {target_username}...")
            nonce = os.urandom(32)
            self.p2p_sessions[target_username]['pending_nonce'] = nonce
            
            payload_dict = {
                "type": "p2p_auth_challenge",
                "nonce": base64.b64encode(nonce).decode('utf-8')
            }
            self.send_p2p_message(target_username, json.dumps(payload_dict), is_internal=True)
            
        except Exception as e:
            print(f"Erro ao enviar desafio P2P: {e}")

    def reply_to_p2p_auth_challenge(self, sender, payload, my_private_key):
        try:
            nonce_b64 = payload.get("nonce")
            if not nonce_b64: return
            
            nonce = base64.b64decode(nonce_b64)
            
            signature = my_private_key.sign(
                nonce,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            
            response_dict = {
                "type": "p2p_auth_response",
                "signature": base64.b64encode(signature).decode('utf-8')
            }
            self.send_p2p_message(sender, json.dumps(response_dict), is_internal=True)
            print(f"[Auth] Desafio de {sender} assinado e devolvido.")
            
        except Exception as e:
            print(f"Erro ao tratar desafio P2P: {e}")

    def verify_p2p_auth_response(self, sender, payload, sender_public_key):
        try:
            signature_b64 = payload.get("signature")
            if not signature_b64: return
            
            if sender not in self.p2p_sessions or 'pending_nonce' not in self.p2p_sessions[sender]:
                return

            nonce = self.p2p_sessions[sender].pop('pending_nonce')
            signature = base64.b64decode(signature_b64)
            
            sender_public_key.verify(
                signature,
                nonce,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            
            self.p2p_sessions[sender]['verified'] = True
            print(f"[Auth] Identidade de {sender} confirmada!")
            
            self.message_received.emit({"type": "p2p_verified", "username": sender})
            
        except InvalidSignature:
            print(f"[Auth] FALHA: Assinatura de {sender} inválida!")
            if sender in self.p2p_sessions:
                del self.p2p_sessions[sender]
        except Exception as e:
            print(f"Erro na verificação P2P: {e}")

    def send_request(self, request_data):
        if not self.socket: return
        try:
            with self.lock:
                plaintext_json = json.dumps(request_data)
                encrypted_payload = self._encrypt_payload(plaintext_json, self.session_aes_key, self.session_hmac_key)
                self.socket.sendall(encrypted_payload + b'\n')
        except Exception as e:
            self.connection_error.emit(f"Erro envio: {e}")

    def start_listening(self):
        if not self.socket or self.listening: return
        self.listening = True
        self.listener_thread = threading.Thread(target=self._listen_for_messages, daemon=True)
        self.listener_thread.start()

    def _initiate_rekey(self):
        try:
            print("INFO: O servidor solicitou renovação de chaves (Rekey).")
            self.pending_rekey_salt = os.urandom(16)
            self.pending_rekey_private_key = self.dh_parameters.generate_private_key()
            client_pub = self.pending_rekey_private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            
            req = {
                "action": "rekey_start",
                "payload": {"dhe_public_key": client_pub.decode('utf-8'), "salt": base64.b64encode(self.pending_rekey_salt).decode('utf-8')}
            }
            self.send_request(req)
        except: pass

    def _finalize_rekey(self, payload):
        try:
            server_pub = load_pem_public_key(payload["server_dhe_public_key"].encode('utf-8'))
            shared = self.pending_rekey_private_key.exchange(server_pub)
            hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=self.pending_rekey_salt, info=b'session-key-derivation')
            derived = hkdf.derive(shared)
            self.session_aes_key = derived[:32]
            self.session_hmac_key = derived[32:]
            self.pending_rekey_private_key = None
            print("SUCESSO: Chaves com o servidor renovadas.")
        except: pass

    def _listen_for_messages(self):
        buffer = b""
        try:
            while self.listening:
                data = self.socket.recv(4096)
                if not data: break
                buffer += data
                
                while b'\n' in buffer:
                    pkt, buffer = buffer.split(b'\n', 1)
                    if not pkt: continue
                    
                    decrypted_str = self._decrypt_payload(pkt, self.session_aes_key, self.session_hmac_key)
                    if decrypted_str:
                        try:
                            msg = json.loads(decrypted_str)
                            m_type = msg.get("type")
                            
                            if m_type == "rekey_required": self._initiate_rekey()
                            elif msg.get("action") == "rekey_finish": self._finalize_rekey(msg.get("payload"))
                            
                            elif m_type in ["new_message", "offline_message"]:
                                sender = msg.get("sender")
                                content = msg.get("text")
                                
                                try:
                                    inner_json = json.loads(content)
                                    if isinstance(inner_json, dict) and "type" in inner_json:
                                        if inner_json["type"] == "p2p_handshake_init":
                                            self.process_incoming_p2p_handshake(sender, inner_json)
                                            continue
                                        elif inner_json["type"] == "p2p_handshake_finish":
                                            self.finalize_p2p_handshake(sender, inner_json)
                                            continue
                                except:
                                    pass
                                
                                is_encrypted = False
                                try:
                                    chk = json.loads(content)
                                    if isinstance(chk, dict) and "iv" in chk and "ct" in chk and "mac" in chk:
                                        is_encrypted = True
                                except: pass

                                if sender in self.p2p_sessions and is_encrypted:
                                    keys = self.p2p_sessions[sender]
                                    decrypted_p2p = self._decrypt_payload(content.encode('utf-8'), keys['aes'], keys['hmac'])
                                    if decrypted_p2p:
                                        msg["text"] = decrypted_p2p
                                        try:
                                            p2p_content = json.loads(decrypted_p2p)
                                            if isinstance(p2p_content, dict) and "type" in p2p_content:
                                                if p2p_content["type"] in ["p2p_auth_challenge", "p2p_auth_response"]:
                                                    auth_msg = p2p_content
                                                    auth_msg["sender"] = sender
                                                    self.message_received.emit(auth_msg)
                                                    continue
                                        except: pass
                                    else:
                                        msg["text"] = "[Erro na descriptografia P2P]"
                                
                                elif is_encrypted:
                                    msg["text"] = "[Mensagem ilegível: Sessão anterior expirada ou chaves perdidas]"

                                self.message_received.emit(msg)
                            
                            else:
                                self.message_received.emit(msg)
                                
                        except json.JSONDecodeError: pass
        except: pass
        finally:
            self.listening = False
            self.close()

    def close(self):
        self.listening = False
        if self.socket:
            try: self.socket.shutdown(socket.SHUT_RDWR)
            except: pass
            self.socket.close()
            self.socket = None