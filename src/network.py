import socket
import json
import threading
import os
import base64
import hashlib
from PyQt6 import QtCore

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
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

	def connect(self):
		try:
			with open(PARAMS_PATH, "rb") as f:
				self.dh_parameters = load_pem_parameters(f.read())
		except Exception as e:
			print(f"Erro fatal: Não foi possível carregar 'dh_params.pem'.")
			print(f"Verifique se o arquivo está em: {PARAMS_PATH}")
			return False
			
		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.socket.connect((self.host, self.port))
			return True
		except ConnectionRefusedError:
			self.socket = None
			return False

	def perform_handshake(self):
		try:
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
				return False, "Servidor não respondeu ao handshake."
				
			response = json.loads(response_data.decode('utf-8'))
			
			if response.get("status") != "success":
				return False, response.get("message", "Falha no handshake.")
				
			server_public_key_pem = response["payload"]["server_dhe_public_key"]
			server_public_key = load_pem_public_key(server_public_key_pem.encode('utf-8'))
			
			shared_secret = client_private_key.exchange(server_public_key)
			
			debug_hash = hashlib.sha256(shared_secret).hexdigest()
			print(f"Hash do Segredo: {debug_hash}")
			
			hkdf = HKDF(
				algorithm=hashes.SHA256(),
				length=64,
				salt=salt_bytes,
				info=b'session-key-derivation',
			)
			derived_keys = hkdf.derive(shared_secret)
			
			self.session_aes_key = derived_keys[:32]
			self.session_hmac_key = derived_keys[32:]
			
			return True, "Handshake concluído com sucesso."
			
		except Exception as e:
			return False, f"Erro durante o handshake: {e}"

	def _encrypt(self, plaintext_json_str):
		if not self.session_aes_key or not self.session_hmac_key:
			raise Exception("Sessão de criptografia não estabelecida.")
		
		padder = PKCS7(algorithms.AES.block_size).padder()
		padded_data = padder.update(plaintext_json_str.encode('utf-8')) + padder.finalize()
		
		iv = os.urandom(algorithms.AES.block_size // 8)
		
		cipher = Cipher(algorithms.AES(self.session_aes_key), modes.CBC(iv))
		encryptor = cipher.encryptor()
		ciphertext = encryptor.update(padded_data) + encryptor.finalize()
		
		h = hmac.HMAC(self.session_hmac_key, hashes.SHA256())
		h.update(iv + ciphertext) 
		mac = h.finalize()
		
		encrypted_payload = {
			"iv": base64.b64encode(iv).decode('utf-8'),
			"ct": base64.b64encode(ciphertext).decode('utf-8'),
			"mac": base64.b64encode(mac).decode('utf-8')
		}
		
		return json.dumps(encrypted_payload).encode('utf-8')

	def _decrypt(self, encrypted_payload_bytes):
		if not self.session_aes_key or not self.session_hmac_key:
			raise Exception("Sessão de criptografia não estabelecida.")
		
		try:
			wrapper = json.loads(encrypted_payload_bytes.decode('utf-8'))
			iv = base64.b64decode(wrapper['iv'])
			ciphertext = base64.b64decode(wrapper['ct'])
			received_mac = base64.b64decode(wrapper['mac'])
			
			h = hmac.HMAC(self.session_hmac_key, hashes.SHA256())
			h.update(iv + ciphertext)
			h.verify(received_mac)
			
			cipher = Cipher(algorithms.AES(self.session_aes_key), modes.CBC(iv))
			decryptor = cipher.decryptor()
			padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
			
			unpadder = PKCS7(algorithms.AES.block_size).unpadder()
			plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
			
			return plaintext.decode('utf-8')
			
		except (InvalidSignature, KeyError, json.JSONDecodeError, Exception):
			return None

	def start_listening(self):
		if not self.socket or self.listening:
			return
		self.listening = True
		self.listener_thread = threading.Thread(target=self._listen_for_messages, daemon=True)
		self.listener_thread.start()

	def _listen_for_messages(self):
		buffer = b""
		try:
			while self.listening:
				data = self.socket.recv(4096)
				if not data:
					break
				buffer += data
				
				while b'\n' in buffer:
					encrypted_payload_bytes, buffer = buffer.split(b'\n', 1)
					if not encrypted_payload_bytes:
						continue
					
					decrypted_json_str = self._decrypt(encrypted_payload_bytes)
					
					if decrypted_json_str:
						try:
							message = json.loads(decrypted_json_str)
							self.message_received.emit(message)
						except json.JSONDecodeError:
							pass 
					else:
						pass
						
		except socket.error as e:
			if self.listening:
				self.connection_error.emit("Conexão com o servidor foi perdida. Por favor, reinicie.")
		except Exception as e:
			pass
		finally:
			self.listening = False
			if self.socket:
				self.socket.close()
				self.socket = None

	def send_request(self, request_data):
		if not self.socket:
			return None
		try:
			with self.lock:
				plaintext_json_str = json.dumps(request_data)
				encrypted_payload = self._encrypt(plaintext_json_str)
				
				self.socket.sendall(encrypted_payload + b'\n')
				
				action = request_data.get("action")
				
				if action in ["login", "register", "store_public_key"]:
					response_data = self.socket.recv(4096)
					
					if response_data:
						decrypted_json_str = self._decrypt(response_data)
						if decrypted_json_str:
							return json.loads(decrypted_json_str)
						else:
							return {"status": "error", "message": "Mensagem do servidor falhou na verificação de integridade."}
					else:
						return {"status": "error", "message": "Servidor não respondeu."}
				
				return {"status": "request_sent"}
		except socket.error as e:
			self.connection_error.emit("Falha ao enviar dados. Conexão instável.")
			return None
		except Exception as e:
			return {"status": "error", "message": f"Erro de rede inesperado: {e}"}

	def close(self):
		self.listening = False
		if self.socket:
			try:
				self.socket.shutdown(socket.SHUT_RDWR)
			except:
				pass
			self.socket.close()
			self.socket = None