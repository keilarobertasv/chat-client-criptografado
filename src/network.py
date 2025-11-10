import socket
import json
import threading
import os
import base64
import hashlib
from PyQt6 import QtCore

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import (
	load_pem_parameters,
	load_pem_public_key,
	Encoding,
	PublicFormat
)

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
			
			self.socket.sendall(json.dumps(request).encode("utf-8"))
			
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

	def start_listening(self):
		if not self.socket or self.listening:
			return
		self.listening = True
		self.listener_thread = threading.Thread(target=self._listen_for_messages, daemon=True)
		self.listener_thread.start()

	def _listen_for_messages(self):
		buffer = ""
		try:
			while self.listening:
				data = self.socket.recv(2048)
				if not data:
					break
				buffer += data.decode('utf-8')
				
				while '}{' in buffer:
					msg_str, buffer = buffer.split('}{', 1)
					msg_str += '}'
					try:
						message = json.loads(msg_str)
						self.message_received.emit(message)
					except json.JSONDecodeError:
						pass 
				
				if buffer and buffer.startswith('{') and buffer.endswith('}'):
					try:
						message = json.loads(buffer)
						self.message_received.emit(message)
						buffer = ""
					except json.JSONDecodeError:
						buffer = "" 
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
				self.socket.sendall(json.dumps(request_data).encode("utf-8"))
				
				action = request_data.get("action")
				
				if action in ["login", "register", "store_public_key"]:
					response_data = self.socket.recv(2048)
					if response_data:
						try:
							response_str = response_data.decode('utf-8').replace('}{', '}\n{').split('\n')[0]
							return json.loads(response_str)
						except json.JSONDecodeError:
							return {"status": "error", "message": "Resposta inválida recebida do servidor."}
				
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