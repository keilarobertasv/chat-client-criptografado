import socket
import json
import threading
from PyQt6 import QtCore

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

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except ConnectionRefusedError:
            self.socket = None
            return False

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
                    message = json.loads(msg_str)
                    self.message_received.emit(message)
                
                if buffer.startswith('{') and buffer.endswith('}'):
                    message = json.loads(buffer)
                    self.message_received.emit(message)
                    buffer = ""
        except socket.error as e:
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
                
                if action in ["login", "register"]:
                    response_data = self.socket.recv(2048)
                    if response_data:
                        response_str = response_data.decode('utf-8').replace('}{', '}\n{').split('\n')[0]
                        return json.loads(response_str)
                
                return {"status": "request_sent"}
        except socket.error as e:
            self.connection_error.emit("Falha ao enviar dados. Conexão instável.")
            return None
        except Exception as e:
            return None

    def close(self):
        self.listening = False
        if self.socket:
            self.socket.close()
            self.socket = None