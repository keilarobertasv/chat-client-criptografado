import sys
import os
from PyQt6.QtWidgets import QApplication, QMessageBox
from gui import LoginWindow
from network import NetworkClient
from database import ChatDatabase 

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

if __name__ == "__main__":
	HOST = '127.0.0.1' 
	PORT = 65432
	
	app = QApplication(sys.argv)

	try:
		style_path = os.path.join(PROJECT_ROOT, "style.qss")
		with open(style_path, "r") as f:
			stylesheet = f.read()
		app.setStyleSheet(stylesheet)
	except FileNotFoundError:
		print("Aviso: Arquivo de estilo 'style.qss' não encontrado. Usando estilo padrão.")

	try:
		local_db = ChatDatabase()
		
		network_client = NetworkClient(HOST, PORT, db_instance=local_db)
		
		if network_client.connect():
			
			success, message = network_client.perform_handshake()
			
			if not success:
				QMessageBox.critical(None, "Erro de Handshake", f"Não foi possível estabelecer uma conexão segura: {message}")
				local_db.close()
				sys.exit()

			login_window = LoginWindow(network_client, local_db) 
			login_window.show()
			
			sys_code = app.exec() 
			
			local_db.close() 
			sys.exit(sys_code)
		else:
			QMessageBox.critical(None, "Erro de Conexão", "Não foi possível conectar ao servidor.")
			local_db.close()

	except Exception as e:
		QMessageBox.critical(None, "Erro Inesperado", f"Ocorreu um erro crítico: {e}")