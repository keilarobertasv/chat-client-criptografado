import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from gui import LoginWindow
from network import NetworkClient
from database import ChatDatabase 

if __name__ == "__main__":
    HOST = '127.0.0.1' 
    PORT = 65432
    
    app = QApplication(sys.argv)

    try:
        with open("style.qss", "r") as f:
            stylesheet = f.read()
        app.setStyleSheet(stylesheet)
    except FileNotFoundError:
        print("Aviso: Arquivo de estilo 'style.qss' não encontrado. Usando estilo padrão.")

    try:
        local_db = ChatDatabase()
        
        network_client = NetworkClient(HOST, PORT)
        
        if network_client.connect():
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