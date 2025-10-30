# ✉️ Chat-client

## 📖 Descrição
O **Cliente** é uma aplicação desktop com interface gráfica que permite ao usuário interagir com o servidor.
Ele fornece telas de login, lista de contatos e janelas de conversas.
Agora, o projeto passa a ter criptografia de ponta a ponta.

[Versão anterior (sem criptografia)](https://github.com/keilarobertasv/chat-client)

---

## ⚙️ Funcionalidades
- Tela de login/registro
- Lista de contatos (online/offline)
- Envio e recebimento de mensagens em tempo real
- Indicador de digitação
- Histórico de conversas persistido localmente
- Reconexão automática e recebimento de mensagens offline

---

## 🏗️ Arquitetura
- Interface gráfica
- Conexão TCP/IP com o servidor
- Threads para envio e recepção de mensagens em paralelo
- Armazenamento do histórico local

---

## 🚀 Como Executar

### 🔧 Pré-requisitos
- Python 3  
- SQLite

### Clonar o repositório
git clone https://github.com/keilarobertasv/chat-client-criptografado 
cd chat-client-criptografado 

### Instalar dependências
pip install -r requirements.txt

### Executar client
python client.py
