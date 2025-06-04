from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config

app = Flask(__name__)

# Configurações arquivo config.py
app.config.from_object(Config)  

# Inicializa SQLAlchemy
db = SQLAlchemy(app) 

# --- Definição do Modelo do Banco de Dados ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False) # Hash de senhas
    role = db.Column(db.String(10), nullable = False, default = 'jogador') # 'jogador' ou 'anjo'

    # Anjo pode enviar diversas menssagens (one-to-many)
    sent_messages = db.relationship('Message', foreign_keys = 'Message.sender_id', backref = 'sender', lazy=True)

    # Jgador pode receber diversas menssagens (one-to-many)
    recived_messages = db.relationship('Message', foreign_keys = 'Message.receiver_id', backref = 'receiver', lazy=True)

    # Se um anjo tem vários jogadores, use backref=anjo_atribuicao e liste as atribuições

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    
    # ID do remetente (anjo) - ForeignKey para User.id
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)

    # ID do destinatário (jogador) - ForeignKey para User.id
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)

    # Conteúdo da mensagem
    content = db.Column(db.Text, nullable = False)

    # Data e hora da mensagem
    timestamp = db.Column(db.DateTime, nullable = False, default = db.func.now())

    def __repr__(self):
        return f"Message('{self.content[:20]}...', 'De: {self.sender.id}', 'Para: {self.receiver_id}')"

# Rota para a página inicial
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    # Cria as tabelas no banco de dados se elas não existirem
    # Isso deve ser executado APENAS UMA VEZ ou quando alterar seus modelos
    with app.app_context():
        db.create_all()
    app.run(debug=True)